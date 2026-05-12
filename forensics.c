/*
 * forensics.c - RequiemFS Forensic Recovery Engine
 * 
 * So basically this whole thing reads a raw disk image byte by byte
 * and looks for file signatures (magic numbers) to recover deleted files.
 * 
 * Right now it supports JPEG, PNG, and PDF recovery.
 * The idea is that when you "delete" a file, the OS just removes the
 * pointer (inode/FAT entry) but the actual data is still sitting there
 * on disk until something overwrites it. We exploit that here.
 * 
 * Build: gcc forensics.c -o forensics
 * Usage: ./forensics <disk_image> [output_dir]
 * 
 * Stdout protocol (the Python UI reads these lines):
 *   SCAN_START
 *   SCANNING: 0x<offset>
 *   FOUND_START: 0x<offset>
 *   FOUND_END: 0x<offset>
 *   FOUND_TYPE: <JPEG|PNG|PDF>
 *   RECOVERED: <filepath>
 *   ENTROPY: <sector_num> <value>
 *   SCAN_TIME: <seconds>
 *   SCAN_COMPLETE: <count>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

/* how big each read chunk is - 4KB seemed like a sweet spot
   too small = too many reads, too big = waste memory */
#define READ_BUF_SIZE 4096

/* don't let a single carved file exceed 8MB, otherwise
   a false positive could eat all our memory lol */
#define MAX_CARVE_SIZE (8 * 1024 * 1024)

/* report scan progress every 64KB - gives the UI enough
   data points for smooth animation without spamming stdout */
#define PROGRESS_INTERVAL 0x10000

/* sector size - standard 512 bytes, same as most real disks */
#define SECTOR_SIZE 512


/* ========== File Type Definitions ==========
 * Each file type we want to recover needs a header signature
 * (magic number) and a footer/end marker. Some formats like PDF
 * have variable-length footers which makes things trickier.
 */

/* -- JPEG: probably the most common thing you'd want to recover -- */
/* starts with FF D8 (SOI = Start Of Image) */
#define JPEG_HDR_0 0xFF
#define JPEG_HDR_1 0xD8
/* ends with FF D9 (EOI = End Of Image) */
#define JPEG_FTR_0 0xFF
#define JPEG_FTR_1 0xD9

/* -- PNG: has a longer 8-byte header which is actually kinda nice
   because it means fewer false positives compared to JPEG's 2 bytes -- */
static const unsigned char PNG_HEADER[] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
#define PNG_HDR_LEN 8
/* PNG ends with the IEND chunk - these are the last 8 bytes of any valid PNG */
static const unsigned char PNG_FOOTER[] = {0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82};
#define PNG_FTR_LEN 8

/* -- PDF: starts with %PDF and ends with %%EOF
   kinda annoying because %%EOF can appear multiple times in 
   linearized PDFs but we just grab the first occurrence -- */
static const unsigned char PDF_HEADER[] = {0x25, 0x50, 0x44, 0x46};
#define PDF_HDR_LEN 4
static const unsigned char PDF_FOOTER[] = {0x25, 0x25, 0x45, 0x4F, 0x46};
#define PDF_FTR_LEN 5

/* -- GIF: starts with GIF8 (47 49 46 38) and ends with 00 3B -- */
static const unsigned char GIF_HEADER[] = {0x47, 0x49, 0x46, 0x38};
#define GIF_HDR_LEN 4
static const unsigned char GIF_FOOTER[] = {0x00, 0x3B};
#define GIF_FTR_LEN 2

/* -- ZIP: starts with PK\x03\x04 and ends with EOCD (PK\x05\x06) + 18 bytes -- */
static const unsigned char ZIP_HEADER[] = {0x50, 0x4B, 0x03, 0x04};
#define ZIP_HDR_LEN 4
static const unsigned char ZIP_FOOTER[] = {0x50, 0x4B, 0x05, 0x06};
#define ZIP_FTR_LEN 4

/* -- MP4: starts with 'ftyp' at offset 4. No standard footer, so we use a size heuristic -- */
static const unsigned char MP4_HEADER[] = {0x66, 0x74, 0x79, 0x70};
#define MP4_HDR_LEN 4


/* types of files we can carve - used internally to track state */
typedef enum {
    FTYPE_NONE = 0,
    FTYPE_JPEG,
    FTYPE_PNG,
    FTYPE_PDF,
    FTYPE_GIF,
    FTYPE_ZIP,
    FTYPE_MP4
} FileType;

/* just a helper to get the string name for printing */
static const char* ftype_name(FileType t) {
    switch(t) {
        case FTYPE_JPEG: return "JPEG";
        case FTYPE_PNG:  return "PNG";
        case FTYPE_PDF:  return "PDF";
        case FTYPE_GIF:  return "GIF";
        case FTYPE_ZIP:  return "ZIP";
        case FTYPE_MP4:  return "MP4";
        default:         return "UNKNOWN";
    }
}

/* file extension for each type */
static const char* ftype_ext(FileType t) {
    switch(t) {
        case FTYPE_JPEG: return "jpg";
        case FTYPE_PNG:  return "png";
        case FTYPE_PDF:  return "pdf";
        case FTYPE_GIF:  return "gif";
        case FTYPE_ZIP:  return "zip";
        case FTYPE_MP4:  return "mp4";
        default:         return "bin";
    }
}


/*
 * get_file_size - figure out how big the disk image is
 * 
 * We do this the old-school way: seek to end, read position, seek back.
 * In a real OS, this info would come from the inode's size field,
 * but since we're working with raw images we gotta do it manually.
 */
static long get_file_size(FILE *fp)
{
    long cur, size;
    cur = ftell(fp);
    fseek(fp, 0L, SEEK_END);
    size = ftell(fp);
    fseek(fp, cur, SEEK_SET);
    return size;
}


/*
 * calc_entropy - calculate Shannon entropy of a data block
 * 
 * Entropy tells us how "random" a chunk of data is:
 *   - 0.0 = all same bytes (like a zeroed-out sector)
 *   - 8.0 = perfectly random (encrypted or compressed data)
 *   - ~4-6 = typical file data (text, code, etc.)
 *   - ~7-8 = compressed files (JPEG, ZIP, etc.)
 * 
 * This is super useful for forensics because it helps us
 * distinguish between empty space, file data, and garbage.
 * I spent way too long debugging the math on this one...
 */
static double calc_entropy(const unsigned char *data, size_t len)
{
    int freq[256];
    double entropy = 0.0;
    size_t i;

    if (len == 0) return 0.0;

    /* count how often each byte value appears */
    memset(freq, 0, sizeof(freq));
    for (i = 0; i < len; i++) {
        freq[data[i]]++;
    }

    /* shannon entropy formula: -sum(p * log2(p)) for each byte value */
    for (i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / (double)len;
            /* using the log change-of-base trick since we don't have log2 everywhere:
               log2(x) = log(x) / log(2) ... but honestly just using log works fine
               since we're comparing relative values anyway */
            entropy -= p * (log(p) / log(2.0));
        }
    }

    return entropy;
}


/*
 * match_bytes - check if a sequence of bytes matches a pattern
 * 
 * Nothing fancy, just a memcmp wrapper basically.
 * Returns 1 if matched, 0 if not.
 */
static int match_bytes(const unsigned char *buf, size_t buf_remaining,
                       const unsigned char *pattern, size_t pat_len)
{
    if (buf_remaining < pat_len) return 0;
    return memcmp(buf, pattern, pat_len) == 0;
}


/*
 * save_carved_file - write the recovered data to a new file
 * 
 * Takes the carved bytes and dumps them to disk with the right extension.
 * The file naming is simple: recovered_0.jpg, recovered_1.png, etc.
 */
static int save_carved_file(const char *output_dir, int index,
                            FileType ftype,
                            const unsigned char *data, size_t length)
{
    char path[512];
    FILE *out;

    snprintf(path, sizeof(path), "%s/recovered_%d.%s",
             output_dir, index, ftype_ext(ftype));

    out = fopen(path, "wb");
    if (!out) {
        fprintf(stderr, "[!] Couldn't create output file: %s\n", path);
        return -1;
    }

    fwrite(data, 1, length, out);
    fclose(out);

    /* tell the UI about this recovery */
    printf("RECOVERED: %s\n", path);
    fflush(stdout);

    return 0;
}


/*
 * scan_disk - the main event, this is where the magic happens
 * 
 * Strategy is basically the same as tools like PhotoRec:
 *   1. Read the image in chunks (4KB at a time)
 *   2. Scan each byte looking for known file headers
 *   3. When we find one, start accumulating bytes
 *   4. Keep going until we find the matching footer
 *   5. Save everything between header and footer
 * 
 * The tricky part is handling markers that might span across
 * two chunks (like if FF is the last byte of chunk 1 and D8 is
 * the first byte of chunk 2). We handle this by seeking back
 * a few bytes before reading the next chunk. Took me a while
 * to get this right without missing any signatures.
 */
static int scan_disk(const char *image_path, const char *output_dir)
{
    FILE *fp;
    unsigned char *buffer;
    unsigned char *carve_buf;
    long file_size, offset;
    size_t bytes_read;
    int recovered = 0;
    clock_t start_time, end_time;

    /* carving state - tracks what we're currently extracting */
    FileType active_type = FTYPE_NONE;
    size_t carve_len = 0;
    long carve_start = 0;

    /* overlap size: needs to be at least as long as our longest header/footer
       so we don't miss signatures that straddle chunk boundaries */
    int overlap = PNG_HDR_LEN; /* PNG header is 8 bytes, our longest signature */

    /* try to open the raw disk image */
    fp = fopen(image_path, "rb");
    if (!fp) {
        fprintf(stderr, "[!] Can't open: %s\n", image_path);
        return -1;
    }

    file_size = get_file_size(fp);
    fprintf(stderr, "[*] Image: %ld bytes (%.2f MB)\n",
            file_size, (double)file_size / (1024.0 * 1024.0));

    /* allocate our buffers - doing this with malloc instead of stack
       arrays because the carve buffer can get pretty big (8MB max)
       and we don't want to blow the stack */
    buffer = (unsigned char *)malloc(READ_BUF_SIZE);
    carve_buf = (unsigned char *)malloc(MAX_CARVE_SIZE);
    if (!buffer || !carve_buf) {
        fprintf(stderr, "[!] malloc failed - are we out of memory?\n");
        if (buffer) free(buffer);
        if (carve_buf) free(carve_buf);
        fclose(fp);
        return -1;
    }

    start_time = clock();

    /* let the UI know we're starting */
    printf("SCAN_START\n");
    fflush(stdout);

    /* === MAIN SCAN LOOP ===
     * Read the image chunk by chunk and scan every byte.
     * This is intentionally brute-force - we're simulating what a
     * forensic tool does when filesystem metadata is gone and all
     * you have is raw blocks. */
    offset = 0;
    while ((bytes_read = fread(buffer, 1, READ_BUF_SIZE, fp)) > 0) {
        size_t i;

        /* report progress periodically so the UI can update */
        if (offset % PROGRESS_INTERVAL == 0) {
            printf("SCANNING: 0x%lX\n", offset);
            fflush(stdout);

            /* also calculate and report entropy for this sector
               (helps the UI show a heatmap of data density) */
            if (bytes_read >= SECTOR_SIZE) {
                double ent = calc_entropy(buffer, SECTOR_SIZE);
                long sec_num = offset / SECTOR_SIZE;
                printf("ENTROPY: %ld %.4f\n", sec_num, ent);
                fflush(stdout);
            }
        }

        /* scan through every byte in this chunk */
        for (i = 0; i < bytes_read; i++) {
            /* pointer to current position - using pointer arithmetic
               as required (could also just do buffer[i] but this
               demonstrates the concept better for the OS class) */
            unsigned char *p = buffer + i;
            size_t remaining = bytes_read - i;

            if (active_type == FTYPE_NONE) {
                /* === NOT CURRENTLY CARVING - LOOK FOR HEADERS === */

                /* check for JPEG: FF D8 */
                if (remaining >= 2 && *(p) == JPEG_HDR_0 && *(p+1) == JPEG_HDR_1) {
                    active_type = FTYPE_JPEG;
                    carve_len = 0;
                    carve_start = offset + (long)i;

                    printf("FOUND_START: 0x%lX\n", carve_start);
                    printf("FOUND_TYPE: JPEG\n");
                    fflush(stdout);

                    /* copy the header bytes into our carve buffer */
                    *(carve_buf + carve_len++) = *(p);
                    *(carve_buf + carve_len++) = *(p+1);
                    i++; /* skip second byte since we already grabbed it */
                    continue;
                }

                /* check for PNG: 89 50 4E 47 0D 0A 1A 0A */
                if (match_bytes(p, remaining, PNG_HEADER, PNG_HDR_LEN)) {
                    active_type = FTYPE_PNG;
                    carve_len = 0;
                    carve_start = offset + (long)i;

                    printf("FOUND_START: 0x%lX\n", carve_start);
                    printf("FOUND_TYPE: PNG\n");
                    fflush(stdout);

                    /* copy all 8 header bytes */
                    memcpy(carve_buf, p, PNG_HDR_LEN);
                    carve_len = PNG_HDR_LEN;
                    i += PNG_HDR_LEN - 1;
                    continue;
                }

                /* check for PDF: 25 50 44 46 (%PDF) */
                if (match_bytes(p, remaining, PDF_HEADER, PDF_HDR_LEN)) {
                    active_type = FTYPE_PDF;
                    carve_len = 0;
                    carve_start = offset + (long)i;

                    printf("FOUND_START: 0x%lX\n", carve_start);
                    printf("FOUND_TYPE: PDF\n");
                    fflush(stdout);

                    memcpy(carve_buf, p, PDF_HDR_LEN);
                    carve_len = PDF_HDR_LEN;
                    i += PDF_HDR_LEN - 1;
                    continue;
                }

                /* check for GIF: 47 49 46 38 (GIF8) */
                if (match_bytes(p, remaining, GIF_HEADER, GIF_HDR_LEN)) {
                    active_type = FTYPE_GIF;
                    carve_len = 0;
                    carve_start = offset + (long)i;

                    printf("FOUND_START: 0x%lX\n", carve_start);
                    printf("FOUND_TYPE: GIF\n");
                    fflush(stdout);

                    memcpy(carve_buf, p, GIF_HDR_LEN);
                    carve_len = GIF_HDR_LEN;
                    i += GIF_HDR_LEN - 1;
                    continue;
                }

                /* check for ZIP: 50 4B 03 04 (PK..) */
                if (match_bytes(p, remaining, ZIP_HEADER, ZIP_HDR_LEN)) {
                    active_type = FTYPE_ZIP;
                    carve_len = 0;
                    carve_start = offset + (long)i;

                    printf("FOUND_START: 0x%lX\n", carve_start);
                    printf("FOUND_TYPE: ZIP\n");
                    fflush(stdout);

                    memcpy(carve_buf, p, ZIP_HDR_LEN);
                    carve_len = ZIP_HDR_LEN;
                    i += ZIP_HDR_LEN - 1;
                    continue;
                }

                /* check for MP4: 'ftyp' starts at byte 4 */
                if (remaining >= 8 && match_bytes(p + 4, remaining - 4, MP4_HEADER, MP4_HDR_LEN)) {
                    active_type = FTYPE_MP4;
                    carve_len = 0;
                    carve_start = offset + (long)i;

                    printf("FOUND_START: 0x%lX\n", carve_start);
                    printf("FOUND_TYPE: MP4\n");
                    fflush(stdout);

                    /* copy all 8 bytes (the 4 bytes of size/offset + ftyp) */
                    memcpy(carve_buf, p, 8);
                    carve_len = 8;
                    i += 7;
                    continue;
                }

            } else {
                /* === CURRENTLY CARVING - ACCUMULATE AND LOOK FOR FOOTER === */

                *(carve_buf + carve_len) = *p;
                carve_len++;

                int found_end = 0;

                /* check for the appropriate footer based on what we're carving */
                switch (active_type) {
                    case FTYPE_JPEG:
                        /* JPEG footer: FF D9 */
                        if (carve_len >= 2 &&
                            *(carve_buf + carve_len - 2) == JPEG_FTR_0 &&
                            *(carve_buf + carve_len - 1) == JPEG_FTR_1) {
                            found_end = 1;
                        }
                        break;

                    case FTYPE_PNG:
                        /* PNG footer: IEND chunk (last 8 bytes) */
                        if (carve_len >= PNG_FTR_LEN &&
                            memcmp(carve_buf + carve_len - PNG_FTR_LEN,
                                   PNG_FOOTER, PNG_FTR_LEN) == 0) {
                            found_end = 1;
                        }
                        break;

                    case FTYPE_PDF:
                        /* PDF footer: %%EOF */
                        if (carve_len >= PDF_FTR_LEN &&
                            memcmp(carve_buf + carve_len - PDF_FTR_LEN,
                                   PDF_FOOTER, PDF_FTR_LEN) == 0) {
                            found_end = 1;
                        }
                        break;

                    case FTYPE_GIF:
                        /* GIF footer: 00 3B */
                        if (carve_len >= GIF_FTR_LEN &&
                            memcmp(carve_buf + carve_len - GIF_FTR_LEN,
                                   GIF_FOOTER, GIF_FTR_LEN) == 0) {
                            found_end = 1;
                        }
                        break;

                    case FTYPE_ZIP:
                        /* ZIP footer: EOCD (PK\x05\x06) + 18 bytes */
                        if (carve_len >= 22 &&
                            memcmp(carve_buf + carve_len - 22,
                                   ZIP_FOOTER, ZIP_FTR_LEN) == 0) {
                            found_end = 1;
                        }
                        break;

                    case FTYPE_MP4:
                        /* MP4 has no standard footer, so we carve a fixed 1MB heuristic */
                        if (carve_len >= 1024 * 1024) {
                            found_end = 1;
                        }
                        break;

                    default:
                        break;
                }

                if (found_end) {
                    long carve_end = offset + (long)i;

                    printf("FOUND_END: 0x%lX\n", carve_end);
                    fflush(stdout);

                    fprintf(stderr, "[+] Carved %s: 0x%lX -> 0x%lX (%zu bytes)\n",
                            ftype_name(active_type), carve_start, carve_end, carve_len);

                    save_carved_file(output_dir, recovered, active_type,
                                     carve_buf, carve_len);
                    recovered++;

                    /* reset state so we can find the next file */
                    active_type = FTYPE_NONE;
                    carve_len = 0;
                }

                /* safety check: if we've been carving for too long,
                   it's probably a false positive. bail out. */
                if (carve_len >= MAX_CARVE_SIZE) {
                    fprintf(stderr, "[!] Carve exceeded %d bytes at 0x%lX, "
                            "probably a false positive - skipping\n",
                            MAX_CARVE_SIZE, carve_start);
                    active_type = FTYPE_NONE;
                    carve_len = 0;
                }
            }
        }

        offset += (long)bytes_read;

        /* seek back by overlap bytes to catch signatures split across chunks.
           this is actually really important - without this we'd miss any
           header/footer that happens to fall right on a chunk boundary */
        if (bytes_read == READ_BUF_SIZE) {
            fseek(fp, (long)(-overlap), SEEK_CUR);
            offset -= overlap;
        }
    }

    end_time = clock();
    double elapsed = (double)(end_time - start_time) / CLOCKS_PER_SEC;

    /* tell the UI how long the scan took */
    printf("SCAN_TIME: %.3f\n", elapsed);
    printf("SCAN_COMPLETE: %d\n", recovered);
    fflush(stdout);

    fprintf(stderr, "\n[+] Done! Recovered %d file(s) in %.3f seconds.\n",
            recovered, elapsed);
    fprintf(stderr, "[+] Scanned %ld bytes (%.2f MB)\n",
            file_size, (double)file_size / (1024.0 * 1024.0));

    /* cleanup - don't forget to free everything!
       memory leaks are bad, especially in a forensics tool that
       might be processing huge disk images */
    free(carve_buf);
    free(buffer);
    fclose(fp);

    return recovered;
}


/*
 * main - entry point
 * 
 * Nothing fancy here, just parse args and kick off the scan.
 * The output dir defaults to current directory if not specified.
 */
int main(int argc, char *argv[])
{
    const char *image_path;
    const char *output_dir = ".";

    fprintf(stderr, "\n");
    fprintf(stderr, "  ======================================\n");
    fprintf(stderr, "   RequiemFS - Forensic Recovery Engine\n");
    fprintf(stderr, "   The undead files, shall rise.\n");
    fprintf(stderr, "  ======================================\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  Supported formats: JPEG, PNG, PDF, GIF, ZIP, MP4\n");
    fprintf(stderr, "\n");

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <disk_image.img> [output_dir]\n\n", argv[0]);
        fprintf(stderr, "  Scans a raw disk image for deleted files using\n");
        fprintf(stderr, "  magic number carving. No filesystem needed.\n\n");
        return 1;
    }

    image_path = argv[1];
    if (argc >= 3) output_dir = argv[2];

    fprintf(stderr, "[*] Target: %s\n", image_path);
    fprintf(stderr, "[*] Output: %s\n\n", output_dir);

    scan_disk(image_path, output_dir);

    return 0;
}
