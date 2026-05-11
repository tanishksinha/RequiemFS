/*
 * ============================================================================
 *  RequiemFS — Raw Disk Forensic Recovery Engine
 * ============================================================================
 *
 *  This program demonstrates low-level file system concepts from
 *  Silberschatz's "Operating System Concepts" (Chapter 12):
 *
 *    - Raw block device reading (bypassing the VFS / OS file system API)
 *    - File carving via Magic Number detection
 *    - Manual memory management with malloc/free
 *    - Binary file I/O with fopen, fread, fseek
 *
 *  The program scans a raw disk image (.img) byte-by-byte for JPEG
 *  signatures (SOI: FF D8, EOI: FF D9), extracts the data between
 *  them, and saves the recovered file to disk.
 *
 *  Build:  gcc forensics.c -o forensics
 *  Usage:  ./forensics <disk_image.img> [output_dir]
 *
 *  Output protocol (parsed by the Python UI via subprocess stdout):
 *    SCAN_START
 *    SCANNING: 0x<offset>
 *    FOUND_START: 0x<offset>
 *    FOUND_END: 0x<offset>
 *    RECOVERED: <filename>
 *    SCAN_COMPLETE: <count>
 *
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- Configuration Constants ---- */
#define SECTOR_SIZE      512
#define READ_BUFFER_SIZE 4096      /* Read in 4KB chunks for efficiency       */
#define MAX_JPEG_SIZE    (8 * 1024 * 1024)  /* Cap at 8MB per carved file     */
#define SCAN_REPORT_INTERVAL 0x10000        /* Report progress every 64KB     */

/* ---- JPEG Magic Numbers (Silberschatz: "Magic Number" file identification) ---- */
#define JPEG_SOI_0 0xFF
#define JPEG_SOI_1 0xD8
#define JPEG_EOI_0 0xFF
#define JPEG_EOI_1 0xD9


/*
 * get_file_size()
 * ---------------
 * Determines the size of a file using fseek/ftell.
 * This mirrors how the OS determines file extent from inode metadata,
 * but here we do it manually on the raw block device image.
 */
static long get_file_size(FILE *fp)
{
    long current_pos, size;

    current_pos = ftell(fp);
    fseek(fp, 0L, SEEK_END);
    size = ftell(fp);
    fseek(fp, current_pos, SEEK_SET);  /* Restore original position */

    return size;
}


/*
 * save_recovered_file()
 * ---------------------
 * Writes carved bytes to a new file. Demonstrates raw binary output
 * using fwrite — the inverse of the carving read operation.
 */
static int save_recovered_file(const char *output_dir,
                               int file_index,
                               const unsigned char *data,
                               size_t length)
{
    char filepath[512];
    FILE *out;

    snprintf(filepath, sizeof(filepath), "%s/recovered_%d.jpg",
             output_dir, file_index);

    out = fopen(filepath, "wb");
    if (!out) {
        fprintf(stderr, "[!] ERROR: Cannot create output file: %s\n", filepath);
        return -1;
    }

    fwrite(data, 1, length, out);
    fclose(out);

    /* Protocol message for the UI */
    printf("RECOVERED: %s\n", filepath);
    fflush(stdout);

    return 0;
}


/*
 * scan_disk_image()
 * -----------------
 * Core forensic carving routine.
 *
 * Strategy (mirrors real forensic tools like Scalpel/PhotoRec):
 *   1. Read the raw image into a buffer chunk by chunk.
 *   2. Slide through each byte looking for the JPEG SOI marker (FF D8).
 *   3. Once found, continue scanning for the EOI marker (FF D9).
 *   4. Extract all bytes between SOI and EOI+2 (inclusive).
 *   5. Save the carved data as a recovered JPEG file.
 *
 * This deliberately uses raw pointer arithmetic and manual memory
 * management — no high-level libraries.
 */
static int scan_disk_image(const char *image_path, const char *output_dir)
{
    FILE *fp;
    unsigned char *buffer;        /* Read buffer for disk chunks             */
    unsigned char *carve_buffer;  /* Accumulator for carved file bytes       */
    long file_size;
    long offset;
    size_t bytes_read;
    int recovered_count = 0;
    int in_jpeg = 0;              /* State flag: are we inside a JPEG?       */
    size_t carve_length = 0;      /* Current carved data length              */
    long carve_start_offset = 0;  /* Byte offset where current JPEG started  */

    /* ---- Open the raw disk image in binary mode ---- */
    fp = fopen(image_path, "rb");
    if (!fp) {
        fprintf(stderr, "[!] ERROR: Cannot open disk image: %s\n", image_path);
        return -1;
    }

    file_size = get_file_size(fp);
    fprintf(stderr, "[*] Disk image size: %ld bytes (%.2f MB)\n",
            file_size, (double)file_size / (1024.0 * 1024.0));

    /* ---- Allocate buffers using manual memory management ---- */
    buffer = (unsigned char *)malloc(READ_BUFFER_SIZE);
    if (!buffer) {
        fprintf(stderr, "[!] ERROR: malloc failed for read buffer\n");
        fclose(fp);
        return -1;
    }

    carve_buffer = (unsigned char *)malloc(MAX_JPEG_SIZE);
    if (!carve_buffer) {
        fprintf(stderr, "[!] ERROR: malloc failed for carve buffer\n");
        free(buffer);
        fclose(fp);
        return -1;
    }

    /* ---- Signal scan start to the UI ---- */
    printf("SCAN_START\n");
    fflush(stdout);

    /* ---- Main scanning loop: read chunk by chunk ---- */
    offset = 0;
    while ((bytes_read = fread(buffer, 1, READ_BUFFER_SIZE, fp)) > 0) {
        size_t i;

        /* Report scanning progress at regular intervals */
        if (offset % SCAN_REPORT_INTERVAL == 0) {
            printf("SCANNING: 0x%lX\n", offset);
            fflush(stdout);
        }

        /* ---- Iterate through each byte in the chunk ---- */
        for (i = 0; i < bytes_read - 1; i++) {
            unsigned char b0 = *(buffer + i);       /* Raw pointer arithmetic */
            unsigned char b1 = *(buffer + i + 1);   /* Next byte              */

            if (!in_jpeg) {
                /*
                 * Look for JPEG SOI marker: FF D8
                 * This is the "Magic Number" that identifies the start of
                 * a JPEG file, regardless of any file system metadata.
                 */
                if (b0 == JPEG_SOI_0 && b1 == JPEG_SOI_1) {
                    in_jpeg = 1;
                    carve_length = 0;
                    carve_start_offset = offset + (long)i;

                    printf("FOUND_START: 0x%lX\n", carve_start_offset);
                    fflush(stdout);

                    /* Copy the SOI marker bytes into the carve buffer */
                    *(carve_buffer + carve_length) = b0;
                    carve_length++;
                    *(carve_buffer + carve_length) = b1;
                    carve_length++;

                    i++;  /* Skip past the second byte of the marker */
                }
            } else {
                /*
                 * We are inside a JPEG — accumulate bytes into carve_buffer.
                 * Simultaneously scan for the EOI marker: FF D9
                 */
                *(carve_buffer + carve_length) = b0;
                carve_length++;

                if (b0 == JPEG_EOI_0 && b1 == JPEG_EOI_1) {
                    /* Found EOI — include the D9 byte to complete the file */
                    *(carve_buffer + carve_length) = b1;
                    carve_length++;

                    long carve_end_offset = offset + (long)i + 1;

                    printf("FOUND_END: 0x%lX\n", carve_end_offset);
                    fflush(stdout);

                    /* Save the carved JPEG */
                    save_recovered_file(output_dir, recovered_count,
                                        carve_buffer, carve_length);
                    recovered_count++;

                    /* Reset state for next potential file */
                    in_jpeg = 0;
                    carve_length = 0;

                    i++;  /* Skip past the D9 byte */
                }

                /* Safety: abort if carved data exceeds max size */
                if (carve_length >= MAX_JPEG_SIZE) {
                    fprintf(stderr,
                            "[!] WARNING: Carved data exceeded %d bytes at "
                            "offset 0x%lX. Aborting this carve.\n",
                            MAX_JPEG_SIZE, carve_start_offset);
                    in_jpeg = 0;
                    carve_length = 0;
                }
            }
        }

        /*
         * Handle the very last byte of the chunk separately.
         * If we're inside a JPEG, we still need to accumulate it.
         * The cross-boundary SOI/EOI detection is handled by the overlap:
         * fseek back by 1 byte so the next chunk re-reads the last byte.
         */
        if (in_jpeg && bytes_read > 0) {
            *(carve_buffer + carve_length) = *(buffer + bytes_read - 1);
            carve_length++;
        }

        offset += (long)bytes_read;

        /*
         * Seek back 1 byte to handle markers that straddle chunk boundaries.
         * This ensures we never miss an FF D8 or FF D9 split across two reads.
         */
        if (bytes_read == READ_BUFFER_SIZE) {
            fseek(fp, -1L, SEEK_CUR);
            offset -= 1;
        }
    }

    /* ---- Signal scan completion ---- */
    printf("SCAN_COMPLETE: %d\n", recovered_count);
    fflush(stdout);

    fprintf(stderr, "[+] Scan complete. Recovered %d file(s).\n", recovered_count);

    /* ---- Free all manually allocated memory ---- */
    free(carve_buffer);
    free(buffer);
    fclose(fp);

    return recovered_count;
}


/*
 * main()
 * ------
 * Entry point. Parses arguments and kicks off the scan.
 */
int main(int argc, char *argv[])
{
    const char *image_path;
    const char *output_dir = ".";  /* Default: save recovered files in CWD */

    fprintf(stderr, "\n");
    fprintf(stderr, "  ╔══════════════════════════════════════════════╗\n");
    fprintf(stderr, "  ║   RequiemFS — Raw Disk Forensic Engine      ║\n");
    fprintf(stderr, "  ║   The undead files, shall rise.             ║\n");
    fprintf(stderr, "  ╚══════════════════════════════════════════════╝\n");
    fprintf(stderr, "\n");

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <disk_image.img> [output_directory]\n", argv[0]);
        fprintf(stderr, "\n");
        fprintf(stderr, "  Scans a raw disk image for deleted JPEG files\n");
        fprintf(stderr, "  using magic number carving (FF D8 ... FF D9).\n");
        fprintf(stderr, "\n");
        return 1;
    }

    image_path = argv[1];

    if (argc >= 3) {
        output_dir = argv[2];
    }

    fprintf(stderr, "[*] Target image : %s\n", image_path);
    fprintf(stderr, "[*] Output dir   : %s\n", output_dir);
    fprintf(stderr, "\n");

    scan_disk_image(image_path, output_dir);

    return 0;
}
