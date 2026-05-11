"""
create_disk.py - RequiemFS Disk Image Generator

Creates a fake disk image and hides files in it to simulate
what happens when you delete a file - the OS removes the pointer
(inode entry) but the actual bytes are still sitting there on disk.

This is basically a controlled test environment so we can verify
that our forensics engine actually works before trying it on
real disk images.

Usage:
  python create_disk.py                              # uses built-in dummy JPEG
  python create_disk.py --import photo.jpg           # inject your own file
  python create_disk.py --import photo.jpg --count 3 # inject it 3 times
  python create_disk.py -o my_disk.img               # custom output name
"""

import os
import sys
import random
import math

# disk config - 10MB is small enough to be fast but big enough
# to demonstrate the concept. real disks are obviously way bigger
DISK_SIZE = 10 * 1024 * 1024  # 10 MB
SECTOR_SIZE = 512

# how many sectors to reserve at the start of the disk
# (simulates MBR, partition table, boot sector, etc.)
RESERVED_SECTORS = 100

# a minimal valid JPEG - it's just a 1x1 white pixel but it has
# proper SOI (FF D8) and EOI (FF D9) markers so the carver can find it.
# I generated this by creating a tiny image in Python/PIL and hex-dumping it.
# honestly it took forever to get a minimal valid JPEG that actually opens lol
DUMMY_JPEG = bytes.fromhex(
    "ffd8ffe000104a46494600010101004800480000ffdb004300030202020202030202030303030406040404040408060605"
    "0609080a0a090809090a0c0f0c0a0b0e0b09090d110d0e0f101011100a0c12131210130f101010ffdb0043010303030403"
    "0408040408100b090b10101010101010101010101010101010101010101010101010101010101010101010101010101010"
    "10101010101010101010ffc00011080001000103012200021101031101ffc4001f00000105010101010101000000000000"
    "00000102030405060708090a0bffc400b5100002010303020403050504040000017d010203000411051221314106135161"
    "07227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738393a43444546474849"
    "4a535455565758595a636465666768696a737475767778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8"
    "a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9fa"
    "ffc4001f0100030101010101010101010000000000000102030405060708090a0bffc400b5110002010204040304070504"
    "0400010277000102031104052131061241510761711322328108144291a1b1c109233352f0156272d10a162434e125f117"
    "18191a262728292a35363738393a434445464748494a535455565758595a636465666768696a737475767778797a828384"
    "85868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8"
    "d9dae2e3e4e5e6e7e8e9eaf2f3f4f5f6f7f8f9faffda000c03010002110311003f00f9fe8a28a00fffd9"
)


def load_payload(image_path=None):
    """
    Load the file we want to inject into the disk image.
    If no path given, uses the built-in tiny JPEG.
    Also validates that the file looks legit before we inject it.
    """
    if image_path is None:
        print("[*] No image provided, using built-in 1x1 dummy JPEG")
        return DUMMY_JPEG, "JPEG"

    image_path = os.path.abspath(image_path)
    if not os.path.isfile(image_path):
        print(f"[!] ERROR: file not found: {image_path}")
        sys.exit(1)

    with open(image_path, "rb") as f:
        data = f.read()

    # figure out what type of file this is by checking the magic bytes
    # (this is literally the same thing our forensics engine does lol)
    ftype = "UNKNOWN"
    if len(data) >= 2 and data[0] == 0xFF and data[1] == 0xD8:
        ftype = "JPEG"
    elif len(data) >= 8 and data[:8] == bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]):
        ftype = "PNG"
    elif len(data) >= 4 and data[:4] == b'%PDF':
        ftype = "PDF"
    else:
        print(f"[!] WARNING: can't identify file type for '{image_path}'")
        print(f"[*] Injecting anyway - the forensics engine might not find it though")
        ftype = "UNKNOWN"

    # make sure it'll actually fit in the disk
    max_payload = DISK_SIZE - (RESERVED_SECTORS * SECTOR_SIZE)
    if len(data) > max_payload:
        print(f"[!] ERROR: file too big ({len(data)} bytes), max is {max_payload}")
        sys.exit(1)

    print(f"[+] Loaded {ftype}: {image_path} ({len(data)} bytes)")
    return data, ftype


def generate_noise_chunk(size):
    """
    Generate a chunk of random-looking data to simulate what
    unallocated disk space actually looks like. Real unallocated
    space is a mix of zeros (never written) and old data fragments
    (previously written then freed).
    
    We mix 10% noise with 90% zeros - this ratio roughly mimics
    a moderately used disk.
    """
    noise_size = size // 10
    noise = bytearray(random.getrandbits(8) for _ in range(noise_size))

    # IMPORTANT: scrub out any accidental JPEG/PNG/PDF signatures
    # from the noise. otherwise the forensics engine gets confused
    # by false positives (learned this the hard way...)
    for j in range(len(noise) - 1):
        # kill JPEG SOI markers
        if noise[j] == 0xFF and noise[j + 1] == 0xD8:
            noise[j + 1] = 0x00
        # kill PNG headers
        if noise[j] == 0x89 and noise[j + 1] == 0x50:
            noise[j + 1] = 0x00
        # kill PDF headers
        if noise[j] == 0x25 and noise[j + 1] == 0x50:
            noise[j + 1] = 0x00

    zeroes = bytearray(size - noise_size)
    return noise + zeroes


def pick_injection_offsets(payload_size, count=1):
    """
    Pick random sector-aligned positions to inject files.
    Makes sure injections don't overlap with each other or
    with the reserved sectors at the start.
    
    This simulates files being scattered across the disk in
    non-contiguous locations (like a fragmented filesystem would have).
    """
    # how many sectors does our payload need?
    sectors_needed = math.ceil(payload_size / SECTOR_SIZE) + 2  # +2 for padding
    total_sectors = DISK_SIZE // SECTOR_SIZE
    max_sector = total_sectors - sectors_needed

    offsets = []
    attempts = 0
    max_attempts = count * 100  # don't loop forever if we can't fit everything

    while len(offsets) < count and attempts < max_attempts:
        attempts += 1
        sector = random.randint(RESERVED_SECTORS, max_sector)
        byte_offset = sector * SECTOR_SIZE

        # check this doesn't overlap with any existing injection
        overlap = False
        for existing_off in offsets:
            # simple overlap check - are the two regions too close?
            if abs(byte_offset - existing_off) < (sectors_needed * SECTOR_SIZE):
                overlap = True
                break

        if not overlap:
            offsets.append(byte_offset)

    if len(offsets) < count:
        print(f"[!] WARNING: could only fit {len(offsets)} injections (requested {count})")

    return offsets


def create_test_disk(filename="test_disk.img", image_path=None, inject_count=1):
    """
    Main function - creates the raw disk image and injects files into it.
    
    This simulates the state of a disk after files have been "deleted":
    the directory entry and inode are gone, but the actual file data
    is still sitting in the unallocated blocks, waiting to be found
    by someone running a forensic carving tool.
    """
    payload, ftype = load_payload(image_path)

    print(f"[*] Creating {DISK_SIZE / 1024 / 1024:.0f}MB test disk: {filename}")

    # step 1: fill the whole disk with noise + zeros
    # this represents unallocated space on a real disk
    with open(filename, "wb") as f:
        chunk_size = 1024 * 1024  # write 1MB at a time
        for i in range(DISK_SIZE // chunk_size):
            chunk = generate_noise_chunk(chunk_size)
            f.write(chunk)
            # show progress because 10MB takes a sec
            pct = ((i + 1) * chunk_size * 100) // DISK_SIZE
            print(f"\r[*] Writing disk... {pct}%", end="", flush=True)
    print()  # newline after progress

    # step 2: pick where to inject our "deleted" files
    offsets = pick_injection_offsets(len(payload), inject_count)

    # step 3: inject the payload at each offset
    # we use r+b mode so we overwrite specific positions
    # without destroying the rest of the disk data
    print(f"[*] Simulating {len(offsets)} 'deleted' {ftype} file(s) via unlinked inodes")

    with open(filename, "r+b") as f:
        for idx, offset in enumerate(offsets):
            sector = offset // SECTOR_SIZE
            f.seek(offset)
            f.write(payload)
            print(f"    [{idx+1}] Injected at 0x{offset:08X} (sector {sector})")

    # print summary
    print(f"\n[+] {filename} created successfully!")
    print(f"[+] {len(offsets)} unlinked inode(s) planted")
    for offset in offsets:
        end = offset + len(payload)
        print(f"    Target: 0x{offset:08X} -> 0x{end:08X} ({len(payload)} bytes)")


def print_usage():
    """show how to use this thing"""
    print("Usage:")
    print("  python create_disk.py                              # dummy JPEG")
    print("  python create_disk.py --import <file>              # your own file")
    print("  python create_disk.py --import <file> --count 3    # inject 3 copies")
    print("  python create_disk.py -o <output.img>              # custom filename")
    print()
    print("Supported file types for import: JPEG, PNG, PDF")


if __name__ == "__main__":
    output_file = "test_disk.img"
    import_image = None
    inject_count = 1

    # parse command line args (keeping it simple, no argparse needed)
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] in ("--import", "-i"):
            if i + 1 >= len(args):
                print("[!] --import needs a file path")
                print_usage()
                sys.exit(1)
            import_image = args[i + 1]
            i += 2
        elif args[i] in ("-o", "--output"):
            if i + 1 >= len(args):
                print("[!] -o needs a filename")
                print_usage()
                sys.exit(1)
            output_file = args[i + 1]
            i += 2
        elif args[i] in ("-c", "--count"):
            if i + 1 >= len(args):
                print("[!] --count needs a number")
                print_usage()
                sys.exit(1)
            inject_count = int(args[i + 1])
            i += 2
        elif args[i] in ("-h", "--help"):
            print_usage()
            sys.exit(0)
        else:
            print(f"[!] Unknown arg: {args[i]}")
            print_usage()
            sys.exit(1)

    create_test_disk(filename=output_file, image_path=import_image,
                     inject_count=inject_count)
