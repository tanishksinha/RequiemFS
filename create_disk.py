import os
import sys
import random

DISK_SIZE = 10 * 1024 * 1024  # 10 MB
SECTOR_SIZE = 512

# A minimal valid 1x1 JPEG image bytes
# Used to simulate the carved file without external dependencies
# Contains valid FF D8 (SOI) and FF D9 (EOI) markers
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


def load_jpeg_payload(image_path=None):
    """
    Load JPEG payload from user-provided image file or fall back to the
    built-in dummy JPEG. Validates the file has correct JPEG magic numbers.
    """
    if image_path is None:
        print("[*] No image provided. Using built-in 1x1 dummy JPEG.")
        return DUMMY_JPEG

    image_path = os.path.abspath(image_path)
    if not os.path.isfile(image_path):
        print(f"[!] ERROR: File not found: {image_path}")
        sys.exit(1)

    with open(image_path, "rb") as f:
        data = f.read()

    # Validate JPEG SOI marker (FF D8)
    if len(data) < 4 or data[0] != 0xFF or data[1] != 0xD8:
        print(f"[!] ERROR: '{image_path}' is not a valid JPEG file (missing SOI marker FF D8).")
        sys.exit(1)

    # Validate JPEG EOI marker (FF D9) at the end
    if data[-2] != 0xFF or data[-1] != 0xD9:
        print(f"[!] WARNING: '{image_path}' may be truncated (missing EOI marker FF D9).")
        print(f"[*] Proceeding anyway — the forensics engine scans for EOI independently.")

    # Ensure image fits inside the disk (with room for reserved sectors)
    max_payload = DISK_SIZE - (100 * SECTOR_SIZE)  # Reserve first 100 sectors
    if len(data) > max_payload:
        print(f"[!] ERROR: Image too large ({len(data)} bytes). Max payload: {max_payload} bytes.")
        sys.exit(1)

    print(f"[+] Loaded user image: {image_path} ({len(data)} bytes)")
    return data


def create_test_disk(filename="test_disk.img", image_path=None):
    """
    Creates a raw disk image simulating unallocated space with a 'deleted'
    JPEG file embedded at a random sector-aligned offset.

    This demonstrates the OS concept of unlinked inodes: the file's data
    blocks remain on disk even after the directory entry / FAT pointer
    is removed. A forensic carver can recover them by scanning for magic
    numbers in raw blocks.
    """
    jpeg_data = load_jpeg_payload(image_path)

    print(f"[*] Creating {DISK_SIZE / 1024 / 1024:.0f}MB test disk: {filename}")

    # 1. Fill disk with zeroes and some random noise to simulate unallocated/fragmented sectors
    with open(filename, "wb") as f:
        chunk_size = 1024 * 1024  # 1MB chunks
        for _ in range(DISK_SIZE // chunk_size):
            # Mix of 90% zeros and 10% random noise
            noise = bytearray(random.getrandbits(8) for _ in range(chunk_size // 10))
            # Sanitize: remove accidental JPEG SOI markers (FF D8) from noise
            for j in range(len(noise) - 1):
                if noise[j] == 0xFF and noise[j + 1] == 0xD8:
                    noise[j + 1] = 0x00
            zeroes = bytearray(chunk_size - len(noise))
            f.write(noise + zeroes)

    # 2. Determine injection location (aligned to sector boundaries)
    max_sector = (DISK_SIZE - len(jpeg_data)) // SECTOR_SIZE

    # Avoid first 100 sectors to "simulate" reserved space like MBR/VBR
    inject_sector = random.randint(100, max_sector)
    inject_offset = inject_sector * SECTOR_SIZE

    print(f"[*] Simulating 'deleted' file via unlinked inode.")
    print(f"[*] Injecting JPEG (size: {len(jpeg_data)} bytes) at offset: 0x{inject_offset:X} (Sector {inject_sector})")

    # 3. Inject the JPEG directly into the raw disk, effectively "bypassing" the OS API
    with open(filename, "r+b") as f:
        f.seek(inject_offset)
        f.write(jpeg_data)

    print(f"[+] {filename} created successfully.")
    print(f"[+] Unlinked Inode / Deleted File simulation complete.")
    print(f"[+] Magic Number Carving Target: 0x{inject_offset:X} -> 0x{inject_offset + len(jpeg_data):X}")


def print_usage():
    print("Usage:")
    print("  python create_disk.py                         # Use built-in dummy JPEG")
    print("  python create_disk.py --import <path.jpg>     # Inject your own JPEG image")
    print("  python create_disk.py -o <output.img>         # Custom output filename")
    print()
    print("Examples:")
    print("  python create_disk.py --import photo.jpg")
    print("  python create_disk.py --import photo.jpg -o my_disk.img")


if __name__ == "__main__":
    output_file = "test_disk.img"
    import_image = None

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] in ("--import", "-i"):
            if i + 1 >= len(args):
                print("[!] ERROR: --import requires a file path argument.")
                print_usage()
                sys.exit(1)
            import_image = args[i + 1]
            i += 2
        elif args[i] in ("-o", "--output"):
            if i + 1 >= len(args):
                print("[!] ERROR: -o requires a filename argument.")
                print_usage()
                sys.exit(1)
            output_file = args[i + 1]
            i += 2
        elif args[i] in ("-h", "--help"):
            print_usage()
            sys.exit(0)
        else:
            print(f"[!] Unknown argument: {args[i]}")
            print_usage()
            sys.exit(1)

    create_test_disk(filename=output_file, image_path=import_image)
