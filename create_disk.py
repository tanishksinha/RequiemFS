import os
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

def create_test_disk(filename="test_disk.img"):
    print(f"[*] Creating {DISK_SIZE/1024/1024:.0f}MB test disk: {filename}")
    
    # 1. Fill disk with zeroes and some random noise to simulate unallocated/fragmented sectors
    with open(filename, "wb") as f:
        chunk_size = 1024 * 1024 # 1MB chunks
        for _ in range(DISK_SIZE // chunk_size):
            # Mix of 90% zeros and 10% random noise
            noise = bytearray(random.getrandbits(8) for _ in range(chunk_size // 10))
            zeroes = bytearray(chunk_size - len(noise))
            f.write(noise + zeroes)

    # 2. Determine injection location (aligned to sector boundaries)
    jpeg_data = DUMMY_JPEG
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
    print(f"[+] Magic Number Carving Target resides exactly at 0x{inject_offset:X} to 0x{inject_offset + len(jpeg_data):X}")

if __name__ == "__main__":
    create_test_disk()
