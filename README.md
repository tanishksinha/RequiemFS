# RequiemFS
> *The undead files, shall rise.*

A **Raw Disk Forensic Recovery Visualizer** — an educational OS simulator demonstrating File-System Implementation concepts from Silberschatz's *Operating System Concepts* (Chapter 12).

## What It Does

RequiemFS bypasses the OS file system API entirely. It reads raw disk sectors, hunts for **Magic Numbers** (JPEG signatures: `FF D8 FF E0`), carves out deleted file data, and resurrects it — just like real forensic tools (PhotoRec, Scalpel, Foremost).

## Architecture

| Component | Language | Purpose |
|-----------|----------|---------|
| `create_disk.py` | Python | Generates a 10MB test disk image with injected "deleted" JPEGs |
| `forensics.c` | C | Low-level forensics engine — raw `fread`/`fseek`, pointer arithmetic, `malloc`/`free` |
| `app.py` | Python + CustomTkinter | Dark-mode forensic dashboard with sector map, hex viewer, and recovery panel |

## Quick Start

```bash
# 1. Generate a test disk image
python create_disk.py
# Or inject your own JPEG:
python create_disk.py --import photo.jpg

# 2. Compile the forensics engine
gcc forensics.c -o forensics.exe

# 3. Launch the dashboard
python app.py
```

## Dependencies

```bash
pip install customtkinter Pillow
```
A C compiler (GCC/MinGW) is required for the forensics engine.

## OS Concepts Demonstrated

- **Unlinked Inodes**: File deletion removes directory entries, but data blocks remain on disk
- **Raw Block Reading**: Bypassing the VFS to read sectors directly as a block device
- **Magic Number Carving**: Identifying file types by byte signatures without file system metadata
- **Manual Memory Management**: `malloc`/`free` with raw pointer arithmetic in the C engine

## Screenshots

*Launch `app.py`, load a disk image, and run the forensic scan to see the sector map light up as deleted files are carved and recovered.*

## License

MIT
