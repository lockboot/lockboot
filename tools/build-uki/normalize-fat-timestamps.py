#!/usr/bin/env python3
"""
Normalize directory timestamps in a FAT32 filesystem to 1980-01-01 00:00:00
for reproducible builds. Only modifies known directory entry locations.
"""
import sys
import struct

def normalize_dir_entry(data, offset, fixed_time, fixed_date):
    """Normalize a single directory entry's timestamps"""
    # Creation time fine resolution (10ms units) at offset 13
    data[offset + 13] = 0x00
    # Creation time (offset 14-15) and date (offset 16-17)
    struct.pack_into('<H', data, offset + 14, fixed_time)
    struct.pack_into('<H', data, offset + 16, fixed_date)
    # Last access date (offset 18-19)
    struct.pack_into('<H', data, offset + 18, fixed_date)
    # Last modified time (offset 22-23) and date (offset 24-25)
    struct.pack_into('<H', data, offset + 22, fixed_time)
    struct.pack_into('<H', data, offset + 24, fixed_date)

def find_and_normalize_dirs(data, fixed_time, fixed_date):
    """Find directory entries by looking for known patterns and normalize them"""
    modified = False

    # Scan for directory entries (32 bytes each)
    for i in range(0, len(data) - 32, 32):
        first_byte = data[i]
        attr = data[i + 11]

        # Skip empty or deleted entries
        if first_byte == 0x00 or first_byte == 0xE5:
            continue

        # Skip long filename entries (attr = 0x0F)
        if attr == 0x0F:
            continue

        # Check if this is a directory entry (attr & 0x10) or special entries (. and ..)
        # OR if it's a plain file (attr & 0x20) in a directory
        # Only process if it looks like EFI, BOOT, or BOOTX64.EFI
        name = data[i:i+11].decode('ascii', errors='ignore').strip()

        if (name.startswith('EFI') or name.startswith('BOOT') or
            name.startswith('.') or name.startswith('BOOTX64')):
            normalize_dir_entry(data, i, fixed_time, fixed_date)
            modified = True

    return modified

def normalize_fat_timestamps(image_path, offset):
    """Set directory entry timestamps to 1980-01-01 00:00:00"""
    # FAT timestamp for 1980-01-01 00:00:00
    fixed_time = 0x0000
    fixed_date = 0x0021

    with open(image_path, 'r+b') as f:
        # Read boot sector to find root directory location
        f.seek(offset)
        boot = f.read(512)

        bytes_per_sector = struct.unpack('<H', boot[11:13])[0]
        sectors_per_cluster = boot[13]
        reserved_sectors = struct.unpack('<H', boot[14:16])[0]
        num_fats = boot[16]
        sectors_per_fat = struct.unpack('<I', boot[36:40])[0]
        root_cluster = struct.unpack('<I', boot[44:48])[0]

        # Calculate data area start
        data_area_offset = offset + (reserved_sectors + num_fats * sectors_per_fat) * bytes_per_sector
        cluster_size = sectors_per_cluster * bytes_per_sector

        # Read and fix only the first 3 data clusters (root + EFI dir + BOOT dir)
        # This is safe and won't touch file data
        for cluster_idx in range(3):
            cluster_num = root_cluster + cluster_idx
            cluster_offset = data_area_offset + (cluster_num - 2) * cluster_size

            f.seek(cluster_offset)
            data = bytearray(f.read(cluster_size))

            if find_and_normalize_dirs(data, fixed_time, fixed_date):
                f.seek(cluster_offset)
                f.write(data)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <image_file> <partition_offset>")
        sys.exit(1)

    image_path = sys.argv[1]
    offset = int(sys.argv[2])
    normalize_fat_timestamps(image_path, offset)
    print("FAT timestamps normalized to 1980-01-01 00:00:00")
