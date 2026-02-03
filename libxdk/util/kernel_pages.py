#!/usr/bin/env python3
import sys
import subprocess
import re

# Constants
HUGE_PAGE_SIZE = 2 * 1024 * 1024  # 2 MB

def get_elf_data(vmlinux_path):
    data = {'segments': [], 'sections': {}}
    
    # --- 1. Parse Program Headers (Segments) ---
    try:
        # -lW for wide output (prevent truncation)
        cmd = ["readelf", "-lW", vmlinux_path]
        output = subprocess.check_output(cmd, universal_newlines=True)
    except FileNotFoundError:
        print("Error: 'readelf' command not found.")
        sys.exit(1)
        
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("LOAD"):
            continue
            
        parts = line.split()
        # Columns: Type Offset VirtAddr PhysAddr FileSiz MemSiz Flg Align
        # We need PhysAddr (col 3) and MemSiz (col 5)
        try:
            phys_addr = int(parts[3], 16)
            mem_size = int(parts[5], 16)
            data['segments'].append({'phys': phys_addr, 'size': mem_size})
        except (ValueError, IndexError):
            continue

    # --- 2. Parse Section Headers (Sections) ---
    try:
        cmd = ["readelf", "-SW", vmlinux_path]
        output = subprocess.check_output(cmd, universal_newlines=True)
    except subprocess.CalledProcessError:
        print("Error: Could not read section headers.")
        sys.exit(1)
    
    sec_pattern = re.compile(r"\[\s*\d+\]\s+([\w\.]+)\s+\w+\s+([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)")
    
    for line in output.splitlines():
        match = sec_pattern.search(line)
        if match:
            name = match.group(1)
            address = int(match.group(2), 16)
            size = int(match.group(3), 16)
            data['sections'][name] = {'address': address, 'size': size}
            
    return data

def merge_segments(segments):
    """
    Merges contiguous or overlapping physical memory ranges.
    Returns a list of (start, end) tuples.
    """
    if not segments:
        return []

    # Sort by physical start address
    segments.sort(key=lambda x: x['phys'])
    
    merged = []
    
    # Start with the first segment
    current_start = segments[0]['phys']
    current_end = current_start + segments[0]['size']
    
    for i in range(1, len(segments)):
        seg_start = segments[i]['phys']
        seg_end = seg_start + segments[i]['size']
        
        # If this segment starts before (or exactly when) the previous one ends, merge them.
        if seg_start <= current_end:
            current_end = max(current_end, seg_end)
        else:
            # We found a gap! Save the current block and start a new one.
            merged.append((current_start, current_end))
            current_start = seg_start
            current_end = seg_end
            
    merged.append((current_start, current_end))
    return merged

def calculate_pages(vmlinux_path):
    data = get_elf_data(vmlinux_path)
    
    print(f"Analyzing: {vmlinux_path}")
    print(f"Page Size: 2 MB ({HUGE_PAGE_SIZE:,} bytes)")
    print("-" * 40)

    # --- Step 1: Calculate Initial Load (Merged) ---
    print("1. Physical Memory Layout (Merged):")
    
    merged_blocks = merge_segments(data['segments'])
    total_initial_pages = 0
    
    for start, end in merged_blocks:
        size = end - start
        
        # Calculate pages based on the start and end frame indices
        start_page_idx = start // HUGE_PAGE_SIZE
        # (end - 1) ensures that if we end exactly on a boundary, we don't count the next page
        end_page_idx = (end - 1) // HUGE_PAGE_SIZE
        
        pages_count = end_page_idx - start_page_idx + 1
        total_initial_pages += pages_count
        
        print(f"   Block [0x{start:x} - 0x{end:x}]")
        print(f"     Size: {size/1024/1024:.2f} MB")
        print(f"     Spans: Pages {start_page_idx} to {end_page_idx} -> {pages_count} Huge Pages")

    print(f"   [Initial Total]: {total_initial_pages} Huge Pages")
    print("-" * 40)

    # --- Step 2: Check for Reclaimable Init Memory ---
    reclaimable_pages = 0
    
    # Find the init section with the highest end address
    max_init_end = 0
    found_init = False
    
    for name, sec in data['sections'].items():
        if ".init" in name:
            end_addr = sec['address'] + sec['size']
            if end_addr > max_init_end:
                max_init_end = end_addr
                found_init = True

    if found_init:
        # Find the specific section at the very end
        last_sec_size = 0
        last_sec_name = ""
        
        for name, sec in data['sections'].items():
            if sec['address'] + sec['size'] == max_init_end:
                last_sec_size = sec['size']
                last_sec_name = name
                break
        
        # Calculate reclaimable pages
        reclaimable_pages = last_sec_size // HUGE_PAGE_SIZE
        
        print(f"2. Reclaimable Section ({last_sec_name}):")
        print(f"   Size: {last_sec_size/1024/1024:.2f} MB")
        print(f"   Status: Frees {reclaimable_pages} full pages.")
    else:
        print("2. No .init sections found.")

    print("-" * 40)

    # --- Step 3: Final Calculation ---
    runtime_pages = total_initial_pages - reclaimable_pages
    print(f"3. Final Runtime Calculation:")
    print(f"   {total_initial_pages} (Initial) - {reclaimable_pages} (Freed) = {runtime_pages}")
    print("=" * 40)
    print(f"   RUNTIME PAGES: {runtime_pages}")
    print("=" * 40)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: ./kernel_pages.py <path_to_vmlinux>")
        sys.exit(1)
    
    calculate_pages(sys.argv[1])
