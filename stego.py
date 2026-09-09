#!/usr/bin/env python3
"""
CTF Steganography & Embedded Payload Analysis Tool (zsteg + binwalk functionality)
Analyzes images and binary files for LSB steganography, embedded sub-files, hidden chunks, and payloads.
"""

import sys
import os
import re
import base64
import argparse
import struct
import numpy as np
from PIL import Image

# ANSI Terminal Colors
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

# Universal Flag Regex Patterns
FLAG_REGEX = re.compile(r'[A-Za-z0-9_\-]{1,25}\{[^}\s\r\n]+\}', re.IGNORECASE)
B64_REGEX = re.compile(r'[A-Za-z0-9+/]{12,}={0,2}')

# Comprehensive Binary Signatures for Carving (binwalk equivalent)
FILE_SIGNATURES = [
    (b'PK\x03\x04', 'ZIP Archive', '.zip'),
    (b'7z\xbc\xaf\x27\x1c', '7-Zip Archive', '.7z'),
    (b'Rar!\x1a\x07', 'RAR Archive', '.rar'),
    (b'\x1f\x8b\x08', 'GZIP Compressed Data', '.gz'),
    (b'BZh', 'BZIP2 Compressed Data', '.bz2'),
    (b'\x89PNG\r\n\x1a\n', 'PNG Image', '.png'),
    (b'\xff\xd8\xff', 'JPEG Image', '.jpg'),
    (b'BM', 'BMP Image', '.bmp'),
    (b'GIF87a', 'GIF Image', '.gif'),
    (b'GIF89a', 'GIF Image', '.gif'),
    (b'%PDF-', 'PDF Document', '.pdf'),
    (b'\x7fELF', 'ELF Binary Executable', '.elf'),
    (b'MZ', 'Windows Executable', '.exe'),
    (b'ID3', 'MP3 Audio (ID3 Tag)', '.mp3'),
    (b'OggS', 'OGG Audio/Video Container', '.ogg'),
    (b'fLaC', 'FLAC Lossless Audio', '.flac'),
    (b'RIFF', 'RIFF Media Container (WAV/WEBP/AVI)', '.riff'),
]

discovered_flags = []

def log_flag(flag, source):
    entry = {'flag': flag, 'source': source}
    if entry not in discovered_flags:
        discovered_flags.append(entry)
        print(f"  {Colors.BOLD}{Colors.GREEN}🚩 FOUND FLAG:{Colors.RESET} {Colors.CYAN}{flag}{Colors.RESET}")
        print(f"     {Colors.YELLOW}Source:{Colors.RESET} {source}\n")

def scan_text_for_flags(text, source_tag):
    if not text:
        return
    for f in FLAG_REGEX.findall(text):
        log_flag(f, source_tag)

    for b64 in B64_REGEX.findall(text):
        try:
            pad = b64 + '=' * ((4 - len(b64) % 4) % 4)
            decoded = base64.b64decode(pad).decode('utf-8', errors='ignore')
            for df in FLAG_REGEX.findall(decoded):
                log_flag(df, f"Base64 Decoded ({b64[:16]}...) in {source_tag}")
        except Exception:
            pass

# ─── 1. ZSTEG / LSB STEGANOGRAPHY ENGINE ───────────────────────────
def analyze_lsb_stego(filepath, verbose=False):
    print(f"\n{Colors.BOLD}{Colors.BLUE}🎨 1. LSB (LEAST SIGNIFICANT BIT) STEGANOGRAPHY SCAN (zsteg){Colors.RESET}")
    print("=" * 65)

    try:
        img = Image.open(filepath)
    except Exception as e:
        print(f"  ℹ️ File is not a valid image or cannot be opened by PIL ({e}). Skipping LSB scan.\n")
        return

    img = img.convert('RGBA')
    arr = np.array(img)
    height, width, channels = arr.shape
    print(f"  {Colors.BOLD}Image Format:{Colors.RESET} {img.format}, Dimensions: {width}x{height}, Mode: {img.mode}")

    # Channel indices: R=0, G=1, B=2, A=3
    channel_map = {'r': 0, 'g': 1, 'b': 2, 'a': 3}
    channel_combos = [
        ('r', [0]), ('g', [1]), ('b', [2]), ('a', [3]),
        ('rgb', [0, 1, 2]), ('bgr', [2, 1, 0]),
        ('rgba', [0, 1, 2, 3]), ('abgr', [3, 2, 1, 0])
    ]

    bits_found_count = 0

    # Scan 1-bit, 2-bit, and 4-bit LSBs across channels
    for bit_depth in [1, 2, 4]:
        mask = (1 << bit_depth) - 1
        for name, ch_list in channel_combos:
            try:
                # Extract pixel channel bits
                extracted_bits = []
                for ch in ch_list:
                    ch_data = arr[:, :, ch]
                    channel_bits = ch_data & mask
                    extracted_bits.append(channel_bits)

                # Stack and flatten bits (row-by-row)
                stacked = np.dstack(extracted_bits).flatten()
                
                # Convert bit values to bytes
                if bit_depth == 1:
                    byte_data = np.packbits(stacked).tobytes()
                else:
                    # Multi-bit LSB packing
                    bit_str = ''.join([bin(val)[2:].zfill(bit_depth) for val in stacked[:20000]])
                    byte_chunks = [int(bit_str[i:i+8], 2) for i in range(0, len(bit_str)-8, 8)]
                    byte_data = bytes(byte_chunks)

                text = byte_data.decode('utf-8', errors='ignore')
                combo_tag = f"LSB {bit_depth}-bit ({name})"

                # Check flags
                flags_found = FLAG_REGEX.findall(text)
                if flags_found:
                    bits_found_count += len(flags_found)
                    for f in flags_found:
                        log_flag(f, f"zsteg LSB Analysis -> {combo_tag}")

                # Check Base64 candidates inside LSB
                for b64 in B64_REGEX.findall(text):
                    try:
                        pad = b64 + '=' * ((4 - len(b64) % 4) % 4)
                        decoded = base64.b64decode(pad).decode('utf-8', errors='ignore')
                        for df in FLAG_REGEX.findall(decoded):
                            bits_found_count += 1
                            log_flag(df, f"Base64 in zsteg LSB Analysis -> {combo_tag}")
                    except Exception:
                        pass

                if verbose:
                    printable = ''.join([c if 32 <= ord(c) <= 126 else '.' for c in text[:60]])
                    print(f"  [{combo_tag:<18}] -> {printable}")

            except Exception:
                pass

    if bits_found_count == 0:
        print(f"  {Colors.GREEN}✓ LSB Scan complete. No immediate flags detected in standard LSB planes.{Colors.RESET}")

# ─── 2. BINWALK / EMBEDDED FILE CARVING ENGINE ─────────────────────
def analyze_binwalk_embedded(filepath, extract=False):
    print(f"\n{Colors.BOLD}{Colors.BLUE}📦 2. BINWALK & EMBEDDED FILE CARVING SCAN{Colors.RESET}")
    print("=" * 65)

    with open(filepath, 'rb') as f:
        data = f.read()

    file_size = len(data)
    print(f"  {Colors.BOLD}Target File Size:{Colors.RESET} {file_size} bytes ({hex(file_size)})")

    matches = []

    # Scan for header signatures
    for sig, desc, ext in FILE_SIGNATURES:
        offsets = [m.start() for m in re.finditer(re.escape(sig), data)]
        for offset in offsets:
            matches.append((offset, desc, ext, sig))

    # Sort matches by byte offset
    matches.sort(key=lambda x: x[0])

    if not matches:
        print(f"  {Colors.GREEN}✓ No embedded headers found inside this file.{Colors.RESET}")
        return

    print(f"\n  {Colors.BOLD}{Colors.YELLOW}Discovered Embedded Signatures:{Colors.RESET}\n")
    print(f"  {'DECIMAL':<10} {'HEXADECIMAL':<12} {'DESCRIPTION':<35}")
    print(f"  {'-'*10} {'-'*12} {'-'*35}")

    for idx, (offset, desc, ext, sig) in enumerate(matches):
        # Skip if match is at offset 0 and matches primary file
        is_primary = (offset == 0)
        marker = " (Primary File Header)" if is_primary else f" 🚨 {Colors.RED}EMBEDDED SUB-FILE{Colors.RESET}"
        print(f"  {offset:<10} {hex(offset):<12} {desc:<35} {marker}")

        # Scan text around offset
        sub_data = data[offset:offset+10000]
        text_sub = sub_data.decode('utf-8', errors='ignore')
        scan_text_for_flags(text_sub, f"Binwalk offset {hex(offset)} ({desc})")

        # Auto Extract / Carve if requested
        if extract and not is_primary:
            out_dir = os.path.join(os.path.dirname(filepath), "extracted_stego")
            os.makedirs(out_dir, exist_ok=True)
            carved_filename = f"carved_at_{hex(offset)}_{idx}{ext}"
            carved_path = os.path.join(out_dir, carved_filename)
            
            with open(carved_path, 'wb') as carved_file:
                carved_file.write(data[offset:])
            print(f"     {Colors.GREEN}↳ Carved & saved to: {carved_path}{Colors.RESET}")

# ─── 3. PNG CHUNK STRUCTURE INSPECTION ──────────────────────────────
def analyze_png_chunks(filepath):
    print(f"\n{Colors.BOLD}{Colors.BLUE}🖼️ 3. PNG CHUNK STRUCTURE INSPECTOR{Colors.RESET}")
    print("=" * 65)

    with open(filepath, 'rb') as f:
        data = f.read()

    if not data.startswith(b'\x89PNG\r\n\x1a\n'):
        print("  ℹ️ Not a PNG file. Skipping PNG chunk inspection.\n")
        return

    offset = 8
    chunks = []
    standard_chunks = {'IHDR', 'PLTE', 'IDAT', 'IEND', 'tRNS', 'cHRM', 'gAMA', 'iCCP', 'sBIT', 'sRGB', 'tEXt', 'zTXt', 'iTXt', 'bKGD', 'hIST', 'pHYs', 'tIME'}

    print(f"  {'CHUNK':<10} {'OFFSET':<12} {'LENGTH':<10} {'STATUS':<20}")
    print(f"  {'-'*10} {'-'*12} {'-'*10} {'-'*20}")

    while offset < len(data):
        if offset + 8 > len(data):
            break
        length = struct.unpack('>I', data[offset:offset+4])[0]
        chunk_type = data[offset+4:offset+8].decode('utf-8', errors='ignore')
        
        status = "Standard" if chunk_type in standard_chunks else f"{Colors.RED}NON-STANDARD / CUSTOM{Colors.RESET}"
        print(f"  {chunk_type:<10} {hex(offset):<12} {length:<10} {status:<20}")

        chunk_data = data[offset+8:offset+8+length]
        scan_text_for_flags(chunk_data.decode('utf-8', errors='ignore'), f"PNG Chunk [{chunk_type}] at {hex(offset)}")

        offset += 12 + length  # Length (4) + Type (4) + Data (N) + CRC (4)

        if chunk_type == 'IEND':
            break

    if offset < len(data):
        trailing_bytes = len(data) - offset
        print(f"\n  {Colors.BOLD}{Colors.RED}🚨 TRAILING DATA AFTER IEND CHUNK!{Colors.RESET} ({trailing_bytes} bytes at offset {hex(offset)})")
        scan_text_for_flags(data[offset:].decode('utf-8', errors='ignore'), "PNG Trailing Bytes")

# ─── MAIN DRIVER ─────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="CTF Steganography & Embedded Payload Analysis Tool (zsteg + binwalk)")
    parser.add_argument("filepath", help="Path to target image or mystery file")
    parser.add_argument("-e", "--extract", action="store_true", help="Automatically carve embedded files and extract payloads")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print verbose LSB bitstream analysis")
    parser.add_argument("--lsb-only", action="store_true", help="Run only LSB stego scan (zsteg mode)")
    parser.add_argument("--carve-only", action="store_true", help="Run only embedded carving scan (binwalk mode)")

    args = parser.parse_args()

    if not os.path.exists(args.filepath):
        print(f"{Colors.RED}❌ Error: File '{args.filepath}' does not exist.{Colors.RESET}")
        sys.exit(1)

    print(f"\n{Colors.BOLD}{Colors.HEADER}============================================================={Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.HEADER} 🕵️  CTF STEGANOGRAPHY & EMBEDDED FILE ANALYZER (zsteg/binwalk){Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.HEADER}============================================================={Colors.RESET}")

    if not args.carve_only:
        analyze_lsb_stego(args.filepath, verbose=args.verbose)
        analyze_png_chunks(args.filepath)

    if not args.lsb_only:
        analyze_binwalk_embedded(args.filepath, extract=args.extract)

    print(f"\n{Colors.BOLD}{Colors.HEADER}============================================================={Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.HEADER} 🏁 STEGO ANALYSIS SUMMARY{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.HEADER}============================================================={Colors.RESET}\n")

    if not discovered_flags:
        print(f"  {Colors.YELLOW}❌ No explicit flags automatically captured.{Colors.RESET}")
        print("  💡 Tip: Run with `-e` to carve embedded sub-files or check color planes.\n")
    else:
        print(f"  {Colors.GREEN}✅ Total Unique Flags Found: {len(discovered_flags)}{Colors.RESET}\n")
        for i, entry in enumerate(discovered_flags, 1):
            print(f"  [{i}] {Colors.BOLD}{Colors.CYAN}{entry['flag']}{Colors.RESET}")
            print(f"      → Source: {entry['source']}\n")

if __name__ == "__main__":
    main()
