#!/usr/bin/env python3
"""
CTF Forensics & Mystery File Analyzer Tool
Analyzes unknown/mystery files for hidden flags, metadata, file header mismatches, 
embedded payloads, and encoded strings.
"""

import sys
import os
import re
import base64
import binascii
import subprocess
import argparse
import struct
import zipfile
import tarfile
from PIL import Image, ExifTags

# ANSI Color Codes for Terminal Output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Universal Flag Regex Patterns
FLAG_REGEX = re.compile(r'[A-Za-z0-9_\-]{1,25}\{[^}\s\r\n]+\}', re.IGNORECASE)
UUID_REGEX = re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b')
SHA256_REGEX = re.compile(r'\b[a-fA-F0-9]{64}\b')
MD5_REGEX = re.compile(r'\b[a-fA-F0-9]{32}\b')
B64_REGEX = re.compile(r'[A-Za-z0-9+/]{12,}={0,2}')

# Magic Byte Signatures for Common File Types
MAGIC_SIGNATURES = [
    (b'\x89PNG\r\n\x1a\n', '.png', 'PNG Image'),
    (b'\xff\xd8\xff', '.jpg', 'JPEG Image'),
    (b'GIF87a', '.gif', 'GIF Image'),
    (b'GIF89a', '.gif', 'GIF Image'),
    (b'PK\x03\x04', '.zip', 'ZIP Archive'),
    (b'7z\xbc\xaf\x27\x1c', '.7z', '7-Zip Archive'),
    (b'Rar!\x1a\x07\x00', '.rar', 'RAR Archive'),
    (b'%PDF-', '.pdf', 'PDF Document'),
    (b'\x7fELF', '.elf', 'ELF Executable'),
    (b'MZ', '.exe', 'Windows Executable'),
    (b'OggS', '.ogg', 'OGG Audio/Video'),
    (b'ID3', '.mp3', 'MP3 Audio'),
    (b'\x00\x00\x01\xba', '.mpg', 'MPEG Video'),
    (b'\x00\x00\x01\xb3', '.mpg', 'MPEG Video'),
    (b'RIFF', '.wav', 'RIFF Container (WAV/AVI/WEBP)'),
    (b'\x1f\x8b\x08', '.tar.gz', 'GZIP Compressed Archive'),
    (b'BZh', '.bz2', 'BZIP2 Compressed Archive'),
]

discovered_flags = []

def log_flag(flag, source):
    entry = {'flag': flag, 'source': source}
    if entry not in discovered_flags:
        discovered_flags.append(entry)
        print(f"  {Colors.BOLD}{Colors.GREEN}🚩 FOUND FLAG:{Colors.RESET} {Colors.CYAN}{flag}{Colors.RESET}")
        print(f"     {Colors.YELLOW}Source:{Colors.RESET} {source}\n")

def check_flags_in_text(text, source_name):
    if not text:
        return
    matches = FLAG_REGEX.findall(text)
    for m in matches:
        log_flag(m, source_name)
    
    # Check Base64 candidates inside text
    for b64_match in B64_REGEX.findall(text):
        try:
            pad_match = b64_match + '=' * ((4 - len(b64_match) % 4) % 4)
            decoded = base64.b64decode(pad_match).decode('utf-8', errors='ignore')
            decoded_flags = FLAG_REGEX.findall(decoded)
            for df in decoded_flags:
                log_flag(df, f"Base64 Decoded ({b64_match}) in {source_name}")
        except Exception:
            pass

# ─── 1. FILE IDENTIFICATION & MAGIC BYTES ───────────────────────
def analyze_file_type(filepath):
    print(f"\n{Colors.BOLD}{Colors.BLUE}🔍 1. FILE IDENTIFICATION & MAGIC BYTES{Colors.RESET}")
    print("=" * 60)

    # 1. System file command
    file_cmd_output = ""
    mime_type = ""
    try:
        res = subprocess.run(['file', '-b', filepath], capture_output=True, text=True)
        file_cmd_output = res.stdout.strip()
        mime_res = subprocess.run(['file', '--mime-type', '-b', filepath], capture_output=True, text=True)
        mime_type = mime_res.stdout.strip()
    except Exception as e:
        file_cmd_output = f"Could not run 'file' command: {e}"

    print(f"  {Colors.BOLD}Path:{Colors.RESET} {filepath}")
    print(f"  {Colors.BOLD}File Command Output:{Colors.RESET} {Colors.GREEN}{file_cmd_output}{Colors.RESET}")
    if mime_type:
        print(f"  {Colors.BOLD}MIME Type:{Colors.RESET} {mime_type}")

    # 2. Magic byte check
    detected_type = "Unknown / Binary"
    suggested_ext = ""
    with open(filepath, 'rb') as f:
        header = f.read(32)
        for magic, ext, name in MAGIC_SIGNATURES:
            if header.startswith(magic):
                detected_type = name
                suggested_ext = ext
                break

    print(f"  {Colors.BOLD}Header Signature:{Colors.RESET} {header[:16].hex()} -> Detected: {Colors.CYAN}{detected_type}{Colors.RESET}")

    # 3. Check for fake / missing extension
    filename = os.path.basename(filepath)
    _, current_ext = os.path.splitext(filename)
    current_ext = current_ext.lower()

    if not current_ext:
        print(f"  {Colors.BOLD}{Colors.YELLOW}⚠️ WARNING:{Colors.RESET} File has no extension! Suggested extension: {Colors.BOLD}{suggested_ext or 'Unknown'}{Colors.RESET}")
    elif suggested_ext and current_ext != suggested_ext and not (current_ext in ['.jpeg', '.jpg'] and suggested_ext == '.jpg'):
        print(f"  {Colors.BOLD}{Colors.RED}🚨 FAKE EXTENSION DETECTED!{Colors.RESET}")
        print(f"     Filename extension is '{current_ext}' but magic bytes indicate {Colors.BOLD}{detected_type} ({suggested_ext}){Colors.RESET}")

# ─── 2. EXIF & METADATA ANALYSIS ─────────────────────────────────
def analyze_metadata(filepath):
    print(f"\n{Colors.BOLD}{Colors.BLUE}📸 2. METADATA & EXIF ANALYSIS{Colors.RESET}")
    print("=" * 60)

    metadata_found = False

    # Try exiftool CLI if available
    try:
        res = subprocess.run(['exiftool', filepath], capture_output=True, text=True)
        if res.returncode == 0 and res.stdout.strip():
            print(f"  {Colors.GREEN}[+] ExifTool Metadata Output:{Colors.RESET}\n")
            lines = res.stdout.strip().split('\n')
            for line in lines:
                print(f"    {line}")
                check_flags_in_text(line, "ExifTool Metadata")
            metadata_found = True
    except FileNotFoundError:
        print("  ℹ️ ExifTool CLI binary not found in PATH. Using Python fallbacks...")

    if not metadata_found:
        # Pillow EXIF Fallback
        try:
            with Image.open(filepath) as img:
                print(f"  {Colors.BOLD}Image Format:{Colors.RESET} {img.format}, Size: {img.size}, Mode: {img.mode}")
                
                # Check info dictionary (PNG text chunks, JPEG comments, etc.)
                if img.info:
                    print(f"  {Colors.GREEN}[+] Image Info Dictionary Attributes:{Colors.RESET}")
                    for k, v in img.info.items():
                        val_str = str(v)
                        print(f"    • {k}: {val_str}")
                        check_flags_in_text(f"{k}: {val_str}", "Image Info Metadata")

                # Check EXIF data
                exif_data = img._getexif() if hasattr(img, '_getexif') else None
                if exif_data:
                    print(f"\n  {Colors.GREEN}[+] EXIF Tag Data:{Colors.RESET}")
                    for tag_id, value in exif_data.items():
                        tag = ExifTags.TAGS.get(tag_id, tag_id)
                        val_str = str(value)
                        print(f"    • {tag} ({tag_id}): {val_str}")
                        check_flags_in_text(f"{tag}: {val_str}", "EXIF Metadata Tag")
        except Exception:
            pass

        # Check Zipfile comments if file is ZIP / Office document
        try:
            if zipfile.is_zipfile(filepath):
                with zipfile.ZipFile(filepath, 'r') as zf:
                    if zf.comment:
                        comm = zf.comment.decode('utf-8', errors='ignore')
                        print(f"  {Colors.GREEN}[+] ZIP File Comment:{Colors.RESET} {comm}")
                        check_flags_in_text(comm, "ZIP File Comment")
                    
                    print(f"  {Colors.GREEN}[+] Archive File Manifest ({len(zf.namelist())} files):{Colors.RESET}")
                    for name in zf.namelist():
                        print(f"    • {name}")
                        check_flags_in_text(name, "Zip Entry Filename")
        except Exception:
            pass

# ─── 3. STRINGS & ENCODED TEXT ANALYSIS ─────────────────────────
def analyze_strings(filepath, min_length=4, verbose=False):
    print(f"\n{Colors.BOLD}{Colors.BLUE}🔤 3. STRINGS & ENCODED TEXT ANALYSIS{Colors.RESET}")
    print("=" * 60)

    extracted_strings = []

    # Run system 'strings' tool if available
    try:
        res = subprocess.run(['strings', '-n', str(min_length), filepath], capture_output=True, text=True, errors='ignore')
        if res.returncode == 0:
            extracted_strings = res.stdout.splitlines()
    except FileNotFoundError:
        # Fallback python strings extraction
        with open(filepath, 'rb') as f:
            content = f.read()
            pattern = re.compile(rb'[^\x00-\x1F\x7F-\xFF]{' + str(min_length).encode() + rb',}')
            extracted_strings = [m.decode('ascii', errors='ignore') for m in pattern.findall(content)]

    print(f"  {Colors.BOLD}Extracted Printable Strings:{Colors.RESET} {len(extracted_strings)} total strings found.")

    # Scan strings for flags and base64 payloads
    for s in extracted_strings:
        check_flags_in_text(s, "Strings Dump")

    if verbose:
        print(f"\n  {Colors.YELLOW}[Verbose] Sample Strings Output (First 50 lines):{Colors.RESET}")
        for s in extracted_strings[:50]:
            print(f"    {s}")

# ─── 4. EMBEDDED FILES & TRAILING PAYLOAD DETECTION ─────────────
def analyze_embedded_data(filepath, extract=False):
    print(f"\n{Colors.BOLD}{Colors.BLUE}📦 4. EMBEDDED FILES & TRAILING PAYLOAD ANALYSIS{Colors.RESET}")
    print("=" * 60)

    with open(filepath, 'rb') as f:
        data = f.read()

    file_len = len(data)
    trailing_offset = None
    trailing_type = ""

    # Check PNG IEND chunk
    iend_pos = data.find(b'IEND\xae\x42\x60\x82')
    if iend_pos != -1:
        end_of_png = iend_pos + 8
        if end_of_png < file_len:
            trailing_offset = end_of_png
            trailing_type = "PNG Image (After IEND chunk)"

    # Check JPEG EOI marker (\xFF\xD9)
    if trailing_offset is None and data.startswith(b'\xff\xd8'):
        eoi_pos = data.rfind(b'\xff\xd9')
        if eoi_pos != -1 and eoi_pos + 2 < file_len:
            trailing_offset = eoi_pos + 2
            trailing_type = "JPEG Image (After EOI marker)"

    if trailing_offset:
        extra_bytes = file_len - trailing_offset
        print(f"  {Colors.BOLD}{Colors.RED}🚨 HIDDEN TRAILING DATA DETECTED!{Colors.RESET}")
        print(f"     Container: {trailing_type}")
        print(f"     Trailing Data Offset: {hex(trailing_offset)} ({trailing_offset} bytes)")
        print(f"     Appended Payload Size: {extra_bytes} bytes")

        trailing_data = data[trailing_offset:]
        check_flags_in_text(trailing_data.decode('utf-8', errors='ignore'), "Appended Trailing Payload")

        if extract:
            output_dir = os.path.join(os.path.dirname(filepath), "extracted")
            os.makedirs(output_dir, exist_ok=True)
            out_file = os.path.join(output_dir, f"appended_payload_{os.path.basename(filepath)}.bin")
            with open(out_file, 'wb') as out_f:
                out_f.write(trailing_data)
            print(f"  {Colors.GREEN}✅ Extracted trailing payload saved to: {out_file}{Colors.RESET}")
    else:
        print("  ✅ No unexpected trailing data appended after image/file end markers.")

    # Search for embedded PK (ZIP) archives inside binary data
    pk_positions = [m.start() for m in re.finditer(b'PK\x03\x04', data)]
    if len(pk_positions) > 0:
        first_pk = pk_positions[0]
        if first_pk > 0:
            print(f"  {Colors.BOLD}{Colors.YELLOW}⚠️ EMBEDDED ZIP ARCHIVE DETECTED!{Colors.RESET}")
            print(f"     ZIP header found at offset {hex(first_pk)} ({first_pk} bytes into file)")
            if extract:
                output_dir = os.path.join(os.path.dirname(filepath), "extracted")
                os.makedirs(output_dir, exist_ok=True)
                zip_out = os.path.join(output_dir, f"embedded_{os.path.basename(filepath)}.zip")
                with open(zip_out, 'wb') as zout:
                    zout.write(data[first_pk:])
                print(f"  {Colors.GREEN}✅ Extracted embedded ZIP saved to: {zip_out}{Colors.RESET}")

# ─── MAIN DRIVER ─────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="CTF Forensics & Mystery File Analyzer Tool")
    parser.add_argument("filepath", help="Path to the target mystery file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print verbose string output")
    parser.add_argument("-e", "--extract", action="store_true", help="Extract embedded archives or trailing data payloads")
    parser.add_argument("-s", "--min-len", type=int, default=4, help="Minimum string length for strings scan (default: 4)")

    args = parser.parse_args()

    if not os.path.exists(args.filepath):
        print(f"{Colors.RED}❌ Error: File '{args.filepath}' does not exist.{Colors.RESET}")
        sys.exit(1)

    print(f"\n{Colors.BOLD}{Colors.HEADER}============================================================{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.HEADER} 🕵️  CTF FORENSICS & MYSTERY FILE ANALYZER{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.HEADER}============================================================{Colors.RESET}")

    analyze_file_type(args.filepath)
    analyze_metadata(args.filepath)
    analyze_strings(args.filepath, min_length=args.min_len, verbose=args.verbose)
    analyze_embedded_data(args.filepath, extract=args.extract)

    print(f"\n{Colors.BOLD}{Colors.HEADER}============================================================{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.HEADER} 🏁 FORENSIC SCAN SUMMARY{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.HEADER}============================================================{Colors.RESET}\n")

    if not discovered_flags:
        print(f"  {Colors.YELLOW}❌ No explicit flags automatically captured.{Colors.RESET}")
        print("  💡 Tip: Check metadata attributes, strings, or extract trailing payloads above for passwords/hints.\n")
    else:
        print(f"  {Colors.GREEN}✅ Total Unique Flags Found: {len(discovered_flags)}{Colors.RESET}\n")
        for i, entry in enumerate(discovered_flags, 1):
            print(f"  [{i}] {Colors.BOLD}{Colors.CYAN}{entry['flag']}{Colors.RESET}")
            print(f"      → Source: {entry['source']}\n")

if __name__ == "__main__":
    main()
