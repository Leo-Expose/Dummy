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
import shutil
import struct
import subprocess
import tempfile
import numpy as np
from PIL import Image, ImageFile

Image.MAX_IMAGE_PIXELS = 50_000_000
ImageFile.LOAD_TRUNCATED_IMAGES = False
MAX_FILE_BYTES = 200 * 1024 * 1024
MAX_CARVE_BYTES = 50 * 1024 * 1024
MAX_EXTERNAL_OUTPUT = 200 * 1024  # 200KB cap on external tool stdout
EXTERNAL_TIMEOUT = 60

# Overpowered password list for steghide (early-round speedrun)
STEGHIDE_PASSWORDS = [
    '', 'password', '123456', 'ctf', 'flag', 'secret', 'admin', 'kju', 'KJU',
    'password123', '1234', '0000', 'qwerty', 'letmein', 'welcome', 'pass',
    'guest', 'ctf123', 'flag123', 'kju123',
]

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

# Flag patterns: strict by default, --loose for any prefix
STRICT_PREFIXES = r'(?:flag|ctf|picoCTF|HTB|THM|kju|CHTB|SEKAI|UIUCTF|PatriotCTF)'
STRICT_FLAG_REGEX = re.compile(STRICT_PREFIXES + r'\{[^}\r\n]{1,200}\}', re.IGNORECASE)
LOOSE_FLAG_REGEX = re.compile(r'[A-Za-z0-9_\-]{3,25}\{[A-Za-z0-9_\-!@#$%^&*()+=~`|:;\"\'<>,.?/\\ \[\]]{1,200}\}')
FLAG_REGEX = STRICT_FLAG_REGEX
B64_REGEX = re.compile(r'[A-Za-z0-9+/]{16,}={0,2}')

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
    (b'SQLite format 3\x00', 'SQLite Database', '.db'),
    (b'\xd4\xc3\xb2\xa1', 'PCAP Capture', '.pcap'),
    (b'\x0a\x0d\x0d\x0a', 'PCAP-NG Capture', '.pcapng'),
]

discovered_flags = []

def log_flag(flag, source):
    if any(e['flag'] == flag for e in discovered_flags):
        return
    entry = {'flag': flag, 'source': source}
    discovered_flags.append(entry)
    print(f"  {Colors.BOLD}{Colors.GREEN}🚩 FOUND FLAG:{Colors.RESET} {Colors.CYAN}{flag}{Colors.RESET}")
    print(f"     {Colors.YELLOW}Source:{Colors.RESET} {source}\n")

def _is_valid_b64(s):
    try:
        if len(s) < 16 or len(s) % 4 == 1:
            return False
        dec = base64.b64decode(s, validate=True)
        return base64.b64encode(dec).decode().rstrip('=') == s.rstrip('=')
    except Exception:
        return False

def scan_text_for_flags(text, source_tag):
    if not text:
        return
    for f in FLAG_REGEX.findall(text):
        log_flag(f, source_tag)

    for b64 in B64_REGEX.findall(text):
        try:
            if not _is_valid_b64(b64):
                continue
            decoded = base64.b64decode(b64).decode('utf-8', errors='ignore')
            if not re.search(r'[\x20-\x7E]{4,}', decoded):
                continue
            for df in FLAG_REGEX.findall(decoded):
                log_flag(df, f"Base64 Decoded ({b64[:16]}...) in {source_tag}")
        except Exception:
            pass

# ─── 1. ZSTEG / LSB STEGANOGRAPHY ENGINE ───────────────────────────
def _bits_to_bytes(vals, bit_depth, lsb_first=False):
    """Convert array of d-bit values to bytes. Tries both MSB-first and LSB-first byte orders."""
    vals = np.asarray(vals, dtype=np.uint8).ravel()
    # Build bitstream MSB-first within each value
    shifts = list(range(bit_depth - 1, -1, -1))
    bits = np.concatenate([((vals >> s) & 1).astype(np.uint8) for s in shifts]) if len(vals) else np.array([], dtype=np.uint8)
    # Trim to whole bytes
    nbytes = len(bits) // 8
    if nbytes == 0:
        return b''
    bits = bits[:nbytes * 8].reshape(nbytes, 8)
    if lsb_first:
        bits = bits[:, ::-1]  # reverse bit order within each byte
    packed = np.packbits(bits, axis=1).tobytes()
    # np.packbits on 2D packs along axis=1 -> one byte per row
    if isinstance(packed, bytes):
        # packbits(axis=1) returns shape (nbytes,1); flatten
        arr = np.frombuffer(packed, dtype=np.uint8)
        return arr.tobytes()
    return bytes(packed)

def analyze_lsb_stego(filepath, verbose=False):
    print(f"\n{Colors.BOLD}{Colors.BLUE}🎨 1. LSB (LEAST SIGNIFICANT BIT) STEGANOGRAPHY SCAN (zsteg){Colors.RESET}")
    print("=" * 65)

    try:
        with Image.open(filepath) as _probe:
            _probe.load()
            img_format = _probe.format
            img = _probe.convert('RGBA')
            arr = np.array(img)
    except Exception as e:
        print(f"  ℹ️ File is not a valid image or cannot be opened by PIL ({e}). Skipping LSB scan.\n")
        return

    height, width, channels = arr.shape
    total_px = width * height
    if total_px * channels > 100_000_000:
        print(f"  ⚠️ Large image ({width}x{height}), scanning first 25M pixels for speed.")
        arr = arr[: min(height, 5000), : min(width, 5000), :]
        height, width, channels = arr.shape
    print(f"  {Colors.BOLD}Image Format:{Colors.RESET} {img_format}, Dimensions: {width}x{height}, Mode: RGBA")

    channel_combos = [
        ('r', [0]), ('g', [1]), ('b', [2]), ('a', [3]),
        ('rgb', [0, 1, 2]), ('bgr', [2, 1, 0]),
        ('rgba', [0, 1, 2, 3]), ('abgr', [3, 2, 1, 0])
    ]

    bits_found_count = 0

    # Scan 1-bit, 2-bit, and 4-bit LSBs across channels, both byte orders
    for bit_depth in [1, 2, 4]:
        mask = (1 << bit_depth) - 1
        for name, ch_list in channel_combos:
            try:
                vals = np.concatenate([(arr[:, :, ch] & mask).ravel() for ch in ch_list])
                # Cap stream to ~4M values for speed (≈500KB decoded) — full for typical CTFs
                if len(vals) > 4_000_000:
                    vals = vals[:4_000_000]
                for order_name, lsb_first in (('msb', False), ('lsb', True)):
                    byte_data = _bits_to_bytes(vals, bit_depth, lsb_first=lsb_first)
                    if not byte_data:
                        continue
                    # Null-terminate at first 0x00 run like zsteg does for preview, but scan full
                    text = byte_data.decode('utf-8', errors='ignore')
                    combo_tag = f"LSB {bit_depth}-bit ({name},{order_name})"

                    # Check flags
                    flags_found = FLAG_REGEX.findall(text)
                    if flags_found:
                        bits_found_count += len(flags_found)
                        for f in flags_found:
                            log_flag(f, f"zsteg LSB Analysis -> {combo_tag}")

                    # Check Base64 candidates inside LSB (validated only)
                    for b64 in B64_REGEX.findall(text):
                        try:
                            if not _is_valid_b64(b64):
                                continue
                            decoded = base64.b64decode(b64).decode('utf-8', errors='ignore')
                            for df in FLAG_REGEX.findall(decoded):
                                bits_found_count += 1
                                log_flag(df, f"Base64 in zsteg LSB Analysis -> {combo_tag}")
                        except Exception:
                            pass

                    if verbose:
                        printable = ''.join([c if 32 <= ord(c) <= 126 else '.' for c in text[:60]])
                        print(f"  [{combo_tag:<22}] -> {printable}")

            except Exception:
                pass

    if bits_found_count == 0:
        print(f"  {Colors.GREEN}✓ LSB Scan complete. No immediate flags detected in standard LSB planes.{Colors.RESET}")

# ─── 2. BINWALK / EMBEDDED FILE CARVING ENGINE ─────────────────────
def analyze_binwalk_embedded(filepath, extract=False):
    print(f"\n{Colors.BOLD}{Colors.BLUE}📦 2. BINWALK & EMBEDDED FILE CARVING SCAN{Colors.RESET}")
    print("=" * 65)

    with open(filepath, 'rb') as f:
        data = f.read(MAX_FILE_BYTES)

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

        # Auto Extract / Carve if requested (capped)
        if extract and not is_primary:
            out_dir = os.path.join(os.path.dirname(os.path.abspath(filepath)), "extracted_stego")
            os.makedirs(out_dir, exist_ok=True)
            carved_filename = f"carved_at_{hex(offset)}_{idx}{ext}"
            carved_path = os.path.join(out_dir, carved_filename)

            with open(carved_path, 'wb') as carved_file:
                carved_file.write(data[offset:offset + MAX_CARVE_BYTES])
            print(f"     {Colors.GREEN}↳ Carved & saved to: {carved_path}{Colors.RESET}")

# ─── 3. PNG CHUNK STRUCTURE INSPECTION ──────────────────────────────
def analyze_png_chunks(filepath):
    print(f"\n{Colors.BOLD}{Colors.BLUE}🖼️ 3. PNG CHUNK STRUCTURE INSPECTOR{Colors.RESET}")
    print("=" * 65)

    with open(filepath, 'rb') as f:
        data = f.read(MAX_FILE_BYTES)

    if not data.startswith(b'\x89PNG\r\n\x1a\n'):
        print("  ℹ️ Not a PNG file. Skipping PNG chunk inspection.\n")
        return

    offset = 8
    standard_chunks = {'IHDR', 'PLTE', 'IDAT', 'IEND', 'tRNS', 'cHRM', 'gAMA', 'iCCP', 'sBIT', 'sRGB',
                       'tEXt', 'zTXt', 'iTXt', 'bKGD', 'hIST', 'pHYs', 'tIME', 'eXIf', 'sCAL', 'sPLT', 'acTL', 'fcTL', 'fdAT'}

    print(f"  {'CHUNK':<10} {'OFFSET':<12} {'LENGTH':<10} {'STATUS':<20}")
    print(f"  {'-'*10} {'-'*12} {'-'*10} {'-'*20}")

    import binascii
    while offset < len(data):
        if offset + 8 > len(data):
            print(f"  ⚠️ Truncated chunk header at {hex(offset)}, stopping.")
            break
        try:
            length = struct.unpack('>I', data[offset:offset+4])[0]
        except struct.error:
            print(f"  ⚠️ Corrupt chunk length at {hex(offset)}, stopping.")
            break
        if length > len(data):
            print(f"  ⚠️ Absurd chunk length {length} at {hex(offset)}, stopping.")
            break
        if offset + 12 + length > len(data):
            print(f"  ⚠️ Truncated chunk data at {hex(offset)} (need {length}B), stopping.")
            break
        try:
            chunk_type = data[offset+4:offset+8].decode('ascii')
        except Exception:
            print(f"  ⚠️ Non-ASCII chunk type at {hex(offset)}, stopping.")
            break
        if not re.fullmatch(r'[A-Za-z]{4}', chunk_type):
            print(f"  ⚠️ Invalid chunk type {chunk_type!r} at {hex(offset)}, stopping.")
            break

        status = "Standard" if chunk_type in standard_chunks else f"{Colors.RED}NON-STANDARD / CUSTOM{Colors.RESET}"
        print(f"  {chunk_type:<10} {hex(offset):<12} {length:<10} {status:<20}")

        chunk_data = data[offset+8:offset+8+length]
        # CRC check (warn only, don't abort — CTFs sometimes break CRC)
        stored_crc = struct.unpack('>I', data[offset+8+length:offset+12+length])[0]
        calc_crc = binascii.crc32(data[offset+4:offset+8+length]) & 0xffffffff
        if stored_crc != calc_crc:
            print(f"     {Colors.YELLOW}⚠️ CRC mismatch (stored {stored_crc:08x} vs calc {calc_crc:08x}){Colors.RESET}")
        scan_text_for_flags(chunk_data.decode('utf-8', errors='ignore'), f"PNG Chunk [{chunk_type}] at {hex(offset)}")

        offset += 12 + length  # Length (4) + Type (4) + Data (N) + CRC (4)

        if chunk_type == 'IEND':
            break

    if offset < len(data):
        trailing_bytes = len(data) - offset
        print(f"\n  {Colors.BOLD}{Colors.RED}🚨 TRAILING DATA AFTER IEND CHUNK!{Colors.RESET} ({trailing_bytes} bytes at offset {hex(offset)})")
        scan_text_for_flags(data[offset:offset + MAX_CARVE_BYTES].decode('utf-8', errors='ignore'), "PNG Trailing Bytes")

# ─── 4. EXTERNAL OVERPOWERED HOOKS (zsteg + steghide, if installed) ─
def _run_external(cmd, timeout=EXTERNAL_TIMEOUT):
    """Run an external binary, return stdout+stderr truncated to cap. Never raises."""
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = (res.stdout or '') + (res.stderr or '')
        if len(out) > MAX_EXTERNAL_OUTPUT:
            out = out[:MAX_EXTERNAL_OUTPUT] + f"\n...[truncated {len(out)}B to {MAX_EXTERNAL_OUTPUT}B]"
        return out
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except FileNotFoundError:
        return "[TOOL NOT FOUND]"
    except Exception as e:
        return f"[ERROR: {e}]"

def _is_png_or_bmp(filepath):
    try:
        with open(filepath, 'rb') as f:
            head = f.read(16)
        return head.startswith(b'\x89PNG\r\n\x1a\n') or head.startswith(b'BM') or \
            filepath.lower().endswith(('.png', '.bmp'))
    except Exception:
        return False

def analyze_external_zsteg(filepath):
    print(f"\n{Colors.BOLD}{Colors.BLUE}⚡ 4. EXTERNAL ZSTEG PASSTHROUGH (overpowered){Colors.RESET}")
    print("=" * 65)
    if not shutil.which('zsteg'):
        print("  ℹ️ zsteg binary not found — skipping (gem install zsteg for extra coverage). Native LSB scan above already ran.")
        return
    if not _is_png_or_bmp(filepath):
        print("  ℹ️ Not PNG/BMP — skipping external zsteg.")
        return
    # --all covers every detector zsteg ships (b1-b8, rgb, rgba, prime, interlace, palette)
    out = _run_external(['zsteg', '--all', filepath])
    if out in ("[TIMEOUT]", "[TOOL NOT FOUND]") or not out.strip():
        print(f"  ⚠️ zsteg produced no output ({out.strip()}).")
        return
    print(f"  {Colors.BOLD}zsteg --all output (capped):{Colors.RESET}")
    for line in out.strip().splitlines()[:40]:
        print(f"    {line[:300]}")
    if len(out.strip().splitlines()) > 40:
        print(f"    ... ({len(out.strip().splitlines())} lines total, capped display)")
    scan_text_for_flags(out, "external zsteg --all")

def analyze_steghide(filepath):
    print(f"\n{Colors.BOLD}{Colors.BLUE}🕵️ 5. STEGHIDE EXTRACTOR (overpowered){Colors.RESET}")
    print("=" * 65)
    if not shutil.which('steghide'):
        print("  ℹ️ steghide binary not found — skipping (apt install steghide for JPG/WAV coverage).")
        return
    if not filepath.lower().endswith(('.jpg', '.jpeg', '.bmp', '.wav', '.au')):
        print("  ℹ️ steghide supports JPG/BMP/WAV/AU only — skipping.")
        return
    cracked = False
    with tempfile.TemporaryDirectory(prefix='ctf_steghide_') as tmpdir:
        for pwd in STEGHIDE_PASSWORDS:
            out_path = os.path.join(tmpdir, 'extracted.bin')
            if os.path.exists(out_path):
                os.remove(out_path)
            out = _run_external(['steghide', 'extract', '-sf', filepath, '-p', pwd,
                                 '-xf', out_path, '-f'], timeout=30)
            if 'wrote extracted data' in out.lower() and os.path.exists(out_path):
                print(f"  {Colors.GREEN}✅ steghide password found: '{pwd or '(empty)'}'{Colors.RESET}")
                try:
                    size = os.path.getsize(out_path)
                    if size > MAX_CARVE_BYTES:
                        print(f"  ⚠️ Extracted payload {size}B exceeds cap, scanning first {MAX_CARVE_BYTES}B.")
                    with open(out_path, 'rb') as f:
                        payload = f.read(MAX_CARVE_BYTES).decode('utf-8', errors='ignore')
                    scan_text_for_flags(payload, f"steghide payload (password='{pwd or '(empty)'}')")
                    if not FLAG_REGEX.search(payload):
                        print(f"     Payload preview (200 chars): {payload[:200]!r}")
                except Exception as e:
                    print(f"  ⚠️ Could not read extracted payload: {e}")
                cracked = True
                break  # one payload per file; stop for speed
        if not cracked:
            print("  ✓ steghide trial complete — no password yielded a payload.")

# ─── MAIN DRIVER ─────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="CTF Steganography & Embedded Payload Analysis Tool (zsteg + binwalk)")
    parser.add_argument("filepath", help="Path to target image or mystery file")
    parser.add_argument("-e", "--extract", action="store_true", help="Automatically carve embedded files and extract payloads")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print verbose LSB bitstream analysis")
    parser.add_argument("--lsb-only", action="store_true", help="Run only LSB stego scan (zsteg mode)")
    parser.add_argument("--carve-only", action="store_true", help="Run only embedded carving scan (binwalk mode)")
    parser.add_argument("--loose", action="store_true", help="Loose flag matching (any prefix{...}); default is strict known-prefix matching")
    parser.add_argument("--force", action="store_true", help="Process files larger than safety cap")
    parser.add_argument("--no-external", action="store_true", help="Skip external zsteg/steghide hooks (pure-Python only)")
    parser.add_argument("--steghide-only", action="store_true", help="Run only the steghide extractor")

    args = parser.parse_args()
    global FLAG_REGEX
    if args.loose:
        FLAG_REGEX = LOOSE_FLAG_REGEX

    if not os.path.exists(args.filepath):
        print(f"{Colors.RED}❌ Error: File '{args.filepath}' does not exist.{Colors.RESET}")
        sys.exit(1)
    if not args.force and os.path.getsize(args.filepath) > MAX_FILE_BYTES:
        print(f"{Colors.RED}❌ File exceeds {MAX_FILE_BYTES}B safety cap. Re-run with --force.{Colors.RESET}")
        sys.exit(1)

    print(f"\n{Colors.BOLD}{Colors.HEADER}============================================================={Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.HEADER} 🕵️  CTF STEGANOGRAPHY & EMBEDDED FILE ANALYZER (zsteg/binwalk){Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.HEADER}============================================================={Colors.RESET}")

    if args.steghide_only:
        analyze_steghide(args.filepath)
    else:
        if not args.carve_only:
            analyze_lsb_stego(args.filepath, verbose=args.verbose)
            analyze_png_chunks(args.filepath)
            if not args.no_external:
                analyze_external_zsteg(args.filepath)

        if not args.lsb_only:
            analyze_binwalk_embedded(args.filepath, extract=args.extract)

        if not args.no_external:
            analyze_steghide(args.filepath)

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
