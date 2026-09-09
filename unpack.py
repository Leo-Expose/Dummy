#!/usr/bin/env python3
"""
CTF Archiving, Unpacking & Encoding Decoder Suite (unpack)
Unpacks ZIP/TAR/7z archives (including password-protected archives), handles multi-layer Base64/Base32/Base85/Hex decoding, ROT13, and extracts hidden flags.
"""

import sys
import os
import re
import base64
import binascii
import zipfile
import tarfile
import gzip
import bz2
import lzma
import urllib.parse
import argparse
import codecs

# ANSI Colors
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

FLAG_REGEX = re.compile(r'[A-Za-z0-9_\-]{1,25}\{[^}\s\r\n]+\}', re.IGNORECASE)
UUID_REGEX = re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b')

# Common CTF passwords for quick trial
COMMON_PASSWORDS = [
    '', 'password', 'admin', '123456', 'root', 'flag', 'ctf', 'secret',
    'pass', 'guest', 'welcome', 'master', '12345678', 'password123'
]

discovered_flags = []

def log_flag(flag, source):
    entry = {'flag': flag, 'source': source}
    if entry not in discovered_flags:
        discovered_flags.append(entry)
        print(f"  {Colors.BOLD}{Colors.GREEN}🚩 FOUND FLAG:{Colors.RESET} {Colors.CYAN}{flag}{Colors.RESET}")
        print(f"     {Colors.YELLOW}Source:{Colors.RESET} {source}\n")

def scan_text(text, source):
    if not text:
        return
    for f in FLAG_REGEX.findall(text):
        log_flag(f, source)

# ─── 1. DECODING & CIPHER ENGINE ─────────────────────────────────
def decode_payload(data_str, depth=0, max_depth=5):
    if depth > max_depth or not data_str:
        return

    data_str = data_str.strip()
    scan_text(data_str, f"Decoder (Depth {depth})")

    # 1. Base64 Decoding
    try:
        pad = data_str + '=' * ((4 - len(data_str) % 4) % 4)
        b64_dec = base64.b64decode(pad).decode('utf-8', errors='ignore')
        if b64_dec and b64_dec != data_str and re.search(r'[\x20-\x7E]{4,}', b64_dec):
            scan_text(b64_dec, f"Base64 Decoded (Depth {depth+1})")
            decode_payload(b64_dec, depth + 1, max_depth)
    except Exception:
        pass

    # 2. Base32 Decoding
    try:
        b32_dec = base64.b32decode(data_str.upper()).decode('utf-8', errors='ignore')
        if b32_dec and b32_dec != data_str:
            scan_text(b32_dec, f"Base32 Decoded (Depth {depth+1})")
            decode_payload(b32_dec, depth + 1, max_depth)
    except Exception:
        pass

    # 3. Base85 Decoding
    try:
        b85_dec = base64.b85decode(data_str).decode('utf-8', errors='ignore')
        if b85_dec and b85_dec != data_str:
            scan_text(b85_dec, f"Base85 Decoded (Depth {depth+1})")
            decode_payload(b85_dec, depth + 1, max_depth)
    except Exception:
        pass

    # 4. Hex Decoding
    try:
        clean_hex = re.sub(r'[^0-9a-fA-F]', '', data_str)
        if len(clean_hex) % 2 == 0 and len(clean_hex) >= 8:
            hex_dec = bytes.fromhex(clean_hex).decode('utf-8', errors='ignore')
            if hex_dec and hex_dec != data_str:
                scan_text(hex_dec, f"Hex Decoded (Depth {depth+1})")
                decode_payload(hex_dec, depth + 1, max_depth)
    except Exception:
        pass

    # 5. ROT13 Cipher
    try:
        rot13_dec = codecs.decode(data_str, 'rot_13')
        if rot13_dec and rot13_dec != data_str:
            scan_text(rot13_dec, f"ROT13 Decoded (Depth {depth+1})")
    except Exception:
        pass

    # 6. URL Decoding
    try:
        url_dec = urllib.parse.unquote(data_str)
        if url_dec and url_dec != data_str:
            scan_text(url_dec, f"URL Decoded (Depth {depth+1})")
    except Exception:
        pass

# ─── 2. ZIP & ARCHIVE UNPACKING ENGINE ─────────────────────────────
def unpack_archive(filepath, password=None, wordlist=None, output_dir=None, recursive=True):
    print(f"\n{Colors.BOLD}{Colors.BLUE}📦 UNPACKING ARCHIVE: {os.path.basename(filepath)}{Colors.RESET}")
    print("=" * 65)

    if not output_dir:
        output_dir = os.path.join(os.path.dirname(os.path.abspath(filepath)), "unpacked")
    os.makedirs(output_dir, exist_ok=True)

    passwords_to_try = list(COMMON_PASSWORDS)
    if password:
        passwords_to_try.insert(0, password)

    if wordlist and os.path.exists(wordlist):
        with open(wordlist, 'r', errors='ignore') as wf:
            passwords_to_try.extend([line.strip() for line in wf if line.strip()])

    # Harvest strings from target archive to use as candidate passwords
    try:
        with open(filepath, 'rb') as f:
            content = f.read()
            found_candidates = [m.decode('ascii', errors='ignore') for m in re.findall(rb'[A-Za-z0-9_\-!@#$%^&*]{4,20}', content)]
            passwords_to_try.extend(found_candidates[:50])
    except Exception:
        pass

    # Unique candidate passwords list
    passwords_to_try = list(dict.fromkeys(passwords_to_try))

    extracted_files = []

    # 1. ZIP Archive Handling
    if zipfile.is_zipfile(filepath):
        print(f"  {Colors.BOLD}Type:{Colors.RESET} ZIP Archive")
        unlocked = False
        used_pwd = None

        with zipfile.ZipFile(filepath, 'r') as zf:
            if zf.comment:
                comm = zf.comment.decode('utf-8', errors='ignore')
                print(f"  {Colors.GREEN}[+] Archive Comment:{Colors.RESET} {comm}")
                scan_text(comm, "ZIP Comment")
                decode_payload(comm)

            for pwd in passwords_to_try:
                try:
                    pwd_bytes = pwd.encode('utf-8') if pwd else None
                    zf.extractall(path=output_dir, pwd=pwd_bytes)
                    unlocked = True
                    used_pwd = pwd
                    break
                except (RuntimeError, zipfile.BadZipFile):
                    continue

            if unlocked:
                pwd_display = f"'{used_pwd}'" if used_pwd else "None (Unprotected)"
                print(f"  {Colors.GREEN}✅ Successfully unpacked! Password used: {pwd_display}{Colors.RESET}")
                for name in zf.namelist():
                    extracted_path = os.path.join(output_dir, name)
                    extracted_files.append(extracted_path)
                    print(f"    • Extracted: {name}")
                    scan_text(name, "Archive Manifest Filename")
            else:
                print(f"  {Colors.RED}❌ Password required or invalid password dictionary trial.{Colors.RESET}")

    # 2. TAR Archive Handling (.tar, .tar.gz, .tar.bz2)
    elif tarfile.is_tarfile(filepath):
        print(f"  {Colors.BOLD}Type:{Colors.RESET} TAR Archive")
        try:
            with tarfile.open(filepath, 'r:*') as tf:
                tf.extractall(path=output_dir)
                print(f"  {Colors.GREEN}✅ Successfully unpacked TAR archive.{Colors.RESET}")
                for member in tf.getmembers():
                    extracted_path = os.path.join(output_dir, member.name)
                    extracted_files.append(extracted_path)
                    print(f"    • Extracted: {member.name}")
                    scan_text(member.name, "TAR Manifest Filename")
        except Exception as e:
            print(f"  {Colors.RED}❌ TAR extraction failed: {e}{Colors.RESET}")

    # 3. GZIP / BZIP2 Single File Compression
    elif filepath.endswith('.gz') or filepath.endswith('.bz2'):
        try:
            out_name = os.path.basename(filepath).rsplit('.', 1)[0]
            out_path = os.path.join(output_dir, out_name)
            
            open_fn = gzip.open if filepath.endswith('.gz') else bz2.open
            with open_fn(filepath, 'rb') as f_in, open(out_path, 'wb') as f_out:
                f_out.write(f_in.read())

            extracted_files.append(out_path)
            print(f"  {Colors.GREEN}✅ Decompressed single archive to: {out_name}{Colors.RESET}")
        except Exception as e:
            print(f"  {Colors.RED}❌ Decompression failed: {e}{Colors.RESET}")

    else:
        print(f"  ℹ️ File '{filepath}' is not a standard ZIP or TAR archive.")

    # Process all extracted files for text, encodings, and nested archives
    for ef in extracted_files:
        if os.path.isfile(ef):
            try:
                with open(ef, 'r', errors='ignore') as f:
                    text_content = f.read()
                    scan_text(text_content, f"File: {os.path.basename(ef)}")
                    decode_payload(text_content)
            except Exception:
                pass

            # Recursive nested unpacking
            if recursive and (zipfile.is_zipfile(ef) or tarfile.is_tarfile(ef)) and ef != filepath:
                print(f"\n  {Colors.YELLOW}🔄 Recursive nested archive detected: {os.path.basename(ef)}{Colors.RESET}")
                unpack_archive(ef, password=password, wordlist=wordlist, output_dir=os.path.join(output_dir, "nested"), recursive=True)

# ─── MAIN DRIVER ─────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="CTF Archiving, Unpacking & Encoding Decoder Tool (unpack)")
    parser.add_argument("target", help="Archive file OR string to decode")
    parser.add_argument("-p", "--password", help="Password for protected archives")
    parser.add_argument("-w", "--wordlist", help="Path to password dictionary wordlist")
    parser.add_argument("-o", "--output", help="Output directory for unpacked files (default: ./unpacked)")
    parser.add_argument("-d", "--decode-only", action="store_true", help="Treat target as cipher/encoded string instead of file")

    args = parser.parse_args()

    print(f"\n{Colors.BOLD}{Colors.HEADER}============================================================={Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.HEADER} 📦  CTF UNPACKING & DECODING SUITE (unpack){Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.HEADER}============================================================={Colors.RESET}")

    if args.decode_only or not os.path.exists(args.target):
        print(f"\n{Colors.BOLD}{Colors.BLUE}🔤 ENCODING & CIPHER DECODER MODE{Colors.RESET}")
        print("=" * 65)
        print(f"  {Colors.BOLD}Target String:{Colors.RESET} {args.target}")
        scan_text(args.target, "Input String")
        decode_payload(args.target)
    else:
        unpack_archive(args.target, password=args.password, wordlist=args.wordlist, output_dir=args.output)

    print(f"\n{Colors.BOLD}{Colors.HEADER}============================================================={Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.HEADER} 🏁 UNPACKING & DECODING SUMMARY{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.HEADER}============================================================={Colors.RESET}\n")

    if not discovered_flags:
        print(f"  {Colors.YELLOW}❌ No explicit flags captured in unpacked output or string decodings.{Colors.RESET}\n")
    else:
        print(f"  {Colors.GREEN}✅ Total Unique Flags Captured: {len(discovered_flags)}{Colors.RESET}\n")
        for i, entry in enumerate(discovered_flags, 1):
            print(f"  [{i}] {Colors.BOLD}{Colors.CYAN}{entry['flag']}{Colors.RESET}")
            print(f"      → Source: {entry['source']}\n")

if __name__ == "__main__":
    main()
