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
import hashlib
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

# ─── Flag patterns: strict by default (low FP for early rounds) ──
# Strict: known CTF prefixes only. Loose: any prefix (opt-in via --loose).
STRICT_PREFIXES = r'(?:flag|ctf|picoCTF|HTB|THM|kju|CHTB|SEKAI|UIUCTF|PatriotCTF)'
STRICT_FLAG_REGEX = re.compile(STRICT_PREFIXES + r'\{[^}\r\n]{1,200}\}', re.IGNORECASE)
LOOSE_FLAG_REGEX = re.compile(r'[A-Za-z0-9_\-]{3,25}\{[A-Za-z0-9_\-!@#$%^&*()+=~`|:;\"\'<>,.?/\\ \[\]]{1,200}\}')
# Active pattern selected at runtime (default strict)
FLAG_REGEX = STRICT_FLAG_REGEX
UUID_REGEX = re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b')
HEX_RUN_REGEX = re.compile(r'(?:[0-9a-fA-F]{2}[\s:]?){8,}')

# Safety caps (zip-bomb / disk-fill protection)
MAX_RECURSION_DEPTH = 3
MAX_TOTAL_BYTES = 200 * 1024 * 1024  # 200MB total unpacked
MAX_SINGLE_FILE = 50 * 1024 * 1024   # 50MB per file
MAX_COMPRESSION_RATIO = 100          # skip if ratio exceeds this
MAX_INPUT_READ = 20 * 1024 * 1024    # 20MB cap for decode-only strings/files scanned as text
_bytes_written = [0]  # mutable counter shared across recursion
_seen_hashes = set()

# Common CTF passwords for quick trial
COMMON_PASSWORDS = [
    '', 'password', 'admin', '123456', 'root', 'flag', 'ctf', 'secret',
    'pass', 'guest', 'welcome', 'master', '12345678', 'password123'
]

discovered_flags = []

def log_flag(flag, source):
    if any(e['flag'] == flag for e in discovered_flags):
        return
    entry = {'flag': flag, 'source': source}
    discovered_flags.append(entry)
    print(f"  {Colors.BOLD}{Colors.GREEN}🚩 FOUND FLAG:{Colors.RESET} {Colors.CYAN}{flag}{Colors.RESET}")
    print(f"     {Colors.YELLOW}Source:{Colors.RESET} {source}\n")

def log_hint(hint, source):
    print(f"  {Colors.YELLOW}💡 HINT ({source}):{Colors.RESET} {hint}")

def scan_text(text, source):
    if not text:
        return
    for f in FLAG_REGEX.findall(text):
        log_flag(f, source)
    # Hashes/UUIDs are hints, not flags (avoids FP noise in strict mode)
    for h in UUID_REGEX.findall(text):
        log_hint(h, source + " [uuid]")

# ─── 1. DECODING & CIPHER ENGINE ─────────────────────────────────
def _pad_b64(s):
    return s + '=' * ((-len(s)) % 4)

def _valid_b64_roundtrip(s):
    """Require canonical base64 to kill false positives on English words."""
    try:
        s = re.sub(r'\s+', '', s)
        if len(s) < 8 or len(s) % 4 == 1:
            return False
        dec = base64.b64decode(_pad_b64(s), validate=True)
        # re-encode must match (ignoring padding)
        return base64.b64encode(dec).decode().rstrip('=') == s.rstrip('=')
    except Exception:
        return False

B64_TOKEN_REGEX = re.compile(r'[A-Za-z0-9+/]{8,}={0,2}')

def _caesar_shifts(s):
    out = []
    for shift in range(1, 26):
        t = ''.join(
            chr((ord(c) - 65 + shift) % 26 + 65) if 'A' <= c <= 'Z'
            else chr((ord(c) - 97 + shift) % 26 + 97) if 'a' <= c <= 'z'
            else c for c in s)
        out.append((shift, t))
    return out

def _xor_bruteforce(data_bytes):
    """Single-byte XOR brute force; yields (key, decoded_str) for printable candidates."""
    results = []
    for key in range(1, 256):
        dec = bytes(b ^ key for b in data_bytes)
        try:
            txt = dec.decode('utf-8')
        except Exception:
            continue
        if not txt:
            continue
        printable = sum(32 <= ord(c) <= 126 or c in '\n\r\t' for c in txt) / max(len(txt), 1)
        if printable > 0.85 and len(txt) >= 4:
            results.append((key, txt))
    return results

def decode_payload(data_str, depth=0, max_depth=5, _visited=None):
    if depth > max_depth or not data_str:
        return
    if _visited is None:
        _visited = set()
    data_str = data_str.strip()
    if len(data_str) > MAX_INPUT_READ:
        data_str = data_str[:MAX_INPUT_READ]
    h = hashlib.sha256(data_str.encode('utf-8', errors='ignore')).hexdigest()
    if h in _visited:
        return
    _visited.add(h)
    scan_text(data_str, f"Decoder (Depth {depth})")

    # 1. Base64 Decoding (whole string, with round-trip validation)
    try:
        s = re.sub(r'\s+', '', data_str)
        if _valid_b64_roundtrip(s):
            b64_dec = base64.b64decode(_pad_b64(s)).decode('utf-8', errors='ignore')
            if b64_dec and b64_dec != data_str and re.search(r'[\x20-\x7E]{4,}', b64_dec):
                scan_text(b64_dec, f"Base64 Decoded (Depth {depth+1})")
                decode_payload(b64_dec, depth + 1, max_depth, _visited)
    except Exception:
        pass

    # 1b. Base64 tokens embedded in larger text ("answer is Zmxh... here")
    try:
        for tok in set(B64_TOKEN_REGEX.findall(data_str)):
            if not _valid_b64_roundtrip(tok):
                continue
            try:
                tdec = base64.b64decode(_pad_b64(tok)).decode('utf-8', errors='ignore')
            except Exception:
                continue
            if tdec and tdec != data_str and re.search(r'[\x20-\x7E]{4,}', tdec):
                scan_text(tdec, f"Base64 Token (Depth {depth+1})")
                decode_payload(tdec, depth + 1, max_depth, _visited)
    except Exception:
        pass

    # 2. Base32 Decoding (only if plausible alphabet/length)
    try:
        s = re.sub(r'\s+', '', data_str).upper()
        if len(s) >= 16 and len(s) % 8 == 0 and re.fullmatch(r'[A-Z2-7=]+', s):
            b32_dec = base64.b32decode(s).decode('utf-8', errors='ignore')
            if b32_dec and b32_dec != data_str:
                scan_text(b32_dec, f"Base32 Decoded (Depth {depth+1})")
                decode_payload(b32_dec, depth + 1, max_depth, _visited)
    except Exception:
        pass

    # 3. Base85 Decoding (conservative: min length + round-trip)
    try:
        s = data_str.strip()
        if 16 <= len(s) <= 10000:
            b85_dec = base64.b85decode(s).decode('utf-8', errors='ignore')
            if b85_dec and b85_dec != data_str and re.search(r'[\x20-\x7E]{4,}', b85_dec):
                # verify round-trip to avoid garbage positives
                if base64.b85encode(b85_dec.encode()).decode() == s:
                    scan_text(b85_dec, f"Base85 Decoded (Depth {depth+1})")
                    decode_payload(b85_dec, depth + 1, max_depth, _visited)
    except Exception:
        pass

    # 4. Hex Decoding (runs of hex pairs, not whole-string strip)
    try:
        for m in HEX_RUN_REGEX.findall(data_str):
            clean_hex = re.sub(r'[\s:]', '', m)
            if len(clean_hex) % 2 == 0 and 16 <= len(clean_hex) <= 10000:
                hex_dec = bytes.fromhex(clean_hex).decode('utf-8', errors='ignore')
                if hex_dec and hex_dec != data_str and re.search(r'[\x20-\x7E]{4,}', hex_dec):
                    scan_text(hex_dec, f"Hex Decoded (Depth {depth+1})")
                    decode_payload(hex_dec, depth + 1, max_depth, _visited)
    except Exception:
        pass

    # 5. Caesar / ROT13 (all 25 shifts; gated on STRICT to avoid loose-mode explosion)
    try:
        if re.search(r'[A-Za-z]{4,}', data_str) and len(data_str) <= 10000:
            if not STRICT_FLAG_REGEX.search(data_str):  # already a flag -> skip brute
                for shift, cand in _caesar_shifts(data_str):
                    if STRICT_FLAG_REGEX.search(cand):
                        scan_text(cand, f"Caesar-{shift} Decoded (Depth {depth+1})")
                        decode_payload(cand, depth + 1, max_depth, _visited)
    except Exception:
        pass

    # 6. URL Decoding (recurse)
    try:
        url_dec = urllib.parse.unquote(data_str)
        if url_dec and url_dec != data_str:
            scan_text(url_dec, f"URL Decoded (Depth {depth+1})")
            decode_payload(url_dec, depth + 1, max_depth, _visited)
    except Exception:
        pass

    # 7. Single-byte XOR (only at depth 0 to bound cost; gated on STRICT)
    try:
        if depth == 0 and 4 <= len(data_str) <= 10000:
            raw = data_str.encode('utf-8', errors='ignore')
            # skip if it already looks like plain flag
            if not STRICT_FLAG_REGEX.search(data_str):
                for key, txt in _xor_bruteforce(raw):
                    if STRICT_FLAG_REGEX.search(txt):
                        scan_text(txt, f"XOR-0x{key:02x} Decoded (Depth {depth+1})")
    except Exception:
        pass

# ─── 2. ZIP & ARCHIVE UNPACKING ENGINE ─────────────────────────────
def _is_within_directory(base, target):
    abs_base = os.path.abspath(base)
    abs_target = os.path.abspath(target)
    return os.path.commonpath([abs_base]) == os.path.commonpath([abs_base, abs_target])

def _safe_zip_extract(zf, path, pwd=None):
    """ZipSlip-safe extraction with per-file size caps. Returns list of written paths."""
    written = []
    for info in zf.infolist():
        name = info.filename
        if not name or name.endswith('/'):
            continue
        # Reject absolute paths / drive letters / traversal
        if os.path.isabs(name) or '..' in name.split('/') or ':' in name.split('/')[0]:
            print(f"  {Colors.YELLOW}⚠️ Skipped unsafe ZIP entry: {name}{Colors.RESET}")
            continue
        target = os.path.join(path, name)
        if not _is_within_directory(path, target):
            print(f"  {Colors.YELLOW}⚠️ Skipped ZipSlip entry: {name}{Colors.RESET}")
            continue
        if info.file_size > MAX_SINGLE_FILE:
            print(f"  {Colors.YELLOW}⚠️ Skipped oversized entry ({info.file_size}B): {name}{Colors.RESET}")
            continue
        if _bytes_written[0] + info.file_size > MAX_TOTAL_BYTES:
            print(f"  {Colors.RED}⛔ Total unpack cap reached, stopping.{Colors.RESET}")
            break
        try:
            os.makedirs(os.path.dirname(target) or path, exist_ok=True)
            with zf.open(info, pwd=pwd) as src, open(target, 'wb') as dst:
                remaining = info.file_size
                while remaining > 0:
                    chunk = src.read(min(65536, remaining))
                    if not chunk:
                        break
                    # compression-ratio guard
                    dst.write(chunk)
                    remaining -= len(chunk)
            _bytes_written[0] += os.path.getsize(target) if os.path.exists(target) else 0
            written.append(target)
        except RuntimeError:
            raise  # bad password -> caller tries next pwd
        except Exception as e:
            print(f"  {Colors.YELLOW}⚠️ Failed entry {name}: {e}{Colors.RESET}")
    return written

def _safe_tar_extract(tf, path):
    written = []
    for member in tf.getmembers():
        name = member.name
        if not name:
            continue
        if os.path.isabs(name) or '..' in name.split('/'):
            print(f"  {Colors.YELLOW}⚠️ Skipped unsafe TAR entry: {name}{Colors.RESET}")
            continue
        if member.issym() or member.islnk():
            print(f"  {Colors.YELLOW}⚠️ Skipped symlink entry: {name}{Colors.RESET}")
            continue
        if member.size > MAX_SINGLE_FILE:
            print(f"  {Colors.YELLOW}⚠️ Skipped oversized entry ({member.size}B): {name}{Colors.RESET}")
            continue
        if _bytes_written[0] + member.size > MAX_TOTAL_BYTES:
            print(f"  {Colors.RED}⛔ Total unpack cap reached, stopping.{Colors.RESET}")
            break
        target = os.path.join(path, name)
        if not _is_within_directory(path, target):
            print(f"  {Colors.YELLOW}⚠️ Skipped TarSlip entry: {name}{Colors.RESET}")
            continue
        try:
            tf.extract(member, path=path, filter='data')
            _bytes_written[0] += member.size
            written.append(target)
        except TypeError:
            # Python <3.12 without filter=; fall back after checks above
            try:
                tf.extract(member, path=path)
                _bytes_written[0] += member.size
                written.append(target)
            except Exception as e:
                print(f"  {Colors.YELLOW}⚠️ Failed entry {name}: {e}{Colors.RESET}")
        except Exception as e:
            print(f"  {Colors.YELLOW}⚠️ Failed entry {name}: {e}{Colors.RESET}")
    return written

def unpack_archive(filepath, password=None, wordlist=None, output_dir=None, recursive=True, _depth=0):
    if _depth > MAX_RECURSION_DEPTH:
        print(f"  {Colors.YELLOW}⚠️ Max recursion depth reached, skipping.{Colors.RESET}")
        return
    # loop protection via content hash
    try:
        with open(filepath, 'rb') as _fh:
            _head = _fh.read(1 << 20)
            _digest = hashlib.sha256(_head).hexdigest()
            if _digest in _seen_hashes:
                print(f"  {Colors.YELLOW}↩ Already processed (loop guard), skipping: {os.path.basename(filepath)}{Colors.RESET}")
                return
            _seen_hashes.add(_digest)
    except Exception:
        pass
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

    # Harvest strings from target archive to use as candidate passwords (capped read)
    try:
        with open(filepath, 'rb') as f:
            content = f.read(2 << 20)  # first 2MB only
            found_candidates = [m.decode('ascii', errors='ignore') for m in re.findall(rb'[A-Za-z0-9_\-!@#$%^&*]{4,20}', content)]
            passwords_to_try.extend(found_candidates[:50])
    except Exception:
        pass

    # Unique candidate passwords list (cap wordlist size for speed)
    passwords_to_try = list(dict.fromkeys(passwords_to_try))[:5000]

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
                    # Password probe: try opening first file entry, then safe-extract
                    names = zf.namelist()
                    if names:
                        with zf.open(names[0], pwd=pwd_bytes) as _probe:
                            _probe.read(16)
                    extracted_files = _safe_zip_extract(zf, output_dir, pwd=pwd_bytes)
                    unlocked = True
                    used_pwd = pwd
                    break
                except RuntimeError:
                    continue
                except (zipfile.BadZipFile, NotImplementedError):
                    continue
                except Exception:
                    continue

            if unlocked:
                pwd_display = f"'{used_pwd}'" if used_pwd else "None (Unprotected)"
                print(f"  {Colors.GREEN}✅ Successfully unpacked! Password used: {pwd_display}{Colors.RESET}")
                for p in extracted_files:
                    rel = os.path.relpath(p, output_dir)
                    print(f"    • Extracted: {rel}")
                    scan_text(rel, "Archive Manifest Filename")
            else:
                print(f"  {Colors.RED}❌ Password required or invalid password dictionary trial.{Colors.RESET}")

    # 2. TAR Archive Handling (.tar, .tar.gz, .tar.bz2)
    elif tarfile.is_tarfile(filepath):
        print(f"  {Colors.BOLD}Type:{Colors.RESET} TAR Archive")
        try:
            with tarfile.open(filepath, 'r:*') as tf:
                extracted_files = _safe_tar_extract(tf, output_dir)
                print(f"  {Colors.GREEN}✅ Unpacked TAR archive ({len(extracted_files)} safe entries).{Colors.RESET}")
                for p in extracted_files:
                    rel = os.path.relpath(p, output_dir)
                    print(f"    • Extracted: {rel}")
                    scan_text(rel, "TAR Manifest Filename")
        except Exception as e:
            print(f"  {Colors.RED}❌ TAR extraction failed: {e}{Colors.RESET}")

    # 3. GZIP / BZIP2 Single File Compression (streamed, capped)
    elif filepath.endswith('.gz') or filepath.endswith('.bz2'):
        try:
            # ratio guard: compressed vs decompressed
            comp_size = os.path.getsize(filepath)
            out_name = os.path.basename(filepath).rsplit('.', 1)[0]
            if not _is_within_directory(output_dir, os.path.join(output_dir, out_name)):
                print(f"  {Colors.RED}❌ Unsafe output name, aborting.{Colors.RESET}")
                return
            out_path = os.path.join(output_dir, out_name)

            open_fn = gzip.open if filepath.endswith('.gz') else bz2.open
            total = 0
            with open_fn(filepath, 'rb') as f_in, open(out_path, 'wb') as f_out:
                while True:
                    chunk = f_in.read(65536)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_SINGLE_FILE or _bytes_written[0] + total > MAX_TOTAL_BYTES:
                        print(f"  {Colors.RED}⛔ Decompression cap hit, truncating.{Colors.RESET}")
                        break
                    if comp_size > 0 and total > comp_size * MAX_COMPRESSION_RATIO:
                        print(f"  {Colors.RED}⛔ Compression ratio exceeded (possible bomb), stopping.{Colors.RESET}")
                        break
                    f_out.write(chunk)

            _bytes_written[0] += total
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
                if os.path.getsize(ef) > MAX_INPUT_READ:
                    print(f"  {Colors.YELLOW}⏩ Skipping content scan (>{MAX_INPUT_READ}B): {os.path.basename(ef)}{Colors.RESET}")
                else:
                    with open(ef, 'r', errors='ignore') as f:
                        text_content = f.read(MAX_INPUT_READ)
                        scan_text(text_content, f"File: {os.path.basename(ef)}")
                        decode_payload(text_content)
            except Exception:
                pass

            # Recursive nested unpacking (depth-capped, loop-guarded)
            if recursive and (zipfile.is_zipfile(ef) or tarfile.is_tarfile(ef)) and ef != filepath:
                print(f"\n  {Colors.YELLOW}🔄 Recursive nested archive detected: {os.path.basename(ef)}{Colors.RESET}")
                unpack_archive(ef, password=password, wordlist=wordlist, output_dir=os.path.join(output_dir, f"nested_d{_depth+1}"), recursive=True, _depth=_depth + 1)

# ─── MAIN DRIVER ─────────────────────────────────────────────────
def main():
    global FLAG_REGEX, MAX_RECURSION_DEPTH
    parser = argparse.ArgumentParser(description="CTF Archiving, Unpacking & Encoding Decoder Tool (unpack)")
    parser.add_argument("target", help="Archive file OR string to decode")
    parser.add_argument("-p", "--password", help="Password for protected archives")
    parser.add_argument("-w", "--wordlist", help="Path to password dictionary wordlist")
    parser.add_argument("-o", "--output", help="Output directory for unpacked files (default: ./unpacked)")
    parser.add_argument("-d", "--decode-only", action="store_true", help="Treat target as cipher/encoded string instead of file")
    parser.add_argument("--loose", action="store_true", help="Loose flag matching (any prefix{...}); default is strict known-prefix matching")
    parser.add_argument("--max-depth", type=int, default=3, help="Max nested-archive depth (default 3)")

    args = parser.parse_args()
    if args.loose:
        FLAG_REGEX = LOOSE_FLAG_REGEX
    MAX_RECURSION_DEPTH = args.max_depth

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
