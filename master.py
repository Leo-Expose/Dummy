import subprocess
import sys
import os
import re
import base64
import binascii

# ─── Flag Patterns ───────────────────────────────────────────
FLAG_PATTERNS = [
    r'FLAG\{[^}]+\}', r'flag\{[^}]+\}', r'Flag\{[^}]+\}',
    r'CTF\{[^}]+\}',  r'ctf\{[^}]+\}',  r'Ctf\{[^}]+\}',
    r'KJU\{[^}]+\}',  r'kju\{[^}]+\}',  r'Kju\{[^}]+\}',
    r'[A-Za-z0-9_]{2,10}\{[A-Za-z0-9_\-!@#$%^&*=+.?\/\\]+\}',
]
COMBINED = re.compile('|'.join(FLAG_PATTERNS))
BASE64_RE = re.compile(r'[A-Za-z0-9+/]{8,}={0,2}')

found_flags = []

# ─── Helpers ─────────────────────────────────────────────────
def header(title):
    print(f"\n{'─'*50}")
    print(f"  {title}")
    print(f"{'─'*50}")

def find_flags(text, source):
    matches = COMBINED.findall(text)
    for m in matches:
        if any(e['flag'] == m for e in found_flags):
            continue
        entry = {'flag': m, 'source': source}
        found_flags.append(entry)
        print(f"  🚩 FLAG FOUND: {m}")
        print(f"     Source    : {source}")

def _pad_b64(s):
    return s + '=' * ((-len(s)) % 4)

def _is_valid_b64(s):
    try:
        if len(s) < 8 or len(s) % 4 == 1:
            return False
        dec = base64.b64decode(_pad_b64(s), validate=True)
        return base64.b64encode(dec).decode().rstrip('=') == s.rstrip('=')
    except Exception:
        return False

def try_base64(text, source):
    for match in set(BASE64_RE.findall(text)):
        try:
            if not _is_valid_b64(match):
                continue
            cur, seen = match, {match}
            for _ in range(3):  # up to 3 nested layers
                decoded = base64.b64decode(_pad_b64(cur)).decode('utf-8', errors='ignore')
                if len(decoded) > 4 and decoded.isprintable():
                    find_flags(decoded, f"Base64 in {source}")
                nxt = None
                for cand in set(BASE64_RE.findall(decoded)):
                    if cand not in seen and _is_valid_b64(cand):
                        nxt = cand
                        break
                if nxt is None:
                    break
                seen.add(nxt)
                cur = nxt
        except:
            pass

def run_tool(cmd):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except FileNotFoundError:
        return "[TOOL NOT FOUND]"
    except Exception as e:
        return f"[ERROR: {e}]"

def tool_exists(name):
    return subprocess.run(['which', name], capture_output=True).returncode == 0

# ─── Scanners ────────────────────────────────────────────────

def scan_file_type(filepath):
    header("FILE — Identify file type")
    out = run_tool(['file', filepath])
    print(f"  {out.strip()}")
    find_flags(out, "file")

def scan_strings(filepath):
    header("STRINGS — Extract printable strings")
    out = run_tool(['strings', filepath])
    lines = out.splitlines()
    print(f"  Extracted {len(lines)} strings")
    find_flags(out, "strings")
    try_base64(out, "strings output")

    # Print suspicious lines
    suspicious = [l for l in lines if any(k in l.lower() for k in ['flag','ctf','kju','secret','password','key','hidden'])]
    if suspicious:
        print("\n  🔍 Suspicious strings:")
        for s in suspicious[:20]:
            print(f"     {s}")

def scan_exiftool(filepath):
    header("EXIFTOOL — Metadata")
    if not tool_exists('exiftool'):
        print("  [SKIPPED] exiftool not found")
        return
    out = run_tool(['exiftool', filepath])
    print(out.strip())
    find_flags(out, "exiftool metadata")
    try_base64(out, "exiftool metadata")

def scan_binwalk(filepath):
    header("BINWALK — Embedded files")
    if not tool_exists('binwalk'):
        print("  [SKIPPED] binwalk not found")
        return
    out = run_tool(['binwalk', filepath])
    print(out.strip())
    find_flags(out, "binwalk scan")

    # Auto extract
    print("\n  ⚙ Running binwalk extract (-e)...")
    extract_out = run_tool(['binwalk', '-e', '--run-as=root', filepath])
    print(f"  {extract_out.strip()[:300]}")

    # Scan extracted files
    extract_dir = f"_{os.path.basename(filepath)}.extracted"
    if os.path.exists(extract_dir):
        print(f"\n  📂 Scanning extracted files in {extract_dir}/")
        for root, dirs, files in os.walk(extract_dir):
            for f in files:
                fpath = os.path.join(root, f)
                print(f"\n  → {fpath}")
                sub_out = run_tool(['strings', fpath])
                find_flags(sub_out, f"binwalk extracted: {f}")
                try_base64(sub_out, f"binwalk extracted: {f}")

def scan_zsteg(filepath):
    header("ZSTEG — PNG/BMP Steganography")
    if not tool_exists('zsteg'):
        print("  [SKIPPED] zsteg not found")
        return
    if not filepath.lower().endswith(('.png', '.bmp')):
        print("  [SKIPPED] zsteg only works on PNG/BMP")
        return
    out = run_tool(['zsteg', filepath])
    print(out.strip()[:500])
    find_flags(out, "zsteg")
    try_base64(out, "zsteg output")

def scan_steghide(filepath):
    header("STEGHIDE — Steganography extract (no password)")
    if not tool_exists('steghide'):
        print("  [SKIPPED] steghide not found")
        return
    if not filepath.lower().endswith(('.jpg', '.jpeg', '.bmp', '.wav', '.au')):
        print("  [SKIPPED] steghide only works on JPG/BMP/WAV")
        return
    out = run_tool(['steghide', 'extract', '-sf', filepath, '-p', '', '-f'])
    print(f"  {out.strip()}")
    find_flags(out, "steghide")

    # Try common passwords
    common_passwords = ['password', '123456', 'ctf', 'flag', 'secret', 'admin', 'kju', '']
    for pwd in common_passwords:
        result = run_tool(['steghide', 'extract', '-sf', filepath, '-p', pwd, '-f'])
        if 'wrote extracted data' in result.lower():
            print(f"  ✅ steghide password found: '{pwd}'")
            find_flags(result, f"steghide password={pwd}")
            break

def scan_foremost(filepath):
    header("FOREMOST — File carving")
    if not tool_exists('foremost'):
        print("  [SKIPPED] foremost not found")
        return
    out_dir = f"foremost_out_{os.path.basename(filepath)}"
    out = run_tool(['foremost', '-i', filepath, '-o', out_dir])
    print(f"  {out.strip()}")
    if os.path.exists(out_dir):
        for root, dirs, files in os.walk(out_dir):
            for f in files:
                if f == 'audit.txt':
                    continue
                fpath = os.path.join(root, f)
                sub_out = run_tool(['strings', fpath])
                find_flags(sub_out, f"foremost carved: {f}")

def scan_xxd(filepath):
    header("XXD — Hex dump")
    if not tool_exists('xxd'):
        print("  [SKIPPED] xxd not found")
        return
    out = run_tool(['xxd', filepath])
    # Only search for flags in hex dump text
    find_flags(out, "xxd hex dump")

    # Also try raw hex decode
    try:
        with open(filepath, 'rb') as f:
            raw = f.read()
        text = raw.decode('utf-8', errors='ignore')
        find_flags(text, "raw binary read")
        try_base64(text, "raw binary read")
    except:
        pass

def scan_unzip(filepath):
    header("UNZIP — Archive contents")
    if not filepath.lower().endswith('.zip'):
        print("  [SKIPPED] not a zip file")
        return

    # List contents
    out = run_tool(['unzip', '-l', filepath])
    print(out.strip())
    find_flags(out, "zip listing")

    # Try extract with no password
    extract_out = run_tool(['unzip', '-o', filepath, '-d', f'unzip_out_{os.path.basename(filepath)}'])
    print(f"\n  Extract: {extract_out.strip()[:200]}")

    # Try common passwords if encrypted
    if 'password' in extract_out.lower() or 'encrypted' in extract_out.lower():
        print("\n  🔐 Zip is encrypted, trying common passwords...")
        for pwd in ['password','123456','ctf','flag','secret','admin','kju','0000']:
            r = run_tool(['unzip', '-P', pwd, '-o', filepath, '-d', f'unzip_out_{os.path.basename(filepath)}'])
            if 'inflating' in r.lower() or 'extracting' in r.lower():
                print(f"  ✅ ZIP password found: '{pwd}'")
                find_flags(r, f"zip extracted password={pwd}")
                break

def scan_image_lsb(filepath):
    header("LSB — Manual image bit check")
    try:
        from PIL import Image
        img = Image.open(filepath)
        pixels = list(img.getdata())
        bits = ''
        for px in pixels[:1000]:
            if isinstance(px, int):
                bits += str(px & 1)
            else:
                for channel in px[:3]:
                    bits += str(channel & 1)

        # Convert bits to text
        chars = []
        for i in range(0, len(bits) - 8, 8):
            byte = bits[i:i+8]
            c = chr(int(byte, 2))
            if c.isprintable():
                chars.append(c)
        lsb_text = ''.join(chars)
        print(f"  LSB text (first 200 chars): {lsb_text[:200]}")
        find_flags(lsb_text, "LSB steganography")
        try_base64(lsb_text, "LSB output")
    except ImportError:
        print("  [SKIPPED] Pillow not installed — pip install Pillow")
    except Exception as e:
        print(f"  [SKIPPED] {e}")

# ─── Summary ─────────────────────────────────────────────────
def print_summary():
    print(f"\n{'='*50}")
    print(f"  SCAN SUMMARY")
    print(f"{'='*50}")
    if not found_flags:
        print("\n  ❌ No flags found.\n")
    else:
        print(f"\n  ✅ {len(found_flags)} flag(s) found:\n")
        for i, f in enumerate(found_flags, 1):
            print(f"  [{i}] {f['flag']}")
            print(f"       → {f['source']}\n")

# ─── Main ─────────────────────────────────────────────────────
def main():
    if len(sys.argv) < 2:
        print("Usage: python ctf_forensics.py <file>")
        print("Works with: jpg, png, bmp, zip, bin, txt, wav, any file")
        sys.exit(1)

    filepath = sys.argv[1]

    if not os.path.exists(filepath):
        print(f"❌ File not found: {filepath}")
        sys.exit(1)

    print(f"\n{'='*50}")
    print(f"  CTF FORENSICS SCANNER")
    print(f"  File: {os.path.basename(filepath)}")
    print(f"  Size: {os.path.getsize(filepath)} bytes")
    print(f"{'='*50}")

    scan_file_type(filepath)
    scan_strings(filepath)
    scan_exiftool(filepath)
    scan_binwalk(filepath)
    scan_zsteg(filepath)
    scan_steghide(filepath)
    scan_foremost(filepath)
    scan_xxd(filepath)
    scan_unzip(filepath)
    scan_image_lsb(filepath)

    print_summary()

if __name__ == '__main__':
    main()
