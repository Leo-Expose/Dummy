#!/usr/bin/env python3
"""CTF PCAP flag scanner — strict by default, streaming, early-round tuned."""
import argparse
import base64
import binascii
import gzip
import os
import re
import sys
import zlib

try:
    from scapy.all import PcapReader, Raw, DNS, DNSRR, ICMP
except ImportError:
    print("❌ Missing dependency: scapy. Install with: pip install -r requirements.txt", file=sys.stderr)
    sys.exit(2)

# ─── Flag Patterns: strict by default ──────────────────────────
STRICT_PREFIXES = r'(?:flag|ctf|picoCTF|HTB|THM|kju|CHTB|SEKAI|UIUCTF|PatriotCTF)'
STRICT_RE = re.compile(STRICT_PREFIXES + r'\{[^}\r\n]{1,200}\}', re.IGNORECASE)
LOOSE_RE = re.compile(r'[A-Za-z0-9_\-]{3,25}\{[A-Za-z0-9_\-!@#$%^&*()+=~`|:;\"\'<>,.?/\\ \[\]]{1,200}\}')
FLAG_RE = STRICT_RE

UUID_RE = re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b')
BASE64_RE = re.compile(r'[A-Za-z0-9+/]{8,}={0,2}')
HEX_RUN_RE = re.compile(r'(?:[0-9a-fA-F]{2}[\s:]?){8,}')

found_flags = []
found_hints = []

def log_flag(flag, source):
    if any(e['flag'] == flag for e in found_flags):
        return
    entry = {'flag': flag, 'source': source}
    found_flags.append(entry)
    print(f"  🚩 FOUND: {flag}")
    print(f"     Source: {source}\n")

def log_hint(hint, source):
    entry = (hint, source)
    if entry not in found_hints:
        found_hints.append(entry)
        print(f"  💡 HINT ({source}): {hint}")

def find_flags(text, source):
    if not text:
        return
    for m in FLAG_RE.findall(text):
        log_flag(m, source)
    for h in UUID_RE.findall(text):
        log_hint(h, source + " [uuid]")

def _pad_b64(s):
    return s + '=' * ((-len(s)) % 4)

def _valid_b64(s):
    try:
        s = re.sub(r'\s+', '', s)
        if len(s) < 8 or len(s) % 4 == 1:
            return False
        dec = base64.b64decode(_pad_b64(s), validate=True)
        return base64.b64encode(dec).decode().rstrip('=') == s.rstrip('=')
    except Exception:
        return False

def try_base64(text, source):
    if not text or len(text) < 8:
        return
    for match in set(BASE64_RE.findall(text)):
        try:
            if not _valid_b64(match):
                continue
            decoded = base64.b64decode(_pad_b64(match)).decode('utf-8', errors='ignore')
            if re.search(r'[\x20-\x7E]{4,}', decoded):
                find_flags(decoded, f"Base64 decoded from {source}")
        except Exception:
            continue

def try_hex_text(text, source):
    """Decode hex-encoded runs found in text (e.g. 666c61677b...)."""
    if not text:
        return
    for m in set(HEX_RUN_RE.findall(text)):
        try:
            clean_hex = re.sub(r'[\s:]', '', m)
            if len(clean_hex) % 2 != 0 or not 16 <= len(clean_hex) <= 10000:
                continue
            decoded = bytes.fromhex(clean_hex).decode('utf-8', errors='ignore')
            if re.search(r'[\x20-\x7E]{4,}', decoded):
                find_flags(decoded, f"Hex decoded from {source}")
        except Exception:
            continue

def try_decompress(raw, source):
    """Attempt gzip/zlib decompression of Raw payloads (HTTP bodies). Returns decoded text or ''."""
    if not raw or len(raw) < 18:
        return ''
    blobs = [raw]
    # Split HTTP headers/body so gzip blob decompresses cleanly
    if b'\r\n\r\n' in raw:
        blobs.append(raw.split(b'\r\n\r\n', 1)[1])
    candidates = []
    for blob in blobs:
        if blob[:2] == b'\x1f\x8b':
            try:
                candidates.append(gzip.decompress(blob).decode('utf-8', errors='ignore'))
            except Exception:
                pass
        # zlib stream (common for HTTP deflate)
        try:
            candidates.append(zlib.decompress(blob).decode('utf-8', errors='ignore'))
        except Exception:
            pass
    for c in candidates:
        if c and re.search(r'[\x20-\x7E]{4,}', c):
            find_flags(c, f"Decompressed body from {source}")
            try_base64(c, f"Decompressed body from {source}")
            try_hex_text(c, f"Decompressed body from {source}")
            return c
    return ''

def clean(data):
    try:
        return data.decode('utf-8', errors='ignore')
    except Exception:
        return ''

# ─── Main Scanner (streaming) ───────────────────────────────────
def scan_pcap(filepath, max_packets=20000, max_bytes=200 * 1024 * 1024):
    print(f"\n{'='*50}")
    print(f"  CTF FLAG SCANNER (strict)")
    print(f"  File: {os.path.basename(filepath)}")
    print(f"{'='*50}\n")

    if not os.path.exists(filepath):
        print(f"❌ File not found: {filepath}")
        sys.exit(1)

    count = 0
    byte_total = 0
    try:
        reader = PcapReader(filepath)
    except Exception as e:
        print(f"❌ Error opening file: {e}")
        sys.exit(1)

    with reader:
        for pkt in reader:
            count += 1
            if count > max_packets:
                print(f"⏩ Packet cap ({max_packets}) hit, stopping. Use --max-packets to raise.\n")
                break
            try:
                pkt_len = len(pkt)
            except Exception:
                pkt_len = 0
            byte_total += pkt_len
            if byte_total > max_bytes:
                print(f"⏩ Byte cap ({max_bytes}) hit, stopping.\n")
                break

            pkt_label = f"Packet #{count}"

            # ── DNS records (TXT exfil is common in early rounds) ──
            try:
                if pkt.haslayer(DNS):
                    dns = pkt[DNS]
                    for rr in ([dns.an] if dns.an else []) + ([dns.ns] if dns.ns else []) + ([dns.ar] if dns.ar else []):
                        try:
                            rdata = rr.rdata
                            txt = rdata.decode('utf-8', errors='ignore') if isinstance(rdata, bytes) else str(rdata)
                            if txt:
                                find_flags(txt, f"{pkt_label} → DNS")
                                try_base64(txt, f"{pkt_label} → DNS")
                        except Exception:
                            continue
                    # also scan query names
                    try:
                        if dns.qd and dns.qd.qname:
                            q = dns.qd.qname.decode('utf-8', errors='ignore')
                            find_flags(q, f"{pkt_label} → DNS query")
                    except Exception:
                        pass
            except Exception:
                pass

            # ── Raw payload: single scan (flags + b64 + hex + decompress) ──
            if pkt.haslayer(Raw):
                try:
                    raw = bytes(pkt[Raw].load)
                except Exception:
                    raw = b''
                if raw:
                    text = clean(raw)
                    if text:
                        find_flags(text, f"{pkt_label} → Raw payload")
                        try_base64(text, f"{pkt_label} → Raw payload")
                        try_hex_text(text, f"{pkt_label} → Raw payload")
                        # compressed HTTP bodies hide flags
                        if b'Content-Encoding' in raw[:2000] or raw[:2] == b'\x1f\x8b' or (len(raw) > 2 and raw[:1] == b'x'):
                            try_decompress(raw, f"{pkt_label} → Raw payload")
                    # ICMP payloads without Raw layer handled below; Raw already covers most
            elif pkt.haslayer(ICMP):
                try:
                    icmps = clean(bytes(pkt[ICMP].payload))
                    if icmps:
                        find_flags(icmps, f"{pkt_label} → ICMP")
                        try_base64(icmps, f"{pkt_label} → ICMP")
                except Exception:
                    pass

    print(f"\n📦 Packets scanned: {count} ({byte_total} bytes)\n")

    # ─── Summary ───────────────────────────────────────────────
    print(f"{'='*50}")
    print(f"  SCAN COMPLETE")
    print(f"{'='*50}")

    if not found_flags:
        print("\n❌ No flags found in this capture.\n")
    else:
        print(f"\n✅ {len(found_flags)} unique flag(s) found:\n")
        for i, f in enumerate(found_flags, 1):
            print(f"  [{i}] {f['flag']}")
            print(f"       → {f['source']}\n")

# ─── Entry Point ──────────────────────────────────────────────
if __name__ == '__main__':
    ap = argparse.ArgumentParser(description="CTF PCAP flag scanner (strict by default)")
    ap.add_argument("pcap", help="Path to .pcap/.pcapng file")
    ap.add_argument("--loose", action="store_true", help="Loose flag matching (any prefix{...})")
    ap.add_argument("--max-packets", type=int, default=20000)
    ap.add_argument("--max-bytes", type=int, default=200 * 1024 * 1024)
    args = ap.parse_args()
    if args.loose:
        FLAG_RE = LOOSE_RE
        print("[*] Loose flag matching enabled.")
    scan_pcap(args.pcap, max_packets=args.max_packets, max_bytes=args.max_bytes)
