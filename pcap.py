from scapy.all import rdpcap, Raw
import base64
import re
import sys
import os

# ─── Flag Patterns ───────────────────────────────────────────
# Generic Braced Flag Pattern (matches ANY prefix: HTB{...}, picoCTF{...}, SECCON{...}, custom_name{...})
GENERIC_BRACED_RE = re.compile(r'[A-Za-z0-9_\-]{1,25}\{[^}\s\r\n]+\}')

# Optional UUID and SHA256 formats
UUID_RE = re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b')
SHA256_RE = re.compile(r'\b[a-fA-F0-9]{64}\b')

BASE64_RE = re.compile(r'[A-Za-z0-9+/]{8,}={0,2}')

found_flags = []

# ─── Helpers ─────────────────────────────────────────────────
def find_flags(text, source):
    matches = GENERIC_BRACED_RE.findall(text)
    for m in matches:
        entry = {'flag': m, 'source': source}
        if entry not in found_flags:
            found_flags.append(entry)
            print(f"  🚩 FOUND: {m}")
            print(f"     Source: {source}\n")

def try_base64(text, source):
    for match in BASE64_RE.findall(text):
        try:
            decoded = base64.b64decode(match + '==').decode('utf-8', errors='ignore')
            if re.search(r'[\x20-\x7E]{4,}', decoded):
                find_flags(decoded, f"Base64 decoded from {source}")
        except:
            pass

def try_hex(raw_bytes, source):
    try:
        hex_str = raw_bytes.hex()
        # Try decoding hex pairs as ASCII
        decoded = bytes.fromhex(hex_str).decode('utf-8', errors='ignore')
        find_flags(decoded, f"Hex decoded from {source}")
    except:
        pass

def clean(data):
    try:
        return data.decode('utf-8', errors='ignore')
    except:
        return ''

# ─── Main Scanner ─────────────────────────────────────────────
def scan_pcap(filepath):
    print(f"\n{'='*50}")
    print(f"  CTF FLAG SCANNER")
    print(f"  File: {os.path.basename(filepath)}")
    print(f"{'='*50}\n")

    try:
        packets = rdpcap(filepath)
    except Exception as e:
        print(f"❌ Error reading file: {e}")
        sys.exit(1)

    print(f"📦 Total packets loaded: {len(packets)}\n")

    for i, pkt in enumerate(packets):
        pkt_label = f"Packet #{i+1}"

        # ── Raw payload ──
        if pkt.haslayer(Raw):
            raw = pkt[Raw].load
            text = clean(raw)

            if text:
                find_flags(text, f"{pkt_label} → Raw payload")
                try_base64(text, f"{pkt_label} → Raw payload")

            try_hex(raw, f"{pkt_label} → Raw bytes")

        # ── HTTP layer (if scapy detects it) ──
        if pkt.haslayer('HTTPRequest') or pkt.haslayer('HTTPResponse'):
            try:
                http_text = clean(bytes(pkt))
                find_flags(http_text, f"{pkt_label} → HTTP layer")
                try_base64(http_text, f"{pkt_label} → HTTP layer")
            except:
                pass

        # ── Full packet bytes (catches everything else) ──
        try:
            full = clean(bytes(pkt))
            find_flags(full, f"{pkt_label} → Full packet")
            try_base64(full, f"{pkt_label} → Full packet")
        except:
            pass

    # ─── Summary ───────────────────────────────────────────────
    print(f"\n{'='*50}")
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
    if len(sys.argv) < 2:
        print("Usage: python flag_scanner.py capture.pcap")
        sys.exit(1)
    scan_pcap(sys.argv[1])