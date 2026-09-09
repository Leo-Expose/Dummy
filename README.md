# 🚩 CTF Analysis & Flag Capture Toolkit

Standalone toolkit for early rounds of small CTFs — tuned for **speed and low false-positives**. Strict flag matching is the default; use `--loose` / `LOOSE_MODE` only for custom-prefix challenges.

## Setup

```bash
pip install -r requirements.txt
chmod +x forensics.py stego.py unpack.py pcap.py
```

> Requires Python 3.10+. Optional system binaries (used if present, with timeouts): `file`, `exiftool`, `strings`. All tools work without them via Python fallbacks.

---

## 🛠 Toolkit Overview & Quick Reference

| Tool | Primary Vector | Under the Hood | Usage Example |
| :--- | :--- | :--- | :--- |
| [`website.js`](./website.js) | Web CTFs, Storage, Headers, XHR/fetch | Violentmonkey/Tampermonkey, `GM_xmlhttpRequest`, `unsafeWindow` | Install in Violentmonkey, enable only on CTF host |
| [`forensics.py`](./forensics.py) | Mystery Files, Fake Extensions, EXIF | Python 3, `file`, `strings`, `Pillow` | `./forensics.py mystery_file` |
| [`stego.py`](./stego.py) | LSB Steganography, Embedded Files | Python 3, `NumPy`, `Pillow` | `./stego.py target_image.png` |
| [`unpack.py`](./unpack.py) | Archives, Password Trial, Ciphers | Python 3, `zipfile`, `tarfile`, `base64` | `./unpack.py -p secret archive.zip` |
| [`pcap.py`](./pcap.py) | Packet Captures, DNS/HTTP exfil | Python 3, `scapy` (streaming) | `./pcap.py capture.pcap` |

Strict mode (default) matches `flag|ctf|picoCTF|HTB|THM|kju|CHTB|SEKAI|UIUCTF|PatriotCTF{...}`. Hashes/UUIDs are printed as `💡 HINT`, not flags.

---

## 1. 🌐 Web Userscript Scanner (`website.js`)

Violentmonkey/Tampermonkey scanner. Console-first output (no floating UI by design — keeps it fast).

### ✨ Key Features
- **Strict Pattern Matching**: known prefixes only by default; set `LOOSE_MODE = true` at the top of the script for custom `PREFIX{...}` challenges.
- **Hidden Element Detection**: `display: none`, `visibility: hidden`, `opacity: 0`, `font-size: 0`, `hidden` attributes, same color/bg.
- **DOM Comments & Inputs**: HTML comments + `<input type="hidden">` + all element attributes.
- **Cookies & Web Storage**: `document.cookie`, `localStorage`, `sessionStorage` (incl. Base64-wrapped flags with round-trip validation).
- **Header Interceptor**: `GM_xmlhttpRequest` re-GET for response headers; `HEAD` fallback.
- **Inline Scripts, Globals & SourceMaps**: inline `<script>`, string/object `window` globals, `*.js.map` fetch.
- **SPA Support**: `MutationObserver` (800ms debounce) + `fetch`/`XHR` response hooks catch React/AJAX-loaded flags. Call `CTF_rescan()` manually after solving a step.

### 📥 Installation
1. Open **Violentmonkey** or **Tampermonkey**.
2. Create new script, paste contents of [`website.js`](./website.js), save.
3. **Enable only on the CTF host** (script settings → match rules) — do not leave on `*://*/*` globally.

### 🖥️ Console Usage
```javascript
discoveredFlags
Array.from(discoveredFlags.keys())
CTF_rescan() // manual re-scan after dynamic content loads
```

---

## 2. 🕵️ Forensics & Mystery File Analyzer (`forensics.py`)

Mystery files with fake extensions, metadata, or appended payloads.

### ✨ Key Features
- **Magic Byte Verification**: `PNG/JPEG/GIF/ZIP/7z/RAR/PDF/ELF/EXE/OGG/MP3/MPEG/RIFF/GZIP/BZIP2/SQLite/OLE/PCAP/PCAP-NG/XZ/Zstd`; warns on fake/missing extension.
- **Metadata & EXIF**: `exiftool` (15s timeout) or `Pillow` `getexif()` + PNG text-chunk fallback.
- **Strings**: system `strings` (15s timeout) or Python `[ -~]` fallback; Base64 hits require canonical round-trip.
- **Trailing Payloads**: after PNG `IEND`, JPEG `EOI`, GIF `0x3B`, PDF `%%EOF`; carve capped at 50MB; embedded ZIP detection.
- **Safety**: 200MB input cap (`--force` to override), `Image.MAX_IMAGE_PIXELS` guard.

### 🚀 Usage
```bash
./forensics.py mystery_file
./forensics.py -e mystery_file      # extract to ./extracted/
./forensics.py -v mystery_file      # verbose strings sample
./forensics.py -s 8 mystery_file    # min string length
./forensics.py --loose mystery_file # any-prefix matching
```

---

## 3. 🖼️ Steganography & Embedded Carver (`stego.py`)

LSB scan + embedded-file carving + PNG chunk audit.

### ✨ Key Features
- **LSB Engine**: 1/2/4-bit planes × `r/g/b/a/rgb/bgr/rgba/abgr` × MSB-first + LSB-first byte orders (vectorized NumPy, 4M-value cap for speed).
- **Carving**: `ZIP/7z/RAR/GZIP/BZIP2/PNG/JPEG/BMP/GIF/PDF/ELF/EXE/MP3/OGG/FLAC/RIFF/SQLite/PCAP` → `./extracted_stego/` (50MB cap per carve).
- **PNG Chunks**: bounds-checked parser with CRC-mismatch warnings; flags non-standard chunks; reports trailing bytes after `IEND`.
- **Safety**: 200MB input cap (`--force` to override), large-image downsample notice.

### 🚀 Usage
```bash
./stego.py target_image.png
./stego.py -e target_image.png
./stego.py --lsb-only target_image.png
./stego.py --carve-only mystery_file
./stego.py --loose target_image.png
```

---

## 4. 📦 Archive Unpacker & Cipher Decoder (`unpack.py`)

Archives + multi-layer cipher decoding.

### ✨ Key Features
- **Safe Extraction**: ZipSlip/TarSlip guards (rejects absolute paths, `..`, symlinks), per-file 50MB cap, 200MB total cap, compression-ratio guard.
- **Passwords**: `-p`, `-w wordlist` (capped at 5000), auto-harvest from first 2MB of file; handles `RuntimeError` (bad password) + `NotImplementedError` (unsupported crypto).
- **Recursion**: nested archives to `--max-depth 3` (default) with SHA256 loop guard.
- **Ciphers** (recursive, cycle-guarded): Base64 (round-trip validated), Base32 (alphabet+length gated), Base85 (round-trip), Hex runs, Caesar-26 (recurse on flag hits), URL-decode (recurse), single-byte XOR brute (depth-0, flag hits only).

### 🚀 Usage
```bash
./unpack.py archive.zip
./unpack.py -p "secret123" archive.zip
./unpack.py -w passwords.txt archive.zip
./unpack.py -d "RkxBR3ttdWx0aV9sYXllcl9iYXNlNjRfZGVjb2RlZH0="
./unpack.py --loose -d "customprefix{...}"
./unpack.py --max-depth 5 archive.zip
```

---

## 5. 📡 PCAP Flag Scanner (`pcap.py`)

Streaming scanner (no full-file `rdpcap` load).

### ✨ Key Features
- **Streaming**: `PcapReader` with `--max-packets 20000` / `--max-bytes 200MB` caps.
- **Layers**: `Raw` payloads, DNS answers + query names (TXT exfil), ICMP payloads.
- **Encodings**: Base64 (validated), hex-run decoding (fixed — old version was a no-op), `gzip`/`zlib` body decompression when `Content-Encoding` present.
- **Strict default** with `--loose` opt-in; UUIDs logged as hints.

### 🚀 Usage
```bash
./pcap.py capture.pcap
./pcap.py --loose capture.pcap
./pcap.py --max-packets 50000 capture.pcapng
```

---

## 🎯 Challenge Workflow Matrix (early-round speedrun)

| Challenge Type | Recommended Workflow |
| :--- | :--- |
| **Web Page** | Enable userscript on CTF host → `Array.from(discoveredFlags.keys())` → `CTF_rescan()` after each step |
| **Unknown / Mystery File** | `./forensics.py file` → check header mismatch → `-e` if trailing/embedded hint |
| **Image Stego (PNG/BMP)** | `./stego.py -e image.png` → LSB hits + carved files + chunk warnings |
| **Protected ZIP / Cipher text** | `./unpack.py -p "pw" file.zip` or `./unpack.py -d "encoded"` |
| **PCAP / PCAP-NG** | `./pcap.py capture.pcap` → check Raw + DNS + decompressed bodies |

> Future (deferred): merge into single `ctf` CLI with subcommands; local verification testbed.
