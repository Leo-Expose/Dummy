# 🚩 Comprehensive CTF Analysis & Flag Capture Toolkit

A modular, production-grade security toolkit engineered for solving **Web Applications**, **Forensics**, **Image Steganography**, **Packet Captures**, and **Archiving/Cipher** CTF challenges.

---

## 🛠 Toolkit Overview & Quick Reference

| Tool | Primary Vector | Under the Hood | Usage Example |
| :--- | :--- | :--- | :--- |
| **[`ctf-flag-scanner.user.js`](file:///mnt/Lay/ctf/ctf-flag-scanner.user.js)** | Web CTFs, Browser Storage, Headers | JavaScript, `GM_xmlhttpRequest`, `unsafeWindow` | Install in Violentmonkey / Tampermonkey |
| **[`forensics`](file:///mnt/Lay/ctf/forensics)** ([`forensics.py`](file:///mnt/Lay/ctf/forensics.py)) | Mystery Files, Fake Extensions, EXIF | Python 3, `file`, `strings`, `Pillow` | `./forensics mystery_file` |
| **[`stego`](file:///mnt/Lay/ctf/stego)** ([`stego.py`](file:///mnt/Lay/ctf/stego.py)) | LSB Steganography, Embedded Files | Python 3, `NumPy`, `zsteg`, `binwalk` | `./stego target_image.png` |
| **[`unpack`](file:///mnt/Lay/ctf/unpack)** ([`unpack.py`](file:///mnt/Lay/ctf/unpack.py)) | Archives, Password Cracking, Ciphers | Python 3, `zipfile`, `tarfile`, `base64` | `./unpack -p secret archive.zip` |
| **[`test-site/`](file:///mnt/Lay/ctf/test-site)** | Local CTF Verification Testbed | Python `SimpleHTTPRequestHandler`, HTML5 | `python3 test-site/server.py` |

---

## 1. 🌐 Web Userscript Scanner (`ctf-flag-scanner.user.js`)

An automated userscript for **Violentmonkey** or **Tampermonkey** that inspects web applications in real time and exposes captured flags via a floating UI overlay or browser console.

### ✨ Key Features
- **Universal Pattern Matching**: Detects `FLAG{...}`, `CTF{...}`, `HTB{...}`, `picoCTF{...}`, `kju{...}`, and any custom format matching `[Prefix]{[content]}`.
- **Hidden Element Detection**: Detects flags hidden via `display: none`, `visibility: hidden`, `opacity: 0`, `font-size: 0px`, `hidden` attributes, or matching font/background colors.
- **DOM Comments & Inputs**: Iterates through HTML comments (`<!-- ... -->`) and `<input type="hidden">` fields.
- **Cookies & Web Storage**: Scans `document.cookie`, `localStorage`, and `sessionStorage`.
- **CORS-Free Header Interceptor**: Uses `GM_xmlhttpRequest` to read all custom HTTP response headers (`X-Flag`, `X-Secret`, `X-CTF-Token`, `Set-Cookie`).
- **Inline Scripts & Window Globals**: Inspects inline `<script>` contents and custom `window` properties.
- **Console Inspection**: Bypasses browser sandboxing via `@grant unsafeWindow`, exposing `discoveredFlags` directly in the F12 console.

### 📥 Installation
1. Open **Violentmonkey** or **Tampermonkey** in your browser.
2. Click **Create New Script** (`+`).
3. Copy and paste the contents of [`ctf-flag-scanner.user.js`](file:///mnt/Lay/ctf/ctf-flag-scanner.user.js).
4. Save the script.

### 🖥️ Console Usage
Open Developer Tools (`F12`) on any CTF page and type:
```javascript
// Access the Map of all discovered flags
discoveredFlags

// Print all flag strings as a list
Array.from(discoveredFlags.keys())
```

---

## 2. 🕵️ Forensics & Mystery File Analyzer (`./forensics`)

Designed for mystery files with missing or fake file extensions, hidden metadata, or appended payloads.

### ✨ Key Features
- **Magic Byte Verification**: Checks the raw binary header against known file signatures (`PNG`, `JPEG`, `ZIP`, `PDF`, `ELF`, `EXE`, etc.) and alerts if the file extension is fake.
- **Metadata & EXIF Inspection**: Runs `exiftool` (or built-in `Pillow` fallbacks) to inspect EXIF metadata, GPS coordinates, comments, and PNG text chunks.
- **Strings Extraction**: Extracts printable ASCII/Unicode text streams and automatically decodes Base64 strings.
- **Appended Payload Carver**: Detects hidden data appended after image end-of-file markers (`IEND` for PNG, `EOI` `FF D9` for JPEG).

### 🚀 Usage Commands
```bash
# Basic inspection of a mystery file
./forensics mystery_file

# Inspect and automatically extract appended payloads to ./extracted/
./forensics -e mystery_file

# Verbose mode (displays sample strings dump)
./forensics -v mystery_file

# Custom minimum string length (default: 4)
./forensics -s 8 mystery_file
```

---

## 3. 🖼️ Steganography & Embedded Carver (`./stego`)

Combines **zsteg** (LSB image steganography) and **binwalk** (embedded file carving).

### ✨ Key Features
- **zsteg LSB Engine**: Evaluates 1-bit, 2-bit, and 4-bit LSB planes across `Red`, `Green`, `Blue`, `Alpha`, `RGB`, `BGR`, `RGBA`, and `ABGR` channels.
- **binwalk Carving Engine**: Scans binary data byte-by-byte for embedded sub-files (`ZIP`, `7z`, `RAR`, `PNG`, `JPEG`, `PDF`, `ELF`, `MP3`, `WAV`, `OGG`) and extracts them into `./extracted_stego/`.
- **PNG Chunk Inspector**: Parses PNG chunk structures (`IHDR`, `PLTE`, `IDAT`, `IEND`, `tEXt`, `zTXt`, etc.) and alerts on non-standard chunks or IDAT anomalies.

### 🚀 Usage Commands
```bash
# Full steganography & embedded file scan
./stego target_image.png

# Scan and automatically extract/carve embedded files to ./extracted_stego/
./stego -e target_image.png

# Run LSB scanning only (zsteg mode)
./stego --lsb-only target_image.png

# Run file carving scan only (binwalk mode)
./stego --carve-only mystery_file
```

---

## 4. 📦 Archive Unpacker & Cipher Decoder (`./unpack`)

Handles archive extraction, password cracking, and multi-layer cipher decoding.

### ✨ Key Features
- **Archive Extraction**: Unpacks `.zip`, `.tar`, `.tar.gz`, `.tar.bz2`, `.gz`, `.bz2`.
- **Password Protection & Brute Force**:
  - Supports explicit password input (`-p password`).
  - Supports dictionary wordlist files (`-w wordlist.txt`).
  - Automatically harvests candidate strings from the target file to attempt as passwords.
- **Recursive Unpacking**: Automatically extracts nested archives (e.g. ZIP inside ZIP inside TAR).
- **Multi-Layer Encoding & Cipher Decoder**:
  - **Base64** (Recursive multi-layer decoding: `b64 -> b64 -> FLAG`).
  - **Base32** & **Base85**.
  - **Hex / ASCII bytes**.
  - **ROT13 / Caesar Shift**.
  - **URL Encoding** (`%20`, `%7B`, etc.).

### 🚀 Usage Commands
```bash
# Unpack archive with auto-password trial
./unpack archive.zip

# Unpack password-protected archive with explicit password
./unpack -p "secret123" archive.zip

# Unpack using a dictionary wordlist
./unpack -w passwords.txt archive.zip

# Decode multi-layer cipher string directly
./unpack -d "RkxBR3ttdWx0aV9sYXllcl9iYXNlNjRfZGVjb2RlZH0="
```

---

## 5. 🧪 Local Verification Testbed (`test-site/`)

A local CTF verification server featuring **26 unique flags** across **41 distinct test locations** (DOM text, hidden CSS, Base64, cookies, storage, scripts, and HTTP response headers).

### Launching the Testbed Server
```bash
python3 test-site/server.py
```
- Open `http://localhost:8000` in your browser to verify the userscript scanner.

---

## 🎯 Challenge Workflow Matrix

| Challenge Type | Recommended Workflow |
| :--- | :--- |
| **Web Page / CTF Web Challenge** | Open page with `ctf-flag-scanner.user.js` active -> Check floating UI / console `discoveredFlags`. |
| **Unknown / Mystery File** | Run `./forensics mystery_file` -> Check header mismatch & EXIF tags. |
| **Image Steganography (PNG/BMP)** | Run `./stego -e image.png` -> Check LSB bit planes & carved embedded sub-files. |
| **Protected ZIP / Multi-layer Cipher** | Run `./unpack -p "password" file.zip` or `./unpack -d "encoded_text"`. |
