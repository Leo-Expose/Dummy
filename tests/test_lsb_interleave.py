#!/usr/bin/env python3
"""Regression test: native LSB must read true zsteg bit order.

zsteg `b1,rgb,lsb` consumes LSBs pixel-interleaved (R,G,B,R,G,B...),
not plane-by-plane (all-R then all-G). A previous implementation
concatenated whole channel planes and missed genuine multi-channel
embeds. This test embeds in true zsteg order and asserts detection.

Also asserts single-channel (R-only) embeds still work.

Usage: python3 tests/test_lsb_interleave.py
Exit 0 = pass, 1 = fail.
"""
import os
import subprocess
import sys
import tempfile

from PIL import Image

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STEGO = os.path.join(REPO_ROOT, "stego.py")
FLAG_RGB = "flag{rgb_interleave_win}"
FLAG_R = "flag{red_only_win}"


def _to_bits(payload: bytes) -> str:
    return "".join(f"{b:08b}" for b in payload + b"\x00")


def embed_true_zsteg_order(path, flag):
    """Embed 1-bit LSB across R,G,B in R,G,B-per-pixel order (what zsteg reads)."""
    bits = _to_bits(flag.encode())
    w, h = 64, 64
    assert len(bits) <= w * h * 3, "fixture too small"
    img = Image.new("RGB", (w, h), "white")
    px = img.load()
    bi = 0
    for y in range(h):
        for x in range(w):
            r, g, b = px[x, y]
            if bi < len(bits):
                r = (r & 0xFE) | int(bits[bi]); bi += 1
            if bi < len(bits):
                g = (g & 0xFE) | int(bits[bi]); bi += 1
            if bi < len(bits):
                b = (b & 0xFE) | int(bits[bi]); bi += 1
            px[x, y] = (r, g, b)
    img.save(path)


def embed_red_only(path, flag):
    """Embed 1-bit LSB in the red channel only."""
    bits = _to_bits(flag.encode())
    w, h = 64, 64
    img = Image.new("RGB", (w, h), "white")
    px = img.load()
    bi = 0
    for y in range(h):
        for x in range(w):
            r, g, b = px[x, y]
            if bi < len(bits):
                r = (r & 0xFE) | int(bits[bi]); bi += 1
            px[x, y] = (r, g, b)
    img.save(path)


def run_stego(path):
    # --no-external proves the NATIVE engine finds it (no zsteg binary needed)
    res = subprocess.run(
        [sys.executable, STEGO, "--no-external", "--lsb-only", path],
        capture_output=True, text=True, timeout=300,
    )
    return res.stdout + res.stderr


def main():
    failures = []
    with tempfile.TemporaryDirectory(prefix="ctf_lsb_test_") as tmp:
        rgb_path = os.path.join(tmp, "rgb_ordered.png")
        r_path = os.path.join(tmp, "red_only.png")
        embed_true_zsteg_order(rgb_path, FLAG_RGB)
        embed_red_only(r_path, FLAG_R)

        out = run_stego(rgb_path)
        if FLAG_RGB in out:
            print(f"PASS: true-zsteg-order RGB embed detected ({FLAG_RGB})")
        else:
            print(f"FAIL: true-zsteg-order RGB embed MISSED ({FLAG_RGB})")
            failures.append("rgb-order")

        out = run_stego(r_path)
        if FLAG_R in out:
            print(f"PASS: red-only embed still detected ({FLAG_R})")
        else:
            print(f"FAIL: red-only embed MISSED ({FLAG_R})")
            failures.append("red-only")

    if failures:
        print(f"\n{len(failures)} failing case(s): {failures}")
        return 1
    print("\nAll LSB interleave tests passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
