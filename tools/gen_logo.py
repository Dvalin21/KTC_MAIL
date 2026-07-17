#!/usr/bin/env python3
"""Generate the KTC Mail default logo as a real binary PNG (no deps).

Design: a "tied cable knot" — two interlocking rounded bars forming a square
knot, the unit a mail server ships: messages tied together. Deliberately NOT
the generic envelope-in-a-circle. Asymmetric: one bar tilts, a small offset
stud breaks the sterility. Transparent background so it sits on any theme.

Pure stdlib: we encode an RGBA PNG by hand (zlib + struct). No Pillow, no
cairosvg — a logo generator should not drag an imaging stack into the build.

Run: python3 tools/gen_logo.py [out.png] [accent_hex]
"""
from __future__ import annotations

import struct
import sys
import zlib
from pathlib import Path

SIZE = 256


def hex_to_rgb(h: str) -> tuple[int, int, int]:
    h = h.lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def lerp(a: int, b: int, t: float) -> int:
    return int(a + (b - a) * t)


def make_pixels(accent: tuple[int, int, int]) -> bytes:
    """Return raw RGBA rows (SIZE*SIZE*4 bytes)."""
    # Complementary stroke: shift hue by mixing toward a warm contrast.
    comp = (
        min(255, accent[0] + 70),
        max(0, accent[1] - 40),
        min(255, accent[2] - 30),
    )
    # prewitt-ish: we rasterize strokes with a thickness using distance fields.
    rows = bytearray()
    cx, cy = SIZE // 2, SIZE // 2

    # bar geometry: two rounded bars crossing, one tilted slightly.
    # bar A: horizontal-ish, bar B: vertical-ish, plus a small offset stud.
    def in_bar(x: float, y: float, x0: float, y0: float, x1: float, y1: float,
               thick: float) -> float:
        # distance from point to segment, returns <thick/2 inside
        dx, dy = x1 - x0, y1 - y0
        L2 = dx * dx + dy * dy
        if L2 == 0:
            t = 0.0
        else:
            t = max(0.0, min(1.0, ((x - x0) * dx + (y - y0) * dy) / L2))
        px, py = x0 + t * dx, y0 + t * dy
        return ((x - px) ** 2 + (y - py) ** 2) ** 0.5

    thick = 26.0
    # bar A endpoints (tilted): top-left to bottom-right, slight asymmetry
    a0 = (54.0, 60.0)
    a1 = (196.0, 204.0)
    # bar B endpoints (tilted the other way) — forms the knot cross
    b0 = (62.0, 198.0)
    b1 = (200.0, 52.0)
    # small offset stud (breaks generic symmetry)
    stud = (188.0, 188.0)
    stud_r = 13.0

    for y in range(SIZE):
        for x in range(SIZE):
            r = g = b = 0
            a = 0
            da = in_bar(x, y, *a0, *a1, thick)
            db = in_bar(x, y, *b0, *b1, thick)
            # round caps: also inside if near an endpoint
            near_a = min(
                ((x - a0[0]) ** 2 + (y - a0[1]) ** 2) ** 0.5,
                ((x - a1[0]) ** 2 + (y - a1[1]) ** 2) ** 0.5,
            )
            near_b = min(
                ((x - b0[0]) ** 2 + (y - b0[1]) ** 2) ** 0.5,
                ((x - b1[0]) ** 2 + (y - b1[1]) ** 2) ** 0.5,
            )
            col = None
            if da < thick / 2 or near_a < thick / 2:
                col = accent
            if db < thick / 2 or near_b < thick / 2:
                col = comp
            # stud
            if ((x - stud[0]) ** 2 + (y - stud[1]) ** 2) ** 0.5 < stud_r:
                col = accent
            if col is not None:
                r, g, b = col
                a = 255
            rows += struct.pack("BBBB", r, g, b, a)
    return bytes(rows)


def encode_png(pixels: bytes) -> bytes:
    def chunk(tag: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", SIZE, SIZE, 8, 6, 0, 0, 0)  # 8-bit RGBA
    idat = zlib.compress(pixels, 9)
    return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def main() -> None:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else (
        Path(__file__).resolve().parents[1]
        / "src/ktc_mail_admin/static/branding/logo.png"
    )
    accent_hex = sys.argv[2] if len(sys.argv) > 2 else "#5b67f1"
    out.parent.mkdir(parents=True, exist_ok=True)
    accent = hex_to_rgb(accent_hex)
    png = encode_png(make_pixels(accent))
    out.write_bytes(png)
    print(f"wrote {out} ({len(png)} bytes, accent={accent_hex})")


if __name__ == "__main__":
    main()
