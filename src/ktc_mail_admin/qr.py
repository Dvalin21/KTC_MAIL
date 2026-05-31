"""Local QR code generation — no external API calls, no secret leakage.

Generates QR code SVGs entirely in-process using the pure-Python qrcode
library with its built-in SVG path image factory.  No PIL / Pillow needed.
"""

from __future__ import annotations

import base64
import io

import qrcode
import qrcode.image.svg


def qr_svg_b64(data: str) -> str:
    """Return a base64-encoded data URI for a QR code SVG of *data*.

    The SVG is minimal (path-based, no raster images), so the data URI is
    typically ~2–4 KB for a TOTP URI.  The result is safe to embed directly
    in an ``<img src="…">`` attribute.
    """
    factory = qrcode.image.svg.SvgPathImage
    img = qrcode.make(data, image_factory=factory)
    buf = io.BytesIO()
    img.save(buf)
    b64 = base64.b64encode(buf.getvalue()).decode()
    return f"data:image/svg+xml;base64,{b64}"
