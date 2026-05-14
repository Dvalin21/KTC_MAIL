"""KTC Mail — Multi-factor authentication (TOTP, stdlib-only).

Implements Time-based One-Time Password (TOTP) per RFC 6238 using
only the Python standard library.  No dependency on ``pyotp`` or
third-party modules.

The implementation is deliberately minimal and boring:
  - HMAC-SHA1 (required by RFC 4226 / RFC 6238)
  - 6-digit codes, 30-second time step
  - ±1 step verification window (default, configurable)
  - Base32-encoded secrets (20 bytes = 160 bits = 32 base32 chars)
"""

from __future__ import annotations

import base64
import hmac
import os
import struct
import time
from urllib.parse import quote


# ── TOTP primitives ──────────────────────────────────────────────────────────


def _hotp(secret: bytes, counter: int, digits: int = 6) -> str:
    """HMAC-Based One-Time Password (RFC 4226 Section 5.3).

    Args:
        secret:  Shared secret as raw bytes.
        counter:  8-byte big-endian counter value.
        digits:   Number of digits in the OTP (default 6).

    Returns:
        *digits*-digit HOTP value as a zero-padded string.
    """
    msg = struct.pack(">Q", counter)
    hs = hmac.new(secret, msg, "sha1").digest()
    # Dynamic truncation (RFC 4226 Section 5.4)
    offset = hs[-1] & 0x0F
    binary = (
        (struct.unpack(">I", hs[offset : offset + 4])[0]) & 0x7FFFFFFF
    ) % (10 ** digits)
    return str(binary).zfill(digits)


def totp(secret_b32: str, *, digits: int = 6, interval: int = 30) -> str:
    """Time-Based One-Time Password (RFC 6238).

    Args:
        secret_b32:  Base32-encoded shared secret.
        digits:      Number of digits in the OTP (default 6).
        interval:    Time step in seconds (default 30).

    Returns:
        Current TOTP code as a zero-padded string.
    """
    secret = base64.b32decode(secret_b32, casefold=True)
    counter = int(time.time()) // interval
    return _hotp(secret, counter, digits)


def verify_totp(
    secret_b32: str,
    code: str,
    *,
    digits: int = 6,
    interval: int = 30,
    window: int = 1,
) -> bool:
    """Verify a TOTP code against the current time step.

    Checks the current step plus/minus *window* steps to account for
    clock skew and slow user entry.

    Args:
        secret_b32:  Base32-encoded shared secret.
        code:        The TOTP code to verify (as a string).
        digits:      Number of digits expected (default 6).
        interval:    Time step in seconds (default 30).
        window:      Verification window in steps each direction (default 1).

    Returns:
        True if the code is valid for any step in the window.
    """
    secret = base64.b32decode(secret_b32, casefold=True)
    counter = int(time.time()) // interval
    for i in range(-window, window + 1):
        expected = _hotp(secret, counter + i, digits)
        # Constant-time comparison to prevent timing attacks
        if hmac.compare_digest(expected, code):
            return True
    return False


# ── Secret management ────────────────────────────────────────────────────────


def generate_secret() -> str:
    """Generate a random base32-encoded TOTP secret.

    Uses 20 random bytes (160 bits), which matches the HOTP recommended
    secret length (RFC 4226 Section 4).

    Returns:
        Base32-encoded secret string (without padding).
    """
    raw = os.urandom(20)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def is_valid_secret(secret_b32: str) -> bool:
    """Check if a string is a valid base32 TOTP secret.

    Returns:
        True if the string can be base32-decoded and has at least
        10 bytes of entropy (minimum for security).
    """
    try:
        raw = base64.b32decode(secret_b32, casefold=True)
        return len(raw) >= 10
    except (ValueError, TypeError):
        return False


# ── QR code URI ──────────────────────────────────────────────────────────────


def otpauth_uri(
    secret_b32: str,
    label: str,
    issuer: str = "KTC Mail",
    *,
    digits: int = 6,
    interval: int = 30,
) -> str:
    """Generate an ``otpauth://`` URI for QR code enrollment.

    Compatible with Google Authenticator, Authy, 1Password, etc.

    Args:
        secret_b32:  Base32-encoded shared secret.
        label:       User-facing label (e.g. ``admin@example.com``).
        issuer:      Issuer name shown in the authenticator app.
        digits:      Number of digits (default 6).
        interval:    Time step in seconds (default 30).

    Returns:
        ``otpauth://totp/{issuer}:{label}?secret=...&issuer=...``
    """
    # Re-encode without padding for the URI (some authenticators are picky)
    padded = secret_b32
    pad = len(secret_b32) % 8
    if pad:
        padded += "=" * (8 - pad)
    encoded_secret = base64.b32encode(base64.b32decode(padded)).decode("ascii").rstrip("=")

    params = (
        f"secret={encoded_secret}"
        f"&issuer={quote(issuer)}"
        f"&algorithm=SHA1"
        f"&digits={digits}"
        f"&period={interval}"
    )
    return f"otpauth://totp/{quote(issuer)}:{quote(label)}?{params}"
