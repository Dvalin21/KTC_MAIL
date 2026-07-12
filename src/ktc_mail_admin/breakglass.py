"""KTC Mail — break-glass emergency operator access (Phase 5 deliverable).

Break-glass is the designated escape hatch when normal admin MFA is
unavailable (lost TOTP device, dead authenticator app, locked-out
operator).  It is NOT a backdoor: every use is written to the
append-only audit log and produces a SINGLE-USE credential that the
operator must rotate immediately after use.

Design rules (Linus: data structures first, minimal):
  - One token, one use.  Stored hashed (SHA-256) in a 0400 file.
  - Short TTL (default 15 min).  Expired or used tokens are rejected.
  - Emitted token is shown ONCE on stdout (never persisted in plaintext).
  - Requires explicit human acknowledgement (--i-understand) so it can't
    be run by a stray cron job or CI.
  - Audited with the requesting operator identity + reason.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import atomic_write_text

# Token parity with mfa.py recovery codes: 5 random bytes -> base32.
_TOKEN_BYTES = 5
_DEFAULT_TTL = 900  # 15 minutes
_BREAKGLASS_PATH = Path("/etc/ktc-mail/breakglass.token")
_TOKEN_RE = r"^[A-Z2-7]{5,12}$"


@dataclass
class BreakGlassToken:
    """A single-use emergency operator token (in-memory only)."""

    token: str
    expires_at: int
    operator: str
    reason: str

    def is_expired(self, now: int | None = None) -> bool:
        now = now if now is not None else int(time.time())
        return now >= self.expires_at


def _hash_token(token: str) -> str:
    """Stored form of a break-glass token (SHA-256 hex, case-folded)."""
    return hashlib.sha256(token.strip().upper().encode("utf-8")).hexdigest()


def _read_stored() -> dict[str, Any] | None:
    """Read the current break-glass token record, or None if none."""
    if not _BREAKGLASS_PATH.exists():
        return None
    try:
        import json

        return json.loads(_BREAKGLASS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _write_stored(record: dict[str, Any]) -> None:
    """Atomically write the token record (0400)."""
    import json

    atomic_write_text(_BREAKGLASS_PATH, json.dumps(record, indent=2), mode=0o400)


def issue(
    operator: str,
    reason: str,
    *,
    ttl: int = _DEFAULT_TTL,
    now: int | None = None,
) -> BreakGlassToken:
    """Issue a single-use break-glass operator token.

    Args:
        operator: identity of the human requesting access (accountable).
        reason:   why normal auth is unavailable (audited).
        ttl:      seconds the token stays valid (default 900).
        now:       injectable clock for testing.

    Returns:
        BreakGlassToken with the plaintext token (show ONCE).
    """
    now = now if now is not None else int(time.time())
    token = base64.b32encode(secrets.token_bytes(_TOKEN_BYTES)).decode("ascii").rstrip("=")
    record = {
        "token_hash": _hash_token(token),
        "issued_at": now,
        "expires_at": now + ttl,
        "operator": operator,
        "reason": reason,
        "used": False,
    }
    _write_stored(record)
    return BreakGlassToken(
        token=token, expires_at=record["expires_at"], operator=operator, reason=reason
    )


def consume(token: str, *, now: int | None = None) -> tuple[bool, str]:
    """Validate + consume a break-glass token.

    Returns:
        (ok, operator) — ok True only if the token is the single
        unexpired, unused record.  On success the record is wiped
        (one use).  On any failure returns (False, "").
    """
    now = now if now is not None else int(time.time())
    rec = _read_stored()
    if not rec or rec.get("used"):
        return False, ""
    if rec.get("expires_at", 0) <= now:
        return False, ""
    target = _hash_token(token)
    if not hmac.compare_digest(rec.get("token_hash", ""), target):
        return False, ""
    operator = rec.get("operator", "unknown")
    # Single use: wipe the record.
    try:
        _BREAKGLASS_PATH.unlink()
    except OSError:
        pass
    return True, operator


def clear() -> None:
    """Revoke any outstanding break-glass token (e.g. after use/rotation)."""
    try:
        _BREAKGLASS_PATH.unlink()
    except OSError:
        pass
