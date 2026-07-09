"""Unit tests for MFA recovery codes (Phase 5 deliverable).

Pure stdlib logic — no mail server, no network. Proves:
  - codes generate unique, well-formed base32 strings
  - hashes are deterministic
  - a code verifies once then is consumed (one-time use)
  - a reused/expired-equivalent code is rejected after consume
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ktc_mail_admin.mfa import (
    generate_recovery_codes,
    hash_recovery_code,
    verify_and_consume_recovery_code,
)


def test_generate_count_and_unique():
    codes = generate_recovery_codes(5)
    assert len(codes) == 5
    assert len(set(codes)) == 5  # unique
    for c in codes:
        assert isinstance(c, str) and len(c) >= 5
        # base32 alphabet (RFC 4648), no padding
        assert all(ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for ch in c)


def test_hash_deterministic_and_case_insensitive():
    h1 = hash_recovery_code("ABCDEF234")
    h2 = hash_recovery_code("abcdef234")
    assert h1 == h2  # stored form is case-folded
    assert h1 == hash_recovery_code("ABCDEF234")


def test_consume_once_then_reject():
    codes = generate_recovery_codes(3)
    hashes = [hash_recovery_code(c) for c in codes]
    ok, remaining = verify_and_consume_recovery_code(hashes, codes[1])
    assert ok is True
    assert len(remaining) == 2
    assert hash_recovery_code(codes[1]) not in remaining

    # Reuse the same code -> must fail (one-time use)
    ok2, remaining2 = verify_and_consume_recovery_code(remaining, codes[1])
    assert ok2 is False
    assert len(remaining2) == 2


def test_unknown_code_rejected():
    hashes = [hash_recovery_code(c) for c in generate_recovery_codes(2)]
    ok, remaining = verify_and_consume_recovery_code(hashes, "ZZZZZZZZ")
    assert ok is False
    assert remaining == hashes  # unchanged on failure


def test_empty_code_rejected():
    hashes = [hash_recovery_code(c) for c in generate_recovery_codes(1)]
    ok, remaining = verify_and_consume_recovery_code(hashes, "")
    assert ok is False
    assert remaining == hashes
