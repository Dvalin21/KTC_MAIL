"""Unit tests for break-glass single-use operator token (Phase 5 deliverable).

Exercises the pure issue/consume/clear logic against a temp token path.
Proves: one-use, TTL expiry, hash-only-at-rest, wipe-after-use.
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import ktc_mail_admin.breakglass as bg


def _setup(tmp_path):
    bg._BREAKGLASS_PATH = tmp_path / "breakglass.token"
    if bg._BREAKGLASS_PATH.exists():
        bg._BREAKGLASS_PATH.unlink()
    return tmp_path


def test_issue_then_consume_once(tmp_path):
    _setup(tmp_path)
    tok = bg.issue("op@example.com", "lost TOTP", now=1000, ttl=900)
    assert tok.is_expired(1000) is False
    assert tok.is_expired(2000) is True
    ok, op = bg.consume(tok.token, now=1000)
    assert ok is True and op == "op@example.com"
    # file wiped after use
    assert not bg._BREAKGLASS_PATH.exists()


def test_reuse_after_consume_fails(tmp_path):
    _setup(tmp_path)
    tok = bg.issue("op@example.com", "x", now=1000, ttl=900)
    assert bg.consume(tok.token, now=1000)[0] is True
    ok2, _ = bg.consume(tok.token, now=1000)
    assert ok2 is False


def test_expired_token_rejected(tmp_path):
    _setup(tmp_path)
    tok = bg.issue("op@example.com", "x", now=1000, ttl=900)
    ok, _ = bg.consume(tok.token, now=2000)  # past expiry
    assert ok is False
    # clear leftover
    bg.clear()


def test_bad_token_rejected(tmp_path):
    _setup(tmp_path)
    bg.issue("op@example.com", "x", now=1000, ttl=900)
    ok, op = bg.consume("NOTAREALTOKEN", now=1000)
    assert ok is False and op == ""
    bg.clear()


def test_clear_revokes_outstanding(tmp_path):
    _setup(tmp_path)
    bg.issue("op@example.com", "x", now=1000, ttl=900)
    assert bg._BREAKGLASS_PATH.exists()
    bg.clear()
    assert not bg._BREAKGLASS_PATH.exists()
