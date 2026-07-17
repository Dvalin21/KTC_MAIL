"""Reporting helpers (user_manager) — graceful degradation without Dovecot."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

import ktc_mail_admin.user_manager as um
from ktc_mail_admin.user_manager import (
    _human_to_bytes,
    _bytes_to_human,
    _parse_quota,
    domain_stats,
    user_stats,
)


def test_human_to_bytes_units():
    assert _human_to_bytes("256M") == 256 * 1024**2
    assert _human_to_bytes("1G") == 1024**3
    assert _human_to_bytes("unlimited") == -1
    assert _human_to_bytes("bogus") == -1
    assert _human_to_bytes("") == -1


def test_bytes_to_human():
    assert _bytes_to_human(-1) == "—"
    assert _bytes_to_human(0) == "0B"
    assert _bytes_to_human(1024) == "1.0K"
    assert _bytes_to_human(1024**3) == "1.0G"


def test_parse_quota_default():
    assert _parse_quota("a:b:5000:5000::/h:/s::userdb_quota_rule=*:storage=5G") == "5G"
    assert _parse_quota("a:b") == "1G"


def test_domain_stats_empty_without_dovecot(monkeypatch, tmp_path):
    # No passwd file -> no domains, no crash.
    monkeypatch.setattr(um, "PASSWD_FILE", tmp_path / "passwd")
    monkeypatch.setattr(um, "_store_kind", lambda: "maildir")
    monkeypatch.setattr(um, "load_profile", lambda: None)
    assert domain_stats() == []


def test_domain_stats_counts_and_quota(monkeypatch, tmp_path):
    pf = tmp_path / "passwd"
    pf.write_text(
        "a@example.com:{x}:5000:5000::/h:/s::userdb_quota_rule=*:storage=1G\n"
        "b@example.com:{y}:5000:5000::/h:/s::userdb_quota_rule=*:storage=256M\n"
        "c@other.com:{z}:5000:5000::/h:/s::userdb_quota_rule=*:storage=unlimited\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(um, "PASSWD_FILE", pf)
    monkeypatch.setattr(um, "_store_kind", lambda: "maildir")
    monkeypatch.setattr(um, "load_profile", lambda: None)
    rows = {r["domain"]: r for r in domain_stats()}
    assert rows["example.com"]["mailboxes"] == 2
    assert rows["example.com"]["quota_bytes"] == 1024**3 + 256 * 1024**2
    assert rows["example.com"]["usage_display"] == "—"
    assert rows["other.com"]["quota_display"] == "∞"


def test_user_stats_degrades_without_dovecot(monkeypatch):
    # Simulate doveadm missing entirely -> every field is "—", no raise.
    import subprocess

    def boom(*a, **k):
        raise FileNotFoundError("doveadm")

    monkeypatch.setattr(subprocess, "run", boom)
    stats = user_stats("a@example.com")
    assert stats["messages"] == "—"
    assert stats["last_login"] == "—"
