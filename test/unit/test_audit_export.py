"""Unit tests for remote audit-log export (Phase 6 deliverable).

Exercises parse_line, syslog framing, and idempotent
position tracking (run_once forwards only new lines + advances
the cursor; a second run with no new lines forwards 0).
The syslog senders are mocked at the socket boundary via a
fake socket so no real network is touched.
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ktc_mail_admin import audit_export as ax


def _write_log(tmp_path, lines):
    p = tmp_path / "audit.log"
    p.write_text("".join(f"{l}\n" for l in lines), encoding="utf-8")
    return p


def test_parse_line():
    T = "\t"
    ev = ax.parse_line(
        f"2026-01-01T00:00:00{T}mfa_enable{T}admin@example.com{T}"
        f"127.0.0.1{T}MFA enabled"
    )
    assert ev.ts == "2026-01-01T00:00:00"
    assert ev.action == "mfa_enable"
    assert ev.actor == "admin@example.com"
    assert ev.detail == "MFA enabled"
    assert ev.source == "127.0.0.1"
    assert ev.syslog_priority() == 5 + 8 * 4  # notice


def test_parse_ignores_blank_and_comment():
    assert ax.parse_line("") is None
    assert ax.parse_line("# comment") is None


def test_syslog_framing():
    ev = ax.AuditEvent(
        ts="2026-01-01T00:00:00", action="login", actor="a@b.com",
        detail="ok", source="1.2.3.4",
    )
    pkt = ev.to_syslog("mail1")
    assert pkt.startswith(b"<") and pkt.endswith(b"\n")
    assert b"action=login actor=a@b.com" in pkt
    assert b"mail1" in pkt


def test_run_once_forwards_new_then_idempotent(tmp_path):
    log = _write_log(tmp_path, [
        "2026-01-01T00:00:00\tlogin\tadmin@example.com\t127.0.0.1\tok",
        "2026-01-01T00:00:01\tmfa_enable\tadmin@example.com\t127.0.0.1\tMFA",
    ])

    sent = []

    class _FakeSock:
        def __init__(self, *a, **k):
            pass

        def settimeout(self, t):
            pass

        def sendto(self, data, dest):
            sent.append(data)
            return len(data)

        def close(self):
            pass

    import socket as _sock
    real_dgram = _sock.socket
    _sock.socket = lambda *a, **k: _FakeSock()

    try:
        n1 = ax.run_once(log, syslog_host="logs.example.com", syslog_port=514)
        # second run: no new lines -> 0 forwarded
        n2 = ax.run_once(log, syslog_host="logs.example.com", syslog_port=514)
    finally:
        _sock.socket = real_dgram

    assert n1 == 2
    assert n2 == 0  # cursor advanced, nothing new
    assert len(sent) == 2  # one datagram per event


def test_run_once_with_new_lines_after_first(tmp_path):
    log = _write_log(tmp_path, [
        "2026-01-01T00:00:00\tlogin\tadmin@example.com\t127.0.0.1\tok",
    ])
    sent = []

    class _FakeSock:
        def __init__(self, *a, **k):
            pass

        def settimeout(self, t):
            pass

        def sendto(self, data, dest):
            sent.append(data)
            return len(data)

        def close(self):
            pass

    import socket as _sock
    real = _sock.socket
    _sock.socket = lambda *a, **k: _FakeSock()
    try:
        ax.run_once(log, syslog_host="h", syslog_port=514)
        # append a new line, re-run
        with log.open("a", encoding="utf-8") as f:
            f.write("2026-01-01T00:05:00\tlogout\tadmin@example.com\t127.0.0.1\tbye\n")
        n = ax.run_once(log, syslog_host="h", syslog_port=514)
    finally:
        _sock.socket = real

    assert n == 1  # only the new line
