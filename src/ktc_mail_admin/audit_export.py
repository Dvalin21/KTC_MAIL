"""KTC Mail — remote audit-log / syslog / SIEM export (Phase 6 deliverable).

The admin audit log (``STATE_DIR/audit.log``) is append-only local
text.  For real detection you need it off-box.  This module
tails the audit log and ships NEW lines to:
  - a syslog server (UDP 514 or TCP) in RFC 5424 framing, and/or
  - an HTTPS SIEM/webhook endpoint (JSON per line).

Design rules (Linus: data structures first, minimal):
  - No daemon of its own — run from a systemd timer (10 min).
  - Position is tracked in a sidecar state file so re-runs only
    forward deltas (idempotent, crash-safe via atomic write).
  - Lines are parsed into (ts, action, actor, detail, source) so the
    syslog PRI and SIEM payload are structured, not raw echo.
  - Failures are reported, never silent (no fake-success).
"""

from __future__ import annotations

import json
import os
import socket
import ssl
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

# RFC 5424 facility: 4 = auth; severity: 5 = notice, 6 = info.
_SYSLOG_FACILITY = 4
_DEFAULT_SYSLOG_PORT = 514
_STATE_SUFFIX = ".export.pos"


@dataclass
class AuditEvent:
    """One parsed audit-log line."""

    ts: str
    action: str
    actor: str
    detail: str
    source: str

    def syslog_priority(self) -> int:
        sev = 5 if self.action.startswith(("login", "mfa", "break")) else 6
        return _SYSLOG_FACILITY * 8 + sev

    def to_syslog(self, hostname: str = "ktc-mail") -> bytes:
        # RFC 5424: <PRI>VERSION TS HOST APP PID MSG
        pri = self.syslog_priority()
        msg = f"action={self.action} actor={self.actor} src={self.source} {self.detail}"
        return (
            f"<{pri}>1 {self.ts} {hostname} ktc-mail - - {msg}"
        ).encode("utf-8", "replace") + b"\n"

    def to_siem(self) -> dict[str, Any]:
        return {
            "ts": self.ts,
            "action": self.action,
            "actor": self.actor,
            "source": self.source,
            "detail": self.detail,
            "host": "ktc-mail",
        }


def parse_line(line: str) -> AuditEvent | None:
    """Parse one audit-log line into an AuditEvent.

    Expected format (from admin_server.audit_log, tab-separated):
        ISO_TS \t ACTION \t ACTOR \t CLIENT_IP \t DETAILS
    The CLIENT_IP doubles as the event *source* (where the action
    originated).  Returns None for blank/comment lines.
    """
    line = line.rstrip("\n")
    if not line or line.startswith("#"):
        return None
    parts = line.split("\t")
    if len(parts) < 5:
        # Best-effort: treat the whole line as detail.
        return AuditEvent(
            ts=parts[0] if parts else "",
            action="unknown",
            actor="",
            detail=line,
            source="",
        )
    return AuditEvent(
        ts=parts[0], action=parts[1], actor=parts[2],
        detail=parts[4], source=parts[3],  # CLIENT_IP = source
    )


def iter_new(audit_path: Path, *, after: int = 0) -> Iterator[tuple[int, AuditEvent]]:
    """Yield (byte_offset, event) for lines at/after *after* bytes.

    *after* is the byte offset of the end of the last line sent
    (i.e. where to resume).  Only NEW lines are yielded.
    """
    if not audit_path.exists():
        return
    with audit_path.open("r", encoding="utf-8", errors="replace") as f:
        f.seek(after)
        offset = after
        for line in f:
            offset += len(line.encode("utf-8", "replace"))
            ev = parse_line(line)
            if ev is not None:
                yield offset, ev


def _load_pos(state_path: Path) -> int:
    if not state_path.exists():
        return 0
    try:
        return int(state_path.read_text(encoding="utf-8").strip() or "0")
    except (OSError, ValueError):
        return 0


def _save_pos(state_path: Path, pos: int) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = state_path.with_suffix(state_path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    try:
        os.write(fd, str(pos).encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    tmp.rename(state_path)


def send_syslog(
    events: list[AuditEvent],
    host: str,
    port: int = _DEFAULT_SYSLOG_PORT,
    *,
    tcp: bool = False,
    tls: bool = False,
    hostname: str = "ktc-mail",
    timeout: float = 5.0,
) -> int:
    """Ship *events* to a syslog server. Returns count sent.

    UDP is fire-and-forget (no delivery guarantee — fine for audit).
    TCP (optionally TLS) is connection-per-batch with a timeout.
    Raises on hard failure so the caller can treat it as a real error.
    """
    if not events:
        return 0
    payload = b"".join(e.to_syslog(hostname) for e in events)
    if tcp:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if tls:
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
        try:
            sock.connect((host, port))
            sock.sendall(payload)
        finally:
            sock.close()
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            # UDP: send each datagram separately (syslog framing is per-line)
            for e in events:
                sock.sendto(e.to_syslog(hostname), (host, port))
        finally:
            sock.close()
    return len(events)


def send_siem(
    events: list[AuditEvent],
    url: str,
    *,
    timeout: float = 10.0,
    headers: dict[str, str] | None = None,
) -> int:
    """POST *events* as JSON to a SIEM/webhook endpoint. Returns count.

    Uses only the standard library (urllib).  One request per batch.
    Raises on non-2xx so the caller knows delivery failed.
    """
    if not events:
        return 0
    import urllib.request

    body = json.dumps([e.to_siem() for e in events]).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status // 100 != 2:
            raise RuntimeError(f"SIEM endpoint returned HTTP {resp.status}")
    return len(events)


def run_once(
    audit_path: Path,
    *,
    syslog_host: str | None = None,
    syslog_port: int = _DEFAULT_SYSLOG_PORT,
    syslog_tcp: bool = False,
    syslog_tls: bool = False,
    siem_url: str | None = None,
    state_path: Path | None = None,
) -> int:
    """Export new audit lines once. Returns number of events exported.

    Idempotent: tracks byte position in *state_path* (defaults to
    ``audit_path`` + ``.export.pos``).  On ANY forwarding
    failure the position is NOT advanced, so the next run retries.
    """
    if state_path is None:
        state_path = audit_path.with_suffix(
            audit_path.suffix + _STATE_SUFFIX
        )
    pos = _load_pos(state_path)
    batch: list[tuple[int, AuditEvent]] = list(iter_new(audit_path, after=pos))
    if not batch:
        return 0

    events = [ev for _, ev in batch]
    new_pos = batch[-1][0]

    forwarded = 0
    if syslog_host:
        forwarded += send_syslog(
            events, syslog_host, syslog_port,
            tcp=syslog_tcp, tls=syslog_tls,
        )
    if siem_url:
        forwarded += send_siem(events, siem_url)

    # Only advance position if we actually had a destination and it succeeded.
    if forwarded > 0:
        _save_pos(state_path, new_pos)
    return forwarded
