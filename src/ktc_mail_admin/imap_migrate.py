"""Dependency-free IMAP mailbox migration (replaces the external imapsync binary).

Copies mail from a source IMAP server into a destination IMAP server (typically
the local Dovecot) on a per-mailbox, per-UID basis, preserving flags and
internal date. A state file records which source UIDs were already copied so a
interrupted migration can resume without duplicating messages.

Uses only the Python standard library (imaplib) — no third-party tools.
"""
from __future__ import annotations

import imaplib
import json
import re
import socket
import ssl
import time
from pathlib import Path

DEFAULT_STATE_DIR = Path("/var/lib/ktc-mail")


def _open(host: str, port: int | None, user: str, password: str,
          ssl: bool, starttls: bool) -> imaplib.IMAP4:
    """Open an authenticated IMAP connection."""
    if ssl:
        port = port or 993
        ctx = ssl.create_default_context()
        conn = imaplib.IMAP4_SSL(host, port, ssl_context=ctx)
    else:
        port = port or 143
        conn = imaplib.IMAP4(host, port)
        if starttls:
            conn.starttls()
    conn.login(user, password)
    return conn


def _list_mailboxes(conn: imaplib.IMAP4) -> list[str]:
    """Return selectable mailbox names (skips \\Noselect)."""
    out: list[str] = []
    typ, data = conn.list()
    if typ != "OK" or not data:
        return out
    for raw in data:
        if not raw:
            continue
        line = raw.decode("utf-8", "replace")
        # flags are wrapped in parens, e.g. (\HasNoChildren) "/" "INBOX"
        m = re.search(r'\((.*?)\)\s+("[^"]*"|\S+)\s+(".*"|\S+)\s*$', line)
        if not m:
            continue
        flags = m.group(1)
        name = m.group(3).strip().strip('"')
        if "\\Noselect" in flags or "\\NonExistent" in flags:
            continue
        out.append(name)
    return out


def _uids(conn: imaplib.IMAP4, mbx: str) -> list[int]:
    """Return the list of UIDs in *mbx* (empty if mailbox absent)."""
    typ, _ = conn.select(mbx, readonly=True)
    if typ != "OK":
        return []
    typ, data = conn.uid("search", None, "ALL")
    if typ != "OK" or not data or not data[0]:
        return []
    return [int(u) for u in data[0].split()]


def _parse_flags_date(raw: str) -> tuple[str, str | None]:
    """Extract (FLAGS, INTERNALDATE) from an IMAP fetch response fragment."""
    flags = ""
    fm = re.search(r"FLAGS\s*\(([^)]*)\)", raw)
    if fm:
        flags = "(" + fm.group(1).strip() + ")"
    date = None
    dm = re.search(r'INTERNALDATE\s+"([^"]+)"', raw)
    if dm:
        date = dm.group(1)
    return flags, date


def _fetch_message(conn: imaplib.IMAP4, uid: int) -> tuple[bytes, str, str | None] | None:
    """Fetch (rfc822 bytes, flags, internaldate) for one UID."""
    typ, data = conn.uid("fetch", uid, "(RFC822 FLAGS INTERNALDATE)")
    if typ != "OK" or not data:
        return None
    body: bytes | None = None
    flags = ""
    date = None
    for part in data:
        if isinstance(part, tuple):
            raw = part[0].decode("utf-8", "replace")
            if isinstance(part[1], (bytes, bytearray)):
                body = bytes(part[1])
                f, d = _parse_flags_date(raw)
                flags, date = f, d
    if body is None:
        return None
    return body, flags, date


def migrate_mailbox(src: imaplib.IMAP4, dst: imaplib.IMAP4, mbx: str,
                    copied: set[int]) -> tuple[int, int]:
    """Copy missing UIDs of *mbx* from src to dst. Returns (copied, skipped)."""
    # ensure the destination mailbox exists
    if dst.select(mbx, readonly=True)[0] != "OK":
        dst.create(mbx)
    src_uids = _uids(src, mbx)
    todo = [u for u in src_uids if u not in copied]
    copied_count = 0
    for uid in todo:
        msg = _fetch_message(src, uid)
        if msg is None:
            continue
        body, flags, date = msg
        dst.append(mbx, flags, date, body)
        copied.add(uid)
        copied_count += 1
    return copied_count, len(src_uids) - copied_count


def run_migration(args) -> int:
    """CLI entry: migrate one user's mail from a source IMAP to a destination.

    Expected args attributes: src_host, src_user, src_password, src_port,
    src_ssl, src_starttls, dst_host, dst_user, dst_password, dst_port,
    dst_ssl, dst_starttls, state, dry_run.
    """
    state_path = Path(args.state) if args.state else \
        DEFAULT_STATE_DIR / f"migrate-{args.dst_user.replace('@', '_')}.json"
    state: dict[str, list[int]] = {}
    if state_path.exists():
        try:
            state = json.loads(state_path.read_text())
        except (ValueError, OSError):
            state = {}

    if args.dry_run:
        print(f"[dry-run] would migrate {args.src_user}@{args.src_host} "
              f"-> {args.dst_user}@{args.dst_host}; state={state_path}")
        return 0

    src = _open(args.src_host, args.src_port, args.src_user, args.src_password,
                args.src_ssl, args.src_starttls)
    dst = _open(args.dst_host, args.dst_port, args.dst_user, args.dst_password,
                args.dst_ssl, args.dst_starttls)
    try:
        mailboxes = _list_mailboxes(src)
        total = 0
        for mbx in mailboxes:
            copied_set = set(state.get(mbx, []))
            before = len(copied_set)
            n, _ = migrate_mailbox(src, dst, mbx, copied_set)
            if n:
                state[mbx] = sorted(copied_set)
                total += n
                print(f"[migrate] {mbx}: +{n} (total {len(copied_set)})")
            else:
                print(f"[migrate] {mbx}: up to date ({before} already copied)")
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(json.dumps(state, indent=2))
        print(f"[migrate] done: {total} message(s) copied. state={state_path}")
        return 0
    except (imaplib.IMAP4.error, socket.error, ssl.SSLError) as exc:
        print(f"migration error: {exc}", file=__import__("sys").stderr)
        return 1
    finally:
        try:
            src.logout()
        except Exception:
            pass
        try:
            dst.logout()
        except Exception:
            pass
