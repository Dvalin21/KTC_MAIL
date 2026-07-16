#!/usr/bin/env python3
"""KTC Mail — mail user account management.

Two mailbox stores, selected by SetupProfile.mailbox_store:
  - "maildir" (default): Dovecot passwd-file + per-user Maildir.
  - "sql":     PostgreSQL-backed mailbox store (dovecot-sql.conf.ext).
              Credentials + per-user quota live in the `mailboxes` table.
              Postfix recipient maps + the Maildir are still maintained
              locally so delivery and recipient validation keep working.

No over-abstraction: the two stores share small helpers; the public
CRUD functions branch on the active store.

passwd-file format (colon-separated):
  email:{SHA512-CRYPT}$6$salt$hash:5000:5000::/var/mail/%d/%n:/usr/sbin/nologin::userdb_quota_rule=*:storage=1G
"""

from __future__ import annotations

import argparse
import getpass
import subprocess
import sys
from pathlib import Path
from typing import Any

from .config import (
    atomic_write_text,
    load_profile,
    get_mailbox_db_password,
    MAILBOX_DB_NAME,
    MAILBOX_DB_ROLE,
)

PASSWD_FILE = Path("/etc/dovecot/passwd")
ALIAS_FILE = Path("/etc/postfix/virtual_alias")
MBX_FILE = Path("/etc/postfix/virtual_mbx")

# Characters that would break passwd-file parsing or Postfix map lookup.
_INVALID_EMAIL_CHARS = (":", "\n", "\r", "\0")


def _validate_email(email: str) -> str | None:
    """Reject dangerous characters; return sanitized lower-case email or None."""
    if not isinstance(email, str) or not email.strip():
        return None
    if any(c in email for c in _INVALID_EMAIL_CHARS):
        return None
    return email.lower().strip()


# ── passwd-file helpers ──────────────────────────────────────────────────


def _parse_passwd(line: str) -> dict[str, str] | None:
    """Parse a Dovecot passwd-file line. Returns None if blank/comment."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parts = line.split(":")
    if len(parts) < 2:
        return None
    return {
        "email": parts[0],
        "password": parts[1],
        "uid": parts[2] if len(parts) > 2 else "5000",
        "gid": parts[3] if len(parts) > 3 else "5000",
        "home": parts[5] if len(parts) > 5 else "",
        "quota": _parse_quota(line),
    }


def _parse_quota(line: str) -> str:
    """Extract quota from extra fields. Default 1G."""
    if "userdb_quota_rule=*:storage=" in line:
        for part in line.split("::"):
            if part.startswith("userdb_quota_rule=*:storage="):
                return part.split("=")[-1]
    return "1G"


def _format_line(email: str, password_hash: str, quota: str) -> str:
    """Format one passwd-file line."""
    domain, user = email.split("@", 1)
    home = f"/var/mail/{domain}/{user}"
    return (
        f"{email}:{password_hash}:5000:5000::{home}:/usr/sbin/nologin"
        f"::userdb_quota_rule=*:storage={quota}"
    )


def _hash_password(password: str) -> str:
    """Hash password via doveadm. Canonical tool, don't reimplement.

    Password is passed via stdin (-p was removed) to avoid /proc/<pid>/cmdline
    exposure (MEDIUM-16). doveadm reads from stdin when -p is omitted.
    """
    result = subprocess.run(
        ["doveadm", "pw", "-s", "SHA512-CRYPT"],
        input=password + "\n",
        capture_output=True, text=True, check=True,
    )
    return result.stdout.strip()


def _read_lines(path: Path) -> list[str]:
    """Read file, return lines. Returns empty list if file missing."""
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8").splitlines(keepends=True)


def _write_lines(path: Path, lines: list[str]) -> None:
    """Write lines to file atomically with fsync (central helper)."""
    atomic_write_text(path, "".join(lines), mode=0o640)


def _dovecot_reload() -> None:
    """Signal Dovecot to reload passwd-file."""
    subprocess.run(
        ["dovecot", "reload"],
        capture_output=True, check=False,
    )


# ── store selection + shared non-store helpers ───────────────────────────


def _store_kind() -> str:
    """Return the active mailbox store ('sql' or 'maildir')."""
    profile = load_profile()
    if profile is None:
        return "maildir"
    return profile.mailbox_store


def _write_postfix_maps(email: str) -> None:
    """Record the recipient in Postfix alias + mailbox maps."""
    alias_lines = _read_lines(ALIAS_FILE)
    alias_lines.append(f"{email} {email}\n")
    _write_lines(ALIAS_FILE, alias_lines)

    domain, user = email.split("@", 1)
    mbx_lines = _read_lines(MBX_FILE)
    mbx_lines.append(f"{email} {domain}/{user}/\n")
    _write_lines(MBX_FILE, mbx_lines)


def _ensure_maildir(email: str) -> None:
    """Create the per-user Maildir on disk."""
    domain, user = email.split("@", 1)
    Path(f"/var/mail/{domain}/{user}").mkdir(parents=True, exist_ok=True)


def _prompt_password(sanitized: str, confirm: bool = True) -> str | None:
    """Prompt for a password (optionally confirm). Returns None on invalid."""
    pw = getpass.getpass(f"Password for {sanitized}: ")
    if confirm:
        if getpass.getpass("Confirm: ") != pw:
            print("error: passwords do not match", file=sys.stderr)
            return None
    if not pw:
        print("error: password cannot be empty", file=sys.stderr)
        return None
    return pw


# ── SQL store (psycopg2, lazily imported so maildir works without it) ───


def _mailbox_db_conn():
    """Open a connection to the mailbox SQL store, or None if unavailable."""
    pw = get_mailbox_db_password()
    if not pw:
        return None
    try:
        import psycopg2
    except ImportError:
        return None
    try:
        return psycopg2.connect(
            host="127.0.0.1",
            dbname=MAILBOX_DB_NAME,
            user=MAILBOX_DB_ROLE,
            password=pw,
            connect_timeout=5,
        )
    except Exception:  # noqa: BLE001 - connection failure is a runtime condition
        return None


def _sql_exec(query: str, params: tuple = ()) -> int:
    """Execute a write query. Returns 0 on success, 1 on error."""
    conn = _mailbox_db_conn()
    if conn is None:
        print("error: mailbox SQL store unavailable", file=sys.stderr)
        return 1
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(query, params)
        return 0
    except Exception as e:  # noqa: BLE001 - surface, don't crash the CLI
        print(f"error: mailbox SQL store: {e}", file=sys.stderr)
        return 1
    finally:
        conn.close()


def _sql_fetchall(query: str, params: tuple = ()) -> list:
    conn = _mailbox_db_conn()
    if conn is None:
        return []
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(query, params)
                return cur.fetchall()
    finally:
        conn.close()


def _sql_fetchone(query: str, params: tuple = ()):
    conn = _mailbox_db_conn()
    if conn is None:
        return None
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(query, params)
                return cur.fetchone()
    finally:
        conn.close()


def _sql_exists(email: str) -> bool:
    return _sql_fetchone(
        "SELECT 1 FROM mailboxes WHERE email = %s", (email,)
    ) is not None


def _sql_user_add(email: str, password_hash: str, quota: str) -> int:
    local, domain = email.split("@", 1)
    maildir = f"/var/mail/{domain}/{local}"
    return _sql_exec(
        "INSERT INTO mailboxes(email, domain, password_hash, maildir, quota) "
        "VALUES (%s, %s, %s, %s, %s)",
        (email, domain, password_hash, maildir, quota),
    )


def _sql_user_delete(email: str) -> int:
    return _sql_exec("DELETE FROM mailboxes WHERE email = %s", (email,))


def _sql_user_passwd(email: str, password_hash: str) -> int:
    return _sql_exec(
        "UPDATE mailboxes SET password_hash = %s WHERE email = %s",
        (password_hash, email),
    )


def _sql_user_list() -> list[tuple[str, str]]:
    rows = _sql_fetchall(
        "SELECT email, quota FROM mailboxes WHERE active = TRUE ORDER BY email"
    )
    return [(r[0], r[1]) for r in rows]


# ── CRUD operations ──────────────────────────────────────────────────────


def user_add(
    email: str,
    password: str | None = None,
    quota: str = "1G",
    dry_run: bool = False,
) -> int:
    """Add a mail user. Returns 0 on success, 1 on error."""
    sanitized = _validate_email(email)
    if sanitized is None:
        print(f"error: '{email}' is not a valid email address", file=sys.stderr)
        return 1

    if _store_kind() == "sql":
        exists = _sql_exists(sanitized)
    else:
        exists = sanitized in {
            _parse_passwd(l)["email"]
            for l in _read_lines(PASSWD_FILE)
            if _parse_passwd(l) is not None
        }
    if exists:
        print(f"error: user '{sanitized}' already exists", file=sys.stderr)
        return 1

    if dry_run:
        print(f"dry-run: would add user '{sanitized}' (quota: {quota})")
        return 0

    if password is None:
        password = _prompt_password(sanitized)
        if password is None:
            return 1
    hash_str = _hash_password(password)

    if _store_kind() == "sql":
        if _sql_user_add(sanitized, hash_str, quota):
            return 1
    else:
        # passwd-file backend (skip when LDAP is the auth source).
        profile = load_profile()
        if profile is None or profile.auth_backend != "ldap":
            lines = _read_lines(PASSWD_FILE)
            lines.append(_format_line(sanitized, hash_str, quota) + "\n")
            _write_lines(PASSWD_FILE, lines)

    _write_postfix_maps(sanitized)
    _ensure_maildir(sanitized)
    _dovecot_reload()
    print(f"added: {sanitized} (quota: {quota})")
    return 0


def user_delete(email: str, dry_run: bool = False) -> int:
    """Remove a mail user."""
    sanitized = _validate_email(email)
    if sanitized is None:
        print(f"error: '{email}' is not a valid email address", file=sys.stderr)
        return 1

    if _store_kind() == "sql":
        exists = _sql_exists(sanitized)
    else:
        exists = any(
            l.startswith(sanitized + ":")
            for l in _read_lines(PASSWD_FILE)
        )
    if not exists:
        print(f"error: user '{sanitized}' not found", file=sys.stderr)
        return 1

    if dry_run:
        print(f"dry-run: would remove user '{sanitized}'")
        return 0

    if _store_kind() == "sql":
        if _sql_user_delete(sanitized):
            return 1
    else:
        lines = _read_lines(PASSWD_FILE)
        lines = [l for l in lines if not l.startswith(sanitized + ":")]
        _write_lines(PASSWD_FILE, lines)

    for f in (ALIAS_FILE, MBX_FILE):
        lines = _read_lines(f)
        lines = [l for l in lines if not l.startswith(sanitized + " ")]
        _write_lines(f, lines)

    _dovecot_reload()
    print(f"removed: {sanitized}")
    return 0


def user_list(dry_run: bool = False) -> int:
    """List all mail users."""
    _ = dry_run  # no-op, list is always read-only
    if _store_kind() == "sql":
        users = _sql_user_list()
    else:
        lines = _read_lines(PASSWD_FILE)
        users = [
            (p["email"], p["quota"])
            for l in lines
            if (p := _parse_passwd(l)) is not None
        ]

    if not users:
        print("no mail users")
        return 0

    print(f"{'email':40s} {'quota':8s}")
    print("-" * 48)
    for email, quota in sorted(users, key=lambda x: x[0]):
        print(f"{email:40s} {quota:8s}")
    return 0


def user_passwd(email: str, password: str | None = None,
                dry_run: bool = False) -> int:
    """Change a user's password."""
    sanitized = _validate_email(email)
    if sanitized is None:
        print(f"error: '{email}' is not a valid email address", file=sys.stderr)
        return 1

    if _store_kind() == "sql":
        exists = _sql_exists(sanitized)
    else:
        exists = any(
            l.startswith(sanitized + ":")
            for l in _read_lines(PASSWD_FILE)
        )
    if not exists:
        print(f"error: user '{sanitized}' not found", file=sys.stderr)
        return 1

    if dry_run:
        print(f"dry-run: would change password for '{sanitized}'")
        return 0

    if password is None:
        password = _prompt_password(sanitized)
        if password is None:
            return 1
    elif not password:
        print("error: password cannot be empty", file=sys.stderr)
        return 1
    hash_str = _hash_password(password)

    if _store_kind() == "sql":
        if _sql_user_passwd(sanitized, hash_str):
            return 1
    else:
        lines = _read_lines(PASSWD_FILE)
        new_lines = []
        for l in lines:
            if l.startswith(sanitized + ":"):
                parsed = _parse_passwd(l)
                quota = parsed.get("quota", "1G") if parsed else "1G"
                new_lines.append(_format_line(sanitized, hash_str, quota) + "\n")
            else:
                new_lines.append(l)
        _write_lines(PASSWD_FILE, new_lines)

    _dovecot_reload()
    print(f"password changed: {sanitized}")
    return 0


# ── CLI handler ────────────────────────────────────────────────────────


def cmd_user(args: argparse.Namespace) -> int:
    """Dispatch user subcommands."""
    dispatch = {
        "add": user_add,
        "del": user_delete,
        "list": user_list,
        "passwd": user_passwd,
    }
    handler = dispatch.get(args.user_cmd)
    if handler is None:
        return 1

    common: dict[str, Any] = {"dry_run": args.dry_run}
    if args.user_cmd in ("add",):
        kw = {**common, "email": args.email}
        if args.password:
            kw["password"] = args.password
        kw["quota"] = args.quota
        return handler(**kw)
    if args.user_cmd == "del":
        return handler(**common, email=args.email)
    if args.user_cmd == "passwd":
        kw = {**common, "email": args.email}
        if args.password:
            kw["password"] = args.password
        return handler(**kw)
    if args.user_cmd in ("list",):
        return handler(**common)
    return 1
