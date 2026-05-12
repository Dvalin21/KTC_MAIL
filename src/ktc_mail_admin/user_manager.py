#!/usr/bin/env python3
"""KTC Mail — mail user account management.

Data structure: one line per user in Dovecot passwd-file format.
No database. No SQL. No abstractions.

passwd-file format (colon-separated):
  user:password:uid:gid:(gecos):home:(shell):extra

Our lines:
  email:{SHA512-CRYPT}$6$salt$hash:5000:5000::/var/mail/%d/%n:/usr/sbin/nologin::userdb_quota_rule=*:storage=1G

Also maintains Postfix virtual_alias and virtual_mbx maps so
Postfix knows which recipients are valid and where to deliver.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import Any

PASSWD_FILE = Path("/etc/dovecot/passwd")
ALIAS_FILE = Path("/etc/postfix/virtual_alias")
MBX_FILE = Path("/etc/postfix/virtual_mbx")


# ── Helpers ────────────────────────────────────────────────────────────


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
    """Hash password via doveadm. Canonical tool, don't reimplement."""
    result = subprocess.run(
        ["doveadm", "pw", "-s", "SHA512-CRYPT", "-p", password],
        capture_output=True, text=True, check=True,
    )
    return result.stdout.strip()


def _read_lines(path: Path) -> list[str]:
    """Read file, return lines. Returns empty list if file missing."""
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8").splitlines(keepends=True)


def _write_lines(path: Path, lines: list[str]) -> None:
    """Write lines to file atomically."""
    tmp = path.with_suffix(".tmp")
    tmp.write_text("".join(lines), encoding="utf-8")
    tmp.chmod(0o644)
    tmp.rename(path)


def _dovecot_reload() -> None:
    """Signal Dovecot to reload passwd-file."""
    subprocess.run(
        ["dovecot", "reload"],
        capture_output=True, check=False,
    )


# ── CRUD operations ────────────────────────────────────────────────────


def user_add(
    email: str,
    password: str | None = None,
    quota: str = "1G",
    dry_run: bool = False,
) -> int:
    """Add a mail user. Returns 0 on success, 1 on error."""
    if "@" not in email:
        print(f"error: '{email}' is not a valid email address", file=sys.stderr)
        return 1

    existing = _read_lines(PASSWD_FILE)
    emails = {
        _parse_passwd(l)["email"]
        for l in existing
        if _parse_passwd(l) is not None
    }
    if email in emails:
        print(f"error: user '{email}' already exists", file=sys.stderr)
        return 1

    if dry_run:
        print(f"dry-run: would add user '{email}' (quota: {quota})")
        return 0

    if password is None:
        import getpass
        password = getpass.getpass(f"Password for {email}: ")
        confirm = getpass.getpass("Confirm: ")
        if password != confirm:
            print("error: passwords do not match", file=sys.stderr)
            return 1
        if not password:
            print("error: password cannot be empty", file=sys.stderr)
            return 1

    hash_str = _hash_password(password)

    # Append to passwd file
    line = _format_line(email, hash_str, quota) + "\n"
    existing.append(line)
    _write_lines(PASSWD_FILE, existing)

    # Update Postfix alias map (user@domain → same for local delivery)
    alias_lines = _read_lines(ALIAS_FILE)
    alias_lines.append(f"{email} {email}\n")
    _write_lines(ALIAS_FILE, alias_lines)

    # Update Postfix mailbox map (user@domain → domain/user/)
    domain, user = email.split("@", 1)
    mbx_lines = _read_lines(MBX_FILE)
    mbx_lines.append(f"{email} {domain}/{user}/\n")
    _write_lines(MBX_FILE, mbx_lines)

    # Ensure maildir exists
    maildir = Path(f"/var/mail/{domain}/{user}")
    maildir.mkdir(parents=True, exist_ok=True)

    _dovecot_reload()
    print(f"added: {email} (quota: {quota})")
    return 0


def user_delete(email: str, dry_run: bool = False) -> int:
    """Remove a mail user."""
    if "@" not in email:
        print(f"error: '{email}' is not a valid email address", file=sys.stderr)
        return 1

    old_lines = _read_lines(PASSWD_FILE)
    new_lines = [l for l in old_lines if not l.startswith(email + ":")]

    if len(new_lines) == len(old_lines):
        print(f"error: user '{email}' not found", file=sys.stderr)
        return 1

    if dry_run:
        print(f"dry-run: would remove user '{email}'")
        return 0

    _write_lines(PASSWD_FILE, new_lines)

    # Remove from alias and mailbox maps
    for f in (ALIAS_FILE, MBX_FILE):
        lines = _read_lines(f)
        lines = [l for l in lines if not l.startswith(email + " ")]
        _write_lines(f, lines)

    _dovecot_reload()
    print(f"removed: {email}")
    return 0


def user_list(dry_run: bool = False) -> int:
    """List all mail users."""
    _ = dry_run  # no-op, list is always read-only
    lines = _read_lines(PASSWD_FILE)
    users = []
    for l in lines:
        parsed = _parse_passwd(l)
        if parsed:
            users.append(parsed)

    if not users:
        print("no mail users")
        return 0

    print(f"{'email':40s} {'quota':8s}")
    print("-" * 48)
    for u in sorted(users, key=lambda x: x["email"]):
        print(f"{u['email']:40s} {u['quota']:8s}")
    return 0


def user_passwd(email: str, dry_run: bool = False) -> int:
    """Change a user's password."""
    if "@" not in email:
        print(f"error: '{email}' is not a valid email address", file=sys.stderr)
        return 1

    lines = _read_lines(PASSWD_FILE)
    new_lines = []
    found = False
    for l in lines:
        if l.startswith(email + ":"):
            found = True
            if dry_run:
                print(f"dry-run: would change password for '{email}'")
                new_lines.append(l)
                continue
            import getpass
            pw = getpass.getpass(f"New password for {email}: ")
            confirm = getpass.getpass("Confirm: ")
            if pw != confirm:
                print("error: passwords do not match", file=sys.stderr)
                return 1
            if not pw:
                print("error: password cannot be empty", file=sys.stderr)
                return 1
            hash_str = _hash_password(pw)
            parsed = _parse_passwd(l)
            if parsed is None:
                new_lines.append(l)
                continue
            quota = parsed.get("quota", "1G")
            new_lines.append(_format_line(email, hash_str, quota) + "\n")
        else:
            new_lines.append(l)

    if not found:
        print(f"error: user '{email}' not found", file=sys.stderr)
        return 1

    if not dry_run:
        _write_lines(PASSWD_FILE, new_lines)
        _dovecot_reload()
        print(f"password changed: {email}")

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
    if args.user_cmd in ("del", "passwd"):
        return handler(**common, email=args.email)
    if args.user_cmd in ("list",):
        return handler(**common)
    return 1
