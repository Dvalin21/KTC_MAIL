#!/usr/bin/env python3
"""KTC Mail — admin web interface (Phase 5 deliverable).

FastAPI + Jinja2 admin server for day-to-day mail server management.

Routes:
  GET  /              Dashboard (protected)
  GET  /users         User management page (protected)
  POST /users/add     Add mailbox (protected)
  POST /users/del     Delete mailbox (protected)
  POST /users/passwd  Change password (protected)
  GET  /login         Login form
  POST /login         Authenticate
  GET  /logout        Clear session
  GET  /api/status    JSON health endpoint (protected)

Auth:
  Session-based via Starlette SessionMiddleware.
  Admin password hashed with hashlib.scrypt.
  Initial password generated on first start, printed to stderr.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import binascii
import collections
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader, pass_context
from starlette.middleware.sessions import SessionMiddleware
from pathlib import Path as _Path

from . import user_manager as um
from . import mfa as mfa_mod
from . import webauthn_mgr as wa
from .qr import qr_svg_b64
from .config import (
    CONFIG_DIR,
    SETUP_PATH,
    STATE_DIR,
    SECRETS_PATH,
    TLS_STATE_PATH,
    DNS_STATE_PATH,
    DKIM_DIR,
    BACKUP_STATE_PATH,
    CERT_NAME,
    read_json,
    save_json_private,
    atomic_write_bytes,
    atomic_write_text,
    setup_logging,
    SetupProfile,
    Branding,
    _EMAIL_RE,
    _valid_email,
)

# ── Quarantine helpers (module-level: pure + subprocess, unit-testable) ────────
# rspamd's `add header` action delivers spam with X-Spam-Flag: YES, which the
# global sieve (spam-to-junk.sieve) files into Junk. These list those messages
# from rspamd history and release / confirm them.


def _first_rcpt(row: dict) -> str:
    rcpt = row.get("rcpt_smtp") or row.get("rcpt") or []
    if isinstance(rcpt, list) and rcpt:
        return rcpt[0]
    if isinstance(rcpt, str):
        return rcpt
    return ""


def parse_rspamc_history(stdout: str) -> list[dict]:
    """Parse `rspamc -j get history` JSON into delivered-spam rows.

    Defensive: tolerates bare-list vs {"rows":[...]}, and field-name variants
    (message-id / message_id, sender_smtp / from, rcpt_smtp / rcpt).
    """
    if not stdout or not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict):
        rows = data.get("rows", [])
    else:
        rows = []
    kept: list[dict] = []
    for r in rows:
        action = str(r.get("action") or "").lower()
        if action not in ("add header", "rewrite subject"):
            continue
        kept.append({
            "message_id": str(r.get("message-id") or r.get("message_id") or ""),
            "from": str(r.get("sender_smtp") or r.get("sender_mime")
                        or r.get("from") or ""),
            "to": _first_rcpt(r),
            "subject": str(r.get("subject") or ""),
            "score": r.get("score", 0),
            "action": str(r.get("action") or ""),
            "time": r.get("unix_time") or r.get("time") or 0,
        })
    return kept


def rspamc_history_rows() -> list[dict]:
    """Run `rspamc -j get history`; return delivered-spam rows (empty if absent)."""
    rspamc = shutil.which("rspamc")
    if not rspamc:
        return []
    try:
        out = subprocess.run(
            [rspamc, "-j", "get", "history"],
            capture_output=True, text=True, timeout=10,
        )
    except (subprocess.SubprocessError, OSError):
        return []
    if out.returncode != 0:
        return []
    return parse_rspamc_history(out.stdout)


def quarantine_release(message_id: str, user: str) -> dict:
    """Move a message from Junk to INBOX for the recipient (best-effort)."""
    doveadm = shutil.which("doveadm")
    moved = False
    if doveadm and user:
        try:
            search = subprocess.run(
                [doveadm, "search", "-u", user, "mailbox", "Junk",
                 "header", "Message-ID", message_id],
                capture_output=True, text=True, timeout=15,
            )
            uids = [ln.split()[-1] for ln in search.stdout.splitlines() if ln.strip()]
            if uids:
                subprocess.run(
                    [doveadm, "move", "-u", user, "INBOX",
                     "mailbox", "Junk", *uids],
                    capture_output=True, text=True, timeout=15,
                )
                moved = True
        except (subprocess.SubprocessError, OSError):
            pass
    return {"moved": moved}


def quarantine_confirm(message_id: str, user: str) -> dict:
    """Train rspamd that this Junk message is spam (best-effort)."""
    doveadm = shutil.which("doveadm")
    rspamc = shutil.which("rspamc")
    learned = False
    if doveadm and rspamc and user:
        try:
            fetch = subprocess.run(
                [doveadm, "fetch", "-u", user, "text", "mailbox", "Junk",
                 "header", "Message-ID", message_id],
                capture_output=True, text=True, timeout=15,
            )
            if fetch.returncode == 0 and fetch.stdout.strip():
                res = subprocess.run(
                    [rspamc, "learn_spam"], input=fetch.stdout,
                    capture_output=True, text=True, timeout=10,
                )
                learned = res.returncode == 0
        except (subprocess.SubprocessError, OSError):
            pass
    return {"learned": learned}


def mailbox_auth(email: str, password: str) -> bool:
    """Authenticate a mailbox user via Dovecot's own auth backend.

    Uses `doveadm auth test` so it works for both passwd-file and SQL stores
    without re-implementing hash verification. Returns True on success.
    ponytail: password is passed as a CLI arg (brief, localhost-only exposure);
    if Dovecot ever exposes a stdin/IMAP-auth path, switch to that.
    """
    doveadm = shutil.which("doveadm")
    if not doveadm or not email or not password:
        return False
    try:
        res = subprocess.run(
            [doveadm, "auth", "test", email, password],
            capture_output=True, text=True, timeout=10,
        )
    except (subprocess.SubprocessError, OSError):
        return False
    return res.returncode == 0


def build_spam_policy_ucl(reject: float, add_header: float,
                          greylist: float | None = None) -> str:
    """Build the rspamd `setting:user:` / `setting:domain:` UCL override string."""
    parts = [f"reject={reject};", f'"add header"={add_header};']
    if greylist is not None:
        parts.append(f"greylist={greylist};")
    return "{actions{" + "".join(parts) + "}}"


# ── Module-level paths ───────────────────────────────────────────────────────

ADMIN_HASH_PATH = CONFIG_DIR / "admin-hash.json"
AUDIT_LOG_PATH = STATE_DIR / "audit.log"
TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"

# ── Logging ───────────────────────────────────────────────────────────────────

logger = logging.getLogger("ktc-mail.admin")


# ── Audit logging ─────────────────────────────────────────────────────────────


def audit_log(
    action: str,
    actor: str,
    details: str,
    client_ip: str = "",
) -> None:
    """Append one audit event to the audit log.

    Format (tab-separated for easy grep/cut):
        timestamp  action  actor  client_ip  details

    The log is append-only in STATE_DIR/audit.log (640 permissions).
    No rotation — the admin is expected to set up logrotate if desired.
    """
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ip = client_ip or "-"
    line = f"{ts}\t{action}\t{actor}\t{ip}\t{details}\n"
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line)
    except OSError:
        logger.exception("writing audit log to %s", AUDIT_LOG_PATH)


# ── Admin account management ─────────────────────────────────────────────────
#
# The admin account is stored as a JSON dict in admin-hash.json:
#   {
#     "password_hash": "scrypt$...",
#     "role": "admin",         # admin | operator | readonly
#     "mfa_secret": "B32...",  # base32 TOTP secret (or null)
#     "mfa_enabled": false,
#     "updated_at": 1234567890
#   }
# ─────────────────────────────────────────────────────────────────

# Role hierarchy (higher number = more privileges)
ROLE_HIERARCHY: dict[str, int] = {
    "admin": 100,
    "operator": 50,
    "readonly": 10,
    "user": 1,
}
DEFAULT_ROLE = "admin"


def admin_password_path() -> Path:
    """Return the admin password hash file path."""
    return ADMIN_HASH_PATH


def hash_password(password: str) -> str:
    """Hash a password using hashlib.scrypt.

    Returns a self-describing string: "scrypt$salt$hash"
    where salt and hash are base64-encoded.
    """
    salt = os.urandom(32)
    hashed = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=16384, r=8, p=1,
        dklen=64,
    )
    return f"scrypt${base64.b64encode(salt).decode()}${base64.b64encode(hashed).decode()}"


def verify_password(password: str, stored: str) -> bool:
    """Verify a password against a stored scrypt hash string."""
    if not stored or not password:
        return False

    parts = stored.split("$")
    if parts[0] != "scrypt" or len(parts) != 3:
        return False

    try:
        salt = base64.b64decode(parts[1])
        expected = base64.b64decode(parts[2])
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=16384, r=8, p=1,
            dklen=64,
        )
        return hmac.compare_digest(expected, actual)
    except (ValueError, binascii.Error):
        return False


def load_admin_account() -> dict[str, Any]:
    """Load the admin account from disk.

    Returns a dict with keys: password_hash, email, role, mfa_secret,
    mfa_enabled, updated_at.  Missing keys get sensible defaults.

    Backward-compatible: existing files with only ``password_hash``
    will get default role=admin and MFA disabled.
    """
    default: dict[str, Any] = {
        "password_hash": "",
        "email": "",
        "role": DEFAULT_ROLE,
        "mfa_secret": None,
        "mfa_enabled": False,
        "mfa_recovery_codes": [],  # list[str] of SHA-256 hex (Phase 5)
        "session_version": 0,
        "updated_at": 0,
    }
    if not ADMIN_HASH_PATH.exists():
        return default
    try:
        data = read_json(ADMIN_HASH_PATH)
        default.update(data)
        return default
    except (OSError, ValueError, json.JSONDecodeError):
        return default


def save_admin_account(account: dict[str, Any]) -> None:
    """Save the admin account to disk."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "password_hash": account.get("password_hash", ""),
        "email": account.get("email", ""),
        "role": account.get("role", DEFAULT_ROLE),
        "mfa_secret": account.get("mfa_secret"),
        "mfa_enabled": bool(account.get("mfa_enabled", False)),
        "mfa_recovery_codes": account.get("mfa_recovery_codes", []),
        "session_version": account.get("session_version", 0),
        "updated_at": int(time.time()),
    }
    save_json_private(ADMIN_HASH_PATH, payload)


def load_admin_hash() -> str | None:
    """Load the stored admin password hash. Returns None if not configured."""
    return load_admin_account().get("password_hash") or None


def save_admin_hash(password_hash: str) -> None:
    """Store the admin password hash to disk (preserves other fields)."""
    account = load_admin_account()
    account["password_hash"] = password_hash
    save_admin_account(account)


def bootstrap_admin_password() -> str:
    """Generate an initial admin password and store the account.

    Returns the plaintext password (caller MUST print it for the admin).
    Sets role=admin, MFA disabled.
    """
    plaintext = secrets.token_urlsafe(24)
    hashed = hash_password(plaintext)
    save_admin_account({
        "password_hash": hashed,
        "email": "",
        "role": "admin",
        "mfa_secret": None,
        "mfa_enabled": False,
    })
    return plaintext


def admin_is_configured() -> bool:
    """Check if an admin password has been set up."""
    return ADMIN_HASH_PATH.exists()


SERVICE_CACHE: dict[str, tuple[float, dict[str, str]]] = {}
SERVICE_CACHE_TTL = 5  # seconds


def _load_profile() -> SetupProfile | None:
    """Load the setup profile from disk. Returns None if not found."""
    if not SETUP_PATH.exists():
        return None
    try:
        return SetupProfile.from_dict(read_json(SETUP_PATH))
    except (OSError, ValueError, json.JSONDecodeError):
        logger.exception("loading setup profile")
        return None


def _all_service_status() -> dict[str, str]:
    """Get status of all tracked services in one systemctl call.

    Uses `systemctl show -p ActiveState --value` to get all states
    in a single subprocess invocation. Results cached for
    SERVICE_CACHE_TTL seconds.
    """
    now = time.monotonic()
    cached = SERVICE_CACHE.get("status")
    if cached and (now - cached[0]) < SERVICE_CACHE_TTL:
        return cached[1]

    svcs = ["postfix", "dovecot", "rspamd", "nginx", "redis-server",
            "ktc-mail-olefy", "ktc-mail-mta-sts"]
    try:
        result = subprocess.run(
            ["systemctl", "show", "-p", "ActiveState", "--value", *svcs],
            capture_output=True, text=True, timeout=5,
        )
    except (subprocess.TimeoutExpired, OSError, subprocess.SubprocessError):
        logger.exception("checking service status")
        svcs_fallback = {s: "unknown" for s in svcs}
        SERVICE_CACHE["status"] = (now, svcs_fallback)
        return svcs_fallback

    lines = result.stdout.strip().splitlines()
    services: dict[str, str] = {}
    for i, svc in enumerate(svcs):
        state = lines[i].strip() if i < len(lines) else "unknown"
        # Normalize: ActiveState returns lowercase, but keep as-is
        services[svc] = state if state else "unknown"

    SERVICE_CACHE["status"] = (now, services)
    return services


def _read_state(path: Path) -> dict[str, Any]:
    """Read a JSON state file. Returns empty dict on failure."""
    if not path.exists():
        return {}
    try:
        return read_json(path)
    except (OSError, ValueError, json.JSONDecodeError):
        logger.exception("reading state file %s", path)
        return {}


def _queue_depth() -> int:
    """Count queued messages via postqueue -p.

    Parses the summary line format: "N requests in M active queues"
    """
    try:
        result = subprocess.run(
            ["postqueue", "-p"],
            capture_output=True, text=True, timeout=5,
        )
    except (subprocess.TimeoutExpired, OSError, subprocess.SubprocessError):
        logger.exception("running postqueue")
        return -1

    if result.returncode != 0:
        return -1
    output = result.stdout.strip()
    if not output or "mail queue is empty" in output:
        return 0
    # Count queue IDs: each starts with a hex string
    # e.g. "A1B2C3D4E5     1234  Fri May 12 12:00:00  user@dom"
    count = 0
    for line in output.splitlines():
        stripped = line.strip()
        if stripped and len(stripped) > 10 and stripped[0] in "0123456789ABCDEF":
            # queue IDs are hex, 10+ chars, followed by whitespace+size+date
            # Check it's not a summary line (which contains words)
            parts = stripped.split()
            if len(parts) >= 5 and parts[1].isdigit():
                count += 1
    return count


def _user_count() -> int:
    """Count active mail users from the Dovecot passwd file."""
    lines = um._read_lines(um.PASSWD_FILE)
    return sum(1 for l in lines if um._parse_passwd(l) is not None)


# ── Mail queue parser ─────────────────────────────────────────────────────────

# Postfix postqueue -p header format:
#   <hex_id> <size> <weekday> <month> <day> <time>  <sender>
# The time and sender are separated by 2+ spaces (fixed-width columns).
# Recipients appear on continuation lines indented with spaces.
_QUEUE_HEADER_RE = re.compile(
    # Queue IDs are base-36 (A-Z,0-9), 10+ chars, always uppercase in
    # postqueue -p output. The date format is always 4 tokens
    # (weekday month day time) followed by 2+ spaces before the sender.
    r"^([0-9A-Z]{10,})\s+(\d+)\s+"                # queue_id + size
    r"(\S+)\s+(\S+)\s+(\d+)\s+(\S+)\s{2,}"        # weekday month day time + 2+ spaces
    r"(\S.*)$"                                     # sender
)


def _parse_queue() -> list[dict[str, Any]]:
    """Run postqueue -p and return structured queue entries.

    Each entry:
      queue_id, size, arrival_time, sender, recipients[]

    Returns empty list for empty queue, or on error.
    The summary line ("-- N Kbytes in M Requests") is discarded.
    """
    try:
        result = subprocess.run(
            ["postqueue", "-p"],
            capture_output=True, text=True, timeout=5,
        )
    except (subprocess.TimeoutExpired, OSError, subprocess.SubprocessError):
        logger.exception("running postqueue")
        return []

    output = result.stdout.strip()
    if not output or "mail queue is empty" in output:
        return []

    entries: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None

    for line in output.splitlines():
        # Skip header separator line
        if line.startswith("-Queue ID-"):
            continue
        # Skip summary line
        if line.startswith("-- "):
            continue

        stripped = line.rstrip()

        # Queue entry header: hex ID + size + date + sender
        m = _QUEUE_HEADER_RE.match(stripped)
        if m:
            # Flush previous entry if we were building one
            if current is not None:
                entries.append(current)
            current = {
                "queue_id": m.group(1),
                "size": int(m.group(2)),
                "arrival_time": f"{m.group(3)} {m.group(4)} {m.group(5)} {m.group(6)}",
                "sender": m.group(7),
                "recipients": [],
            }
            continue

        # Recipient continuation line (indented — non-empty and non-header)
        if current is not None and stripped:
            recipient = stripped.strip()
            if recipient not in current["recipients"]:
                current["recipients"].append(recipient)

    # Flush last entry
    if current is not None:
        entries.append(current)

    return entries


# ── DKIM helpers ──────────────────────────────────────────────────────────────


def _list_dkim_keys(domain: str) -> list[dict[str, Any]]:
    """List DKIM key files and compute their DNS records."""
    if not DKIM_DIR.exists():
        return []
    keys: list[dict[str, Any]] = []
    for f in sorted(DKIM_DIR.glob("*.private")):
        selector = f.stem
        dns_record = ""
        try:
            pub = subprocess.run(
                ["openssl", "rsa", "-pubout", "-outform", "DER"],
                input=f.read_bytes(),
                capture_output=True, timeout=5,
            )
            if pub.returncode == 0:
                b64 = base64.b64encode(pub.stdout).decode()
                dns_record = f"v=DKIM1; k=rsa; p={b64}"
        except (subprocess.SubprocessError, OSError, binascii.Error):
            logger.exception("extracting DKIM public key for %s", selector)
        st = f.stat()
        keys.append({
            "selector": selector,
            "dns_record": dns_record,
            "size": st.st_size,
            "modified": int(st.st_mtime),
        })
    return keys


# ── Log helpers ────────────────────────────────────────────────────────────────


def _tail_file(path: Path, n: int = 100) -> str:
    """Return last N lines of a file by reading from the end.

    Reads in 4 KB blocks from EOF to avoid loading the entire file.
    Falls back to "(file not found)" or "(error)" messages.
    """
    if not path.exists():
        return "(file not found)"
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(0, 2)  # EOF
            size = f.tell()
            block_size = 4096
            data: list[str] = []
            pos = size
            while len(data) < n and pos > 0:
                read_size = min(block_size, pos)
                pos -= read_size
                f.seek(pos)
                chunk = f.read(read_size)
                data = chunk.splitlines() + data
            return "\n".join(data[-n:])
    except Exception as exc:
        logger.exception("tailing %s", path)
        return f"(error reading file: {exc})"


# ── Log sources for the /logs viewer ───────────────────────────────────────────
# Each entry is either a systemd unit (read via journalctl) or a file on disk.
# Grouped so the UI can show "what is doing what, for what service" plainly.
LOG_SOURCES: dict[str, dict[str, str]] = {
    # KTC Mail services
    "ktc-setup":      {"label": "Setup wizard",        "group": "KTC Mail", "unit": "ktc-mail-setup.service"},
    "ktc-admin":      {"label": "Admin portal",        "group": "KTC Mail", "unit": "ktc-mail-admin.service"},
    "ktc-acme":       {"label": "ACME / TLS",          "group": "KTC Mail", "unit": "ktc-mail-acme-renew.service"},
    "ktc-backup":     {"label": "Backup",              "group": "KTC Mail", "unit": "ktc-mail-backup.service"},
    "ktc-olefy":      {"label": "Olefy (macro scan)",  "group": "KTC Mail", "unit": "ktc-mail-olefy.service"},
    "ktc-mta-sts":    {"label": "MTA-STS resolver",    "group": "KTC Mail", "unit": "ktc-mail-mta-sts.service"},
    "ktc-firewall":   {"label": "Firewall monitor",    "group": "KTC Mail", "unit": "ktc-mail-firewall-monitor.service"},
    "ktc-exporter":   {"label": "Metrics exporter",    "group": "KTC Mail", "unit": "ktc-mail-exporter.service"},
    "ktc-rate-limit": {"label": "Rate limiter",        "group": "KTC Mail", "unit": "ktc-mail-rate-limit.service"},
    "ktc-audit-exp":  {"label": "Audit export",        "group": "KTC Mail", "unit": "ktc-mail-audit-export.service"},
    # Mail stack
    "postfix":        {"label": "Postfix (SMTP)",      "group": "Mail stack", "unit": "postfix.service"},
    "dovecot":        {"label": "Dovecot (IMAP)",      "group": "Mail stack", "unit": "dovecot.service"},
    "rspamd":         {"label": "Rspamd (anti-spam)",  "group": "Mail stack", "unit": "rspamd.service"},
    "nginx":          {"label": "Nginx (web)",        "group": "Mail stack", "unit": "nginx.service"},
    # File-based
    "audit":          {"label": "Admin audit log",     "group": "Files", "file": "audit"},
    "mail":           {"label": "System mail log",     "group": "Files", "file": "mail"},
}


def _read_log_source(source_key: str, n: int = 100) -> str:
    """Return log text for a LOG_SOURCES key.

    Journal units are read via `journalctl -u <unit> -n N` (subprocess with a
    hard timeout — never block the request thread). File sources reuse
    _tail_file. Returns a plain-text string either way.
    """
    spec = LOG_SOURCES.get(source_key)
    if not spec:
        return "(unknown log source)"
    if "unit" in spec:
        try:
            result = subprocess.run(
                ["journalctl", "-u", spec["unit"], "-n", str(n),
                 "--no-pager", "--output=short"],
                capture_output=True, text=True, timeout=10,
            )
        except subprocess.TimeoutExpired:
            return "(journalctl timed out — service may be busy)"
        except FileNotFoundError:
            return "(journalctl not available on this host)"
        if result.returncode != 0:
            return f"(journalctl error: {result.stderr.strip() or 'exit ' + str(result.returncode)})"
        return result.stdout or f"(no log output for {spec['label']})"
    # file source
    if spec.get("file") == "audit":
        return _tail_file(AUDIT_LOG_PATH, n)
    return _tail_file(Path("/var/log/mail.log"), n)


# ── Certificate helpers ────────────────────────────────────────────────────────


def _cert_info_from_path(cert_path: Path) -> dict[str, Any]:
    """Parse certificate metadata using openssl.

    Returns a dict with keys: end_date, issuer, subject, sans, fingerprint.
    Empty dict if the cert file does not exist or parsing fails.
    Uses a SINGLE openssl call for all fields.
    """
    info: dict[str, Any] = {}
    if not cert_path.exists():
        return info
    try:
        # Single openssl call for all fields
        r = subprocess.run(
            [
                "openssl", "x509", "-in", str(cert_path), "-noout",
                "-enddate", "-issuer", "-subject",
                "-ext", "subjectAltName",
                "-fingerprint", "-sha256",
            ],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode != 0:
            logger.warning("openssl x509 failed: %s", r.stderr)
            return info

        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("notAfter="):
                info["end_date"] = line.replace("notAfter=", "")
            elif line.startswith("issuer="):
                info["issuer"] = line.replace("issuer=", "")
            elif line.startswith("subject="):
                info["subject"] = line.replace("subject=", "")
            elif line.startswith("X509v3 Subject Alternative Name:"):
                # SANs may span multiple lines; capture the rest
                idx = r.stdout.index(line)
                info["sans"] = r.stdout[idx:].strip()
            elif line.startswith("SHA256 Fingerprint="):
                info["fingerprint"] = line.replace("SHA256 Fingerprint=", "")
    except (subprocess.SubprocessError, OSError, ValueError, IndexError):
        logger.exception("reading cert info from %s", cert_path)
    return info
    return info


def _cert_expiry_days(end_date_str: str) -> int | None:
    """Compute days until certificate expiry.

    Parses the openssl 'notAfter=' date format:
      "May 12 12:34:56 2026 GMT"
    Returns the number of days (0 if already expired) or None on parse
    failure.
    """
    try:
        expiry = datetime.strptime(end_date_str, "%b %d %H:%M:%S %Y %Z")
        now = datetime.utcnow()
        delta = expiry - now
        return max(0, delta.days)
    except (ValueError, TypeError):
        return None


# ── Login rate limiter (Redis-backed) ─────────────────────────────────────────
# Per-IP sliding window: max 5 failed attempts in 60 seconds.
# Uses Redis for multi-worker support. Falls back to in-memory if Redis unavailable.
_LOGIN_RATE_LIMIT = 5
_LOGIN_RATE_WINDOW = 60  # seconds
_login_attempts_fallback: dict[str, list[float]] = {}

_REDIS_URL = os.environ.get("KTC_ADMIN_REDIS", "redis://localhost:6379/0")
_redis_client = None


def _get_redis():
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    try:
        import redis
        _redis_client = redis.from_url(_REDIS_URL, socket_connect_timeout=2, socket_timeout=2, decode_responses=True)
        _redis_client.ping()
        return _redis_client
    except (ImportError, OSError):
        return None
    except Exception as exc:
        # redis module was loaded; catch RedisError if available
        try:
            import redis
            if isinstance(exc, redis.RedisError):
                return None
        except (ImportError, AttributeError):
            pass
        return None


def _login_rate_check(ip: str) -> bool:
    """Return True if this IP is currently rate-limited (blocked)."""
    now = time.time()
    window_start = now - _LOGIN_RATE_WINDOW
    r = _get_redis()
    if r:
        key = f"ktc:ratelimit:login:{ip}"
        # Remove old entries, count remaining
        r.zremrangebyscore(key, 0, window_start)
        count = r.zcard(key)
        return count >= _LOGIN_RATE_LIMIT
    # Fallback to in-memory
    attempts = _login_attempts_fallback.get(ip)
    if not attempts:
        return False
    _login_attempts_fallback[ip] = [t for t in attempts if t > window_start]
    return len(_login_attempts_fallback[ip]) >= _LOGIN_RATE_LIMIT


def _login_rate_record(ip: str) -> None:
    """Record a failed login attempt from *ip*."""
    now = time.time()
    r = _get_redis()
    if r:
        key = f"ktc:ratelimit:login:{ip}"
        r.zadd(key, {str(now): now})
        r.expire(key, _LOGIN_RATE_WINDOW + 10)
        return
    _login_attempts_fallback.setdefault(ip, []).append(now)


def _login_rate_clear(ip: str) -> None:
    """Clear failed attempt history for *ip* (on successful login)."""
    r = _get_redis()
    if r:
        key = f"ktc:ratelimit:login:{ip}"
        r.delete(key)
        return
    _login_attempts_fallback.pop(ip, None)


# ── FastAPI app setup ─────────────────────────────────────────────────────────


def create_app() -> FastAPI:
    """Create and configure the FastAPI admin application."""
    app = FastAPI(title="KTC Mail Admin")
    app.mount(
        "/static",
        StaticFiles(directory=str(_Path(__file__).resolve().parent / "static")),
        name="static",
    )

    # ── Session key ───────────────────────────────────────────────────
    # Generate a random key on first start, persist it so sessions
    # survive restarts. The key is unique per install, unlike a
    # deterministic hash of a known value.
    session_key: str = ""
    sk_path = CONFIG_DIR / "session-key"
    if sk_path.exists():
        try:
            session_key = sk_path.read_text(encoding="utf-8").strip()
        except OSError:
            pass
    if not session_key:
        session_key = secrets.token_hex(32)
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        try:
            # Atomic write with fsync to avoid race window
            atomic_write_text(sk_path, session_key, mode=0o600)
        except OSError:
            logger.exception("writing session key to %s", sk_path)

    # Allow env override for testing
    session_key = os.environ.get("KTC_ADMIN_SECRET", session_key)

    # Session cookie flags:
    #   - HttpOnly: always on (prevents JS access)
    #   - Secure:   on by default; disable via KTC_DEV=1 for local HTTP testing
    #   - SameSite: lax (prevents CSRF from external sites)
    # Starlette's SessionMiddleware hardcodes HttpOnly; we control Secure here.
    use_https = os.environ.get("KTC_DEV", "0") != "1"

    app.add_middleware(
        SessionMiddleware,
        secret_key=session_key,
        session_cookie="ktc_admin_session",
        max_age=86400,  # 24 hours
        same_site="lax",
        https_only=use_https,
    )

    # ── Security headers (CSP) ──────────────────────────────────────────
    # Defense-in-depth: limits what resources can load even if an XSS
    # vulnerability exists.
    #
    # Scripts: 'unsafe-inline' removed — all JS is the external /static/admin.js
    # bundle (confirm dialogs via addEventListener, no inline handlers).
    # Styles: 'unsafe-inline' kept — theming uses inline <style> blocks; no
    # user-controlled CSS is injected, so the risk is low. Tighten to a
    # hashed/nonced stylesheet only if external CSS is ever introduced.
    #
    # Target CSP (scripts already here):
    #   default-src 'self'
    #   script-src 'self'
    #   style-src 'self' 'unsafe-inline'
    #   img-src 'self' data:
    #   frame-ancestors 'none'
    #   form-action 'self'

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response = await call_next(request)
        if response.media_type and "text/html" in response.media_type:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; "
                "frame-ancestors 'none'; "
                "form-action 'self'"
            )
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
        return response

    # ── CSRF helper ────────────────────────────────────────────────────
    # Per-session CSRF token. Generated once per session, validated
    # on every POST request. Uses hmac.compare_digest to prevent
    # timing attacks against the token comparison.

    def get_csrf_token(request: Request) -> str:
        """Get or create a CSRF token for this session."""
        token = request.session.get("csrf_token")
        if not token:
            token = secrets.token_hex(32)
            request.session["csrf_token"] = token
        return token

    def validate_csrf(request: Request, form_token: str) -> bool:
        """Validate a submitted CSRF token against the session token."""
        session_token = request.session.get("csrf_token")
        if not session_token:
            return False
        return hmac.compare_digest(session_token, form_token)

    # ── Templates ──────────────────────────────────────────────────────
    _jinja_env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=True,
        cache_size=0,
    )
    templates = Jinja2Templates(env=_jinja_env)

    # Jinja2 filters
    def datetime_from_ts(timestamp: int) -> str:
        """Format a Unix timestamp as a human-readable date."""
        try:
            dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
            return dt.strftime("%Y-%m-%d %H:%M UTC")
        except (ValueError, OSError, OverflowError):
            return "unknown"
    templates.env.filters["datetime_from_ts"] = datetime_from_ts

    # ── Branding context (available to every template as `ui`) ──
    # ponytail: load once, cache; branding changes are rare. Falls back to
    # KTC Mail defaults when no profile/branding exists yet.
    _branding_cache: dict = {"ts": 0.0, "val": None}

    def _load_branding() -> "Branding":
        import time as _t
        now = _t.time()
        if _branding_cache["val"] is not None and now - _branding_cache["ts"] < 30:
            return _branding_cache["val"]
        prof = load_profile()
        b = prof.branding if prof else Branding()
        _branding_cache["val"] = b
        _branding_cache["ts"] = now
        return b

    @pass_context
    def _ui_global(context: Any) -> dict:
        b = _load_branding()
        name = b.org_name.strip() or "KTC"
        # Split "Acme Mail" -> ("Acme", "Mail") for the two-tone wordmark.
        parts = name.rsplit(" ", 1)
        if len(parts) == 2:
            brand_name, brand_suffix = parts[0], parts[1]
        else:
            brand_name, brand_suffix = name, ""
        return {
            "accent": b.effective_accent(),
            "brand_name": brand_name,
            "brand_suffix": brand_suffix,
            "logo_url": b.logo_url.strip(),
        }

    templates.env.globals["ui"] = _ui_global

    # ── Auth / RBAC helpers ────────────────────────────────────────────

    def _safe_redirect(path: str, *,
                       query: dict[str, str] | None = None,
                       status_code: int = 302) -> RedirectResponse:
        """Build a RedirectResponse with URL-encoded query parameters.

        Every user-controlled value passed in *query* is percent-encoded
        to prevent redirect parameter injection / response splitting.
        """
        url = path
        if query:
            encoded = urllib.parse.urlencode(query)
            url = f"{path}?{encoded}"
        return RedirectResponse(url=url, status_code=status_code)

    def login_redirect() -> RedirectResponse:
        return RedirectResponse(url="/login", status_code=302)

    def forbidden_response() -> HTMLResponse:
        return HTMLResponse(
            "<html><body><h1>403 Forbidden</h1>"
            "<p>Your account does not have permission for this action.</p>"
            "</body></html>",
            status_code=403,
        )

    def is_authenticated(request: Request) -> bool:
        if not request.session.get("authenticated"):
            return False
        # Session version check: invalidate sessions after MFA state change
        acct = load_admin_account()
        stored_version = acct.get("session_version", 0)
        session_version = request.session.get("session_version", -1)
        if session_version != stored_version:
            request.session.clear()
            return False
        return True

    def require_role(request: Request, min_role: str = "readonly") -> bool:
        """Check auth + minimum role level.

        Returns True if the user is authenticated and their role meets
        or exceeds *min_role*.  Returns False otherwise (caller should
        then return login_redirect() or forbidden_response()).
        """
        if not request.session.get("authenticated"):
            return False
        if not request.session.get("mfa_verified", True):
            # MFA is required but not yet verified — redirect to login
            return False
        user_role = request.session.get("role", "readonly")
        min_level = ROLE_HIERARCHY.get(min_role, 0)
        user_level = ROLE_HIERARCHY.get(user_role, 0)
        return user_level >= min_level

    def client_ip(request: Request) -> str:
        """Extract client IP from request, respecting X-Forwarded-For.

        Only trusts X-Forwarded-For when behind a known proxy.
        Configure trusted proxy IPs via KTC_TRUSTED_PROXIES env var
        (comma-separated CIDRs, e.g., '127.0.0.1/32,10.0.0.0/8').
        """
        # Check if we're behind a trusted proxy
        trusted_proxies = os.environ.get("KTC_TRUSTED_PROXIES", "")
        if request.client and trusted_proxies:
            import ipaddress
            client_ip_obj = ipaddress.ip_address(request.client.host)
            for net_str in trusted_proxies.split(","):
                net_str = net_str.strip()
                if net_str and client_ip_obj in ipaddress.ip_network(net_str):
                    # Behind trusted proxy — trust X-Forwarded-For
                    forwarded = request.headers.get("x-forwarded-for", "")
                    if forwarded:
                        return forwarded.split(",")[0].strip()
        # Not behind trusted proxy, or no X-Forwarded-For
        if request.client:
            return request.client.host or ""
        return ""

    def actor_email(request: Request) -> str:
        """Get the authenticated admin email from session."""
        return request.session.get("email", "unknown")

    def account_mfa_status() -> dict[str, Any]:
        """Get MFA + role status for the current admin account.

        Returns dict with keys: enabled, secret_present, otpauth_uri, role.
        The URI is only returned when MFA is being enrolled (not yet
        enabled but a secret exists).
        """
        acct = load_admin_account()
        enabled = bool(acct.get("mfa_enabled", False))
        secret = acct.get("mfa_secret")
        return {
            "enabled": enabled,
            "secret_present": bool(secret),
            "recovery_codes": len(acct.get("mfa_recovery_codes", []) or []),
            "role": acct.get("role", DEFAULT_ROLE),
            "otpauth_uri": (
                mfa_mod.otpauth_uri(secret, acct.get("email", "admin"))
                if secret and not enabled else ""
            ),
        }

    # ── Routes ─────────────────────────────────────────────────────────

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request):
        if is_authenticated(request):
            return RedirectResponse(url="/", status_code=302)

        is_mfa_step = request.session.get("mfa_pending", False)
        wa_email = request.session.get("mfa_pending_email", "")
        webauthn_available = wa.has_credentials(wa_email) if is_mfa_step else False
        totp_available = (
            bool(load_admin_account().get("mfa_enabled", False))
            if is_mfa_step else False
        )
        error = request.query_params.get("error", "")

        return templates.TemplateResponse(
            request, "login.html",
            {
                "request": request,
                "error": error,
                "csrf_token": get_csrf_token(request),
                "mfa_step": is_mfa_step,
                "webauthn_available": webauthn_available,
                "totp_available": totp_available,
            },
        )

    @app.post("/login")
    async def login_post(request: Request):
        form = await request.form()
        email = form.get("email", "")
        password = form.get("password", "")
        csrf_token = form.get("csrf_token", "")
        ip = client_ip(request)

        # Rate limit: per-IP, 5 failures in 60 seconds
        if _login_rate_check(ip):
            logger.warning("Login rate limit hit: ip=%s email=%s", ip, email)
            return RedirectResponse(
                url="/login?error=Too+many+failed+logins.+Try+again+in+60+seconds",
                status_code=429,
            )

        if not validate_csrf(request, csrf_token):
            return RedirectResponse(
                url="/login?error=Invalid+session+token",
                status_code=302,
            )

        acct = load_admin_account()
        stored_hash = acct.get("password_hash", "")
        if not stored_hash:
            logger.warning("Login attempted but admin not configured: ip=%s email=%s", ip, email)
            return RedirectResponse(
                url="/login?error=Invalid+credentials",
                status_code=302,
            )

        if not verify_password(password, stored_hash):
            _login_rate_record(ip)
            logger.warning("Failed login: ip=%s email=%s", ip, email)
            return _safe_redirect(
                "/login", query={"error": "Invalid credentials"})

        # Successful login — clear rate limit for this IP
        _login_rate_clear(ip)

        # Password OK — check if a second factor is required.
        # TOTP (mfa_enabled) OR an enrolled security key both gate the session.
        mfa_enabled = bool(acct.get("mfa_enabled", False))
        wa_enabled = wa.has_credentials(email)
        if mfa_enabled or wa_enabled:
            # Set pending state, redirect to MFA step
            request.session["mfa_pending"] = True
            request.session["mfa_pending_email"] = email
            request.session["mfa_pending_time"] = int(time.time())
            return RedirectResponse(url="/login?step=mfa", status_code=302)

        # No MFA — complete login immediately
        request.session["authenticated"] = True
        request.session["email"] = email
        request.session["role"] = acct.get("role", DEFAULT_ROLE)
        request.session["mfa_verified"] = True
        request.session["login_time"] = int(time.time())
        request.session["session_version"] = acct.get("session_version", 0)

        audit_log("login", email, "login (no MFA)", client_ip(request))
        return RedirectResponse(url="/", status_code=302)

    @app.post("/login/mfa")
    async def login_mfa(request: Request):
        """Verify TOTP code after password authentication."""
        if not request.session.get("mfa_pending", False):
            return RedirectResponse(url="/login", status_code=302)

        ip = client_ip(request)

        # Rate limit MFA attempts too (same pool as password login)
        if _login_rate_check(ip):
            logger.warning("MFA rate limit hit: ip=%s", ip)
            return RedirectResponse(
                url="/login?error=Too+many+failed+logins.+Try+again+in+60+seconds",
                status_code=429,
            )

        form = await request.form()
        code = str(form.get("totp_code", "")).strip()
        csrf_token = form.get("csrf_token", "")

        if not validate_csrf(request, csrf_token):
            return RedirectResponse(
                url="/login?error=Invalid+session+token",
                status_code=302,
            )

        # Check MFA timeout (5 minutes to enter code)
        pending_time = request.session.get("mfa_pending_time", 0)
        if int(time.time()) - pending_time > 300:
            request.session.pop("mfa_pending", None)
            request.session.pop("mfa_pending_email", None)
            request.session.pop("mfa_pending_time", None)
            return RedirectResponse(
                url="/login?error=MFA+code+expired.+Sign+in+again",
                status_code=302,
            )

        acct = load_admin_account()
        secret = acct.get("mfa_secret", "")
        if not secret:
            return RedirectResponse(
                url="/login?error=MFA+not+configured",
                status_code=302,
            )

        if not code or not mfa_mod.verify_totp(secret, code):
            # Fall back to a one-time recovery code before rejecting.
            acct = load_admin_account()
            stored = acct.get("mfa_recovery_codes", []) or []
            if code and stored:
                ok, remaining = mfa_mod.verify_and_consume_recovery_code(stored, code)
                if ok:
                    acct["mfa_recovery_codes"] = remaining
                    save_admin_account(acct)
                    _login_rate_clear(ip)
                    email = request.session.get("mfa_pending_email", "unknown")
                    audit_log(
                        "mfa_recovery", email,
                        f"recovery code used ({len(remaining)} remaining)",
                        client_ip(request),
                    )
                    request.session["authenticated"] = True
                    request.session["email"] = email
                    request.session["role"] = acct.get("role", DEFAULT_ROLE)
                    request.session["mfa_verified"] = True
                    request.session["login_time"] = int(time.time())
                    request.session["session_version"] = acct.get("session_version", 0)
                    request.session.pop("mfa_pending", None)
                    request.session.pop("mfa_pending_email", None)
                    request.session.pop("mfa_pending_time", None)
                    return RedirectResponse(url="/", status_code=302)
            _login_rate_record(ip)
            email = request.session.get("mfa_pending_email", "unknown")
            logger.warning("Failed MFA: ip=%s email=%s", ip, email)
            return RedirectResponse(
                url="/login?error=Invalid+verification+code",
                status_code=302,
            )

        # Successful MFA — clear rate limit for this IP
        _login_rate_clear(ip)

        email = request.session.get("mfa_pending_email", "unknown")
        request.session["authenticated"] = True
        request.session["email"] = email
        request.session["role"] = acct.get("role", DEFAULT_ROLE)
        request.session["mfa_verified"] = True
        request.session["login_time"] = int(time.time())
        request.session["session_version"] = acct.get("session_version", 0)
        # Clear pending state
        request.session.pop("mfa_pending", None)
        request.session.pop("mfa_pending_email", None)
        request.session.pop("mfa_pending_time", None)

        audit_log("login", email, "login (MFA)", client_ip(request))
        return RedirectResponse(url="/", status_code=302)

    @app.post("/login/break-glass")
    async def login_break_glass(request: Request):
        """Consume a single-use break-glass token to gain operator access.

        The token is issued by `ktc-mail admin break-glass`.  It is
        one-use, short-TTL, and every issuance is audited.  On success
        the operator is logged in and the token is wiped.
        """
        form = await request.form()
        token = str(form.get("breakglass_token", "")).strip()
        csrf_token = form.get("csrf_token", "")
        if not validate_csrf(request, csrf_token):
            return RedirectResponse(
                url="/login?error=Invalid+session+token", status_code=302)
        # Rate-limit break-glass attempts too — the token is short (~25 bits)
        # and online-guessable if unthrottled. Mirror the /login pool.
        ip = client_ip(request)
        if _login_rate_check(ip):
            logger.warning("Break-glass rate limit hit: ip=%s", ip)
            return RedirectResponse(
                url="/login?error=Too+many+failed+attempts.+Try+again+in+60+seconds",
                status_code=429,
            )
        if not token:
            return RedirectResponse(
                url="/login?error=Break-glass+token+required", status_code=302)


        from .breakglass import consume as breakglass_consume
        ok, operator = breakglass_consume(token)
        if not ok:
            logger.warning("Failed break-glass login (bad/expired/used token)")
            _login_rate_record(ip)
            return RedirectResponse(
                url="/login?error=Invalid+or+expired+break-glass+token",
                status_code=302)

        request.session["authenticated"] = True
        request.session["email"] = operator
        request.session["role"] = "operator"  # break-glass grants operator
        request.session["mfa_verified"] = True
        request.session["login_time"] = int(time.time())
        request.session["break_glass"] = True
        audit_log("login", operator, "login (break-glass)", client_ip(request))
        return RedirectResponse(url="/", status_code=302)

    # ── WebAuthn login second factor (P2) ─────────────────────────────
    # Triggered from the MFA step when the pending admin has keys enrolled.

    @app.post("/login/webauthn/begin")
    async def login_wa_begin(request: Request):
        if not request.session.get("mfa_pending", False):
            return JSONResponse({"error": "no pending login"}, status_code=400)
        email = request.session.get("mfa_pending_email", "")
        if not email or not wa.has_credentials(email):
            return JSONResponse({"error": "no webauthn credential"},
                                status_code=400)
        try:
            opts = wa.begin_authentication(request, email)
        except RuntimeError as exc:
            return JSONResponse({"error": str(exc)}, status_code=503)
        return JSONResponse(opts)

    @app.post("/login/webauthn/finish")
    async def login_wa_finish(request: Request):
        if not request.session.get("mfa_pending", False):
            return RedirectResponse(url="/login", status_code=302)
        ip = client_ip(request)
        if _login_rate_check(ip):
            return JSONResponse(
                {"ok": False, "error": "Too many failed attempts"},
                status_code=429)
        try:
            payload = await request.json()
        except Exception:
            _login_rate_record(ip)
            return JSONResponse({"ok": False, "error": "Invalid response"},
                                status_code=400)
        if not validate_csrf(request, payload.get("csrf_token", "")):
            _login_rate_record(ip)
            return JSONResponse({"ok": False, "error": "Invalid session token"},
                                status_code=403)
        email = request.session.get("mfa_pending_email", "unknown")
        ok, err = wa.verify_authentication(request, email, payload)
        if not ok:
            _login_rate_record(ip)
            logger.warning("Failed WebAuthn login: ip=%s email=%s err=%s",
                           ip, email, err)
            return JSONResponse({"ok": False, "error": "Invalid security key"},
                                status_code=401)
        _login_rate_clear(ip)
        acct = load_admin_account()
        request.session["authenticated"] = True
        request.session["email"] = email
        request.session["role"] = acct.get("role", DEFAULT_ROLE)
        request.session["mfa_verified"] = True
        request.session["login_time"] = int(time.time())
        request.session["session_version"] = acct.get("session_version", 0)
        request.session.pop("mfa_pending", None)
        request.session.pop("mfa_pending_email", None)
        request.session.pop("mfa_pending_time", None)
        audit_log("login", email, "login (WebAuthn)", client_ip(request))
        return JSONResponse({"ok": True})

    @app.get("/logout")
    async def logout(request: Request):
        request.session.clear()
        return RedirectResponse(url="/login", status_code=302)

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request):
        if not require_role(request, "readonly"):
            return login_redirect()

        profile = _load_profile()
        tls_state = _read_state(TLS_STATE_PATH)
        dns_state = _read_state(DNS_STATE_PATH)

        services = _all_service_status()

        cert_info = {}
        if tls_state:
            cert_info = {
                "domains": tls_state.get("domains", []),
                "updated_at": tls_state.get("updated_at", 0),
            }

        dns_info = {}
        if dns_state:
            dns_info = {
                "hash": dns_state.get("hash", ""),
                "updated_at": dns_state.get("updated_at", 0),
                "record_count": len(dns_state.get("records", [])),
            }

        admin_email = ""
        if profile:
            admin_email = profile.admin_email

        # Backup status for dashboard
        from .backup_manager import (
            load_config as bk_load_config,
            load_status as bk_load_status,
        )
        bk_config = bk_load_config()
        bk_status = bk_load_status()

        return templates.TemplateResponse(
            request, "dashboard.html",
            {
                "request": request,
                "profile": profile,
                "admin_email": admin_email,
                "services": services,
                "cert_info": cert_info,
                "dns_info": dns_info,
                "queue_depth": _queue_depth(),
                "user_count": _user_count(),
                "backup_configured": bk_config.is_configured(),
                "backup_last_success": bk_status.last_success,
                "backup_last_snapshot": bk_status.last_snapshot or "",
            },
        )

    # ── User management ────────────────────────────────────────────────

    @app.get("/users", response_class=HTMLResponse)
    async def users_page(request: Request):
        if not require_role(request, "admin"):
            return login_redirect()

        # Load users from passwd file
        users_data: list[dict[str, str]] = []
        lines = um._read_lines(um.PASSWD_FILE)
        for line in lines:
            parsed = um._parse_passwd(line)
            if parsed:
                users_data.append({
                    "email": parsed["email"],
                    "quota": parsed.get("quota", "1G"),
                })

        error = request.query_params.get("error", "")
        msg = request.query_params.get("msg", "")

        return templates.TemplateResponse(
            request, "users.html",
            {
                "request": request,
                "csrf_token": get_csrf_token(request),
                "users": sorted(users_data, key=lambda u: u["email"]),
                "error": error,
                "msg": msg,
            },
        )

    @app.post("/users/add")
    async def users_add(request: Request):
        if not require_role(request, "admin"):
            return login_redirect()

        form = await request.form()
        csrf_token = form.get("csrf_token", "")
        if not validate_csrf(request, csrf_token):
            return RedirectResponse(
                url="/users?error=Invalid+session+token",
                status_code=302,
            )

        email = str(form.get("email", "")).strip().lower()
        password = str(form.get("password", ""))
        quota = str(form.get("quota", "1G"))

        if not _valid_email(email):
            return _safe_redirect(
                "/users", query={"error": "Invalid email address"})
        if not password:
            return _safe_redirect(
                "/users", query={"error": "Password required"})

        result = um.user_add(email, password=password, quota=quota, dry_run=False)
        if result != 0:
            return _safe_redirect("/users",
                                  query={"error": f"Failed to add {email}"})

        audit_log("user_add", actor_email(request), email, client_ip(request))
        return _safe_redirect("/users", query={"msg": f"Added {email}"})

    @app.post("/users/del")
    async def users_del(request: Request):
        if not require_role(request, "admin"):
            return login_redirect()

        form = await request.form()
        csrf_token = form.get("csrf_token", "")
        if not validate_csrf(request, csrf_token):
            return RedirectResponse(
                url="/users?error=Invalid+session+token",
                status_code=302,
            )

        email = str(form.get("email", "")).strip().lower()
        if not _valid_email(email):
            return _safe_redirect(
                "/users", query={"error": "Invalid email address"})

        result = um.user_delete(email, dry_run=False)
        if result != 0:
            return _safe_redirect("/users",
                                  query={"error": f"Failed to remove {email}"})

        audit_log("user_del", actor_email(request), email, client_ip(request))
        return _safe_redirect("/users", query={"msg": f"Removed {email}"})

    @app.post("/users/passwd")
    async def users_passwd(request: Request):
        if not require_role(request, "admin"):
            return login_redirect()

        form = await request.form()
        csrf_token = form.get("csrf_token", "")
        if not validate_csrf(request, csrf_token):
            return RedirectResponse(
                url="/users?error=Invalid+session+token",
                status_code=302,
            )

        email = str(form.get("email", "")).strip().lower()
        password = str(form.get("password", ""))

        if not _valid_email(email):
            return _safe_redirect(
                "/users", query={"error": "Invalid email address"})
        if not password:
            return _safe_redirect(
                "/users", query={"error": "Password required"})

        result = um.user_passwd(email, dry_run=False, password=password)
        if result != 0:
            return _safe_redirect("/users",
                                  query={"error": f"Failed to change password for {email}"})

        audit_log("user_passwd", actor_email(request), email, client_ip(request))

    # ── Spam policy (per-user / per-domain) ─────────────────────────────

    def _load_spam_overrides() -> list[dict[str, str]]:
        """List active rspamd override keys from Redis (setting:user: / setting:domain:)."""
        try:
            r = _get_redis()
            keys = r.keys("setting:*")
        except Exception:
            return []
        out: list[dict[str, str]] = []
        for k in sorted(keys):
            out.append({"key": k, "value": r.get(k) or ""})
        return out

    @app.get("/spam-policy", response_class=HTMLResponse)
    async def spam_policy_page(request: Request):
        if not require_role(request, "admin"):
            return login_redirect()

        error = request.query_params.get("error", "")
        msg = request.query_params.get("msg", "")
        return templates.TemplateResponse(
            request, "spam_policy.html",
            {
                "request": request,
                "csrf_token": get_csrf_token(request),
                "overrides": _load_spam_overrides(),
                "baseline": {"reject": 15.0, "add_header": 6.0, "greylist": 4.0},
                "error": error,
                "msg": msg,
            },
        )

    @app.post("/spam-policy")
    async def spam_policy_save(request: Request):
        if not require_role(request, "admin"):
            return login_redirect()

        form = await request.form()
        csrf_token = form.get("csrf_token", "")
        if not validate_csrf(request, csrf_token):
            return RedirectResponse(
                url="/spam-policy?error=Invalid+session+token", status_code=302)

        action = str(form.get("action", "set"))
        target = str(form.get("target", "")).strip().lower()

        if action == "remove":
            key = str(form.get("key", ""))
            if not (key.startswith("setting:user:") or key.startswith("setting:domain:")):
                return _safe_redirect("/spam-policy", query={"error": "Invalid override key"})
            try:
                _get_redis().delete(key)
            except Exception:
                return _safe_redirect("/spam-policy", query={"error": "Redis unavailable"})
            audit_log("spam_policy_remove", actor_email(request), key, client_ip(request))
            return _safe_redirect("/spam-policy", query={"msg": f"Removed {key}"})

        # action == "set"
        target_type = str(form.get("target_type", "user"))
        if not target:
            return _safe_redirect("/spam-policy", query={"error": "Email or domain required"})
        if target_type == "user":
            if not _valid_email(target):
                return _safe_redirect("/spam-policy", query={"error": "Invalid email address"})
            key = f"setting:user:{target}"
        else:
            domain = target.split("@")[-1]
            if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", domain):
                return _safe_redirect("/spam-policy", query={"error": "Invalid domain"})
            key = f"setting:domain:{domain}"

        try:
            reject = float(form.get("reject", ""))
            add_header = float(form.get("add_header", ""))
        except (ValueError, TypeError):
            return _safe_redirect(
                "/spam-policy", query={"error": "reject and add-header must be numbers"})

        greylist: float | None = None
        greylist_raw = str(form.get("greylist", "")).strip()
        if greylist_raw:
            try:
                greylist = float(greylist_raw)
            except ValueError:
                return _safe_redirect(
                    "/spam-policy", query={"error": "greylist must be a number"})

        ucl = build_spam_policy_ucl(reject, add_header, greylist)
        try:
            _get_redis().set(key, ucl)
        except Exception:
            return _safe_redirect("/spam-policy", query={"error": "Redis unavailable"})
        audit_log("spam_policy_set", actor_email(request), f"{key} -> {ucl}", client_ip(request))
        return _safe_redirect("/spam-policy", query={"msg": f"Saved {key}"})

    # ── Quarantine (delivered spam in Junk) ──────────────────────────────
    # rspamd's `add header` action delivers spam with X-Spam-Flag: YES, which the
    # global sieve (spam-to-junk.sieve) files into Junk. This view lists those
    # messages from rspamd history and lets an admin release false positives
    # (Junk -> INBOX) or confirm spam (train the filter). Helpers are
    # module-level (see top of file) so they are unit-testable.

    @app.get("/quarantine", response_class=HTMLResponse)
    async def quarantine_page(request: Request):
        if not require_role(request, "admin"):
            return login_redirect()
        rows = rspamc_history_rows()
        return templates.TemplateResponse(
            request, "quarantine.html",
            {
                "request": request,
                "csrf_token": get_csrf_token(request),
                "rows": rows,
                "message": request.query_params.get("msg", ""),
                "error": request.query_params.get("error", ""),
            },
        )

    @app.post("/quarantine/release")
    async def quarantine_release_handler(request: Request):
        if not require_role(request, "admin"):
            return login_redirect()
        form = await request.form()
        if not validate_csrf(request, str(form.get("csrf_token", ""))):
            return _safe_redirect("/quarantine", query={"error": "Invalid session token"})
        message_id = str(form.get("message_id", "")).strip()
        user = str(form.get("user", "")).strip().lower()
        if not message_id or not user:
            return _safe_redirect("/quarantine", query={"error": "message_id and user required"})
        res = quarantine_release(message_id, user)
        audit_log("quarantine_release", actor_email(request), f"{user} {message_id}",
                  client_ip(request))
        msg = "Released to Inbox" if res["moved"] else "Released (mailbox move unavailable)"
        return _safe_redirect("/quarantine", query={"msg": msg})

    @app.post("/quarantine/confirm")
    async def quarantine_confirm_handler(request: Request):
        if not require_role(request, "admin"):
            return login_redirect()
        form = await request.form()
        if not validate_csrf(request, str(form.get("csrf_token", ""))):
            return _safe_redirect("/quarantine", query={"error": "Invalid session token"})
        message_id = str(form.get("message_id", "")).strip()
        user = str(form.get("user", "")).strip().lower()
        if not message_id or not user:
            return _safe_redirect("/quarantine", query={"error": "message_id and user required"})
        res = quarantine_confirm(message_id, user)
        audit_log("quarantine_confirm", actor_email(request), f"{user} {message_id}",
                  client_ip(request))
        msg = "Marked as spam" if res["learned"] else "Confirmed (trainer unavailable)"
        return _safe_redirect("/quarantine", query={"msg": msg})

    # ── End-user self-service ────────────────────────────────────────────
    # Mailbox users log in with their own credentials (Dovecot auth) and may
    # change their password, tune their own spam sensitivity (reuses the
    # setting:user: rspamd override from Slice-A), and release their own Junk
    # mail (reuses quarantine_release from Slice-B, scoped to their address).

    @app.get("/self/login", response_class=HTMLResponse)
    async def self_login_page(request: Request):
        if require_role(request, "user"):
            return RedirectResponse(url="/self", status_code=302)
        error = request.query_params.get("error", "")
        return templates.TemplateResponse(
            request, "self_login.html",
            {"request": request, "error": error, "csrf_token": get_csrf_token(request)},
        )

    @app.post("/self/login")
    async def self_login_post(request: Request):
        form = await request.form()
        if not validate_csrf(request, str(form.get("csrf_token", ""))):
            return _safe_redirect("/self/login", query={"error": "Invalid session token"})
        email = str(form.get("email", "")).strip().lower()
        password = str(form.get("password", ""))
        if not _valid_email(email):
            return _safe_redirect("/self/login", query={"error": "Invalid email address"})
        if not mailbox_auth(email, password):
            audit_log("self_login_fail", email, client_ip(request))
            return _safe_redirect("/self/login", query={"error": "Invalid credentials"})
        request.session["authenticated"] = True
        request.session["email"] = email
        request.session["role"] = "user"
        request.session["mfa_verified"] = True
        request.session["login_time"] = int(time.time())
        request.session["session_version"] = load_admin_account().get("session_version", 0)
        audit_log("self_login", email, client_ip(request))
        return RedirectResponse(url="/self", status_code=302)

    @app.get("/self", response_class=HTMLResponse)
    async def self_service_page(request: Request):
        if not require_role(request, "user"):
            return RedirectResponse(url="/self/login", status_code=302)
        email = request.session.get("email", "")
        current = None
        try:
            raw = _get_redis().get(f"setting:user:{email}")
            if raw:
                current = raw
        except Exception:
            current = None
        rows = [r for r in rspamc_history_rows() if r.get("to", "").lower() == email]
        return templates.TemplateResponse(
            request, "self_service.html",
            {
                "request": request,
                "csrf_token": get_csrf_token(request),
                "email": email,
                "current": current,
                "baseline": {"reject": 15.0, "add_header": 6.0, "greylist": 4.0},
                "rows": rows,
                "message": request.query_params.get("msg", ""),
                "error": request.query_params.get("error", ""),
            },
        )

    @app.post("/self/password")
    async def self_password_change(request: Request):
        if not require_role(request, "user"):
            return RedirectResponse(url="/self/login", status_code=302)
        form = await request.form()
        if not validate_csrf(request, str(form.get("csrf_token", ""))):
            return _safe_redirect("/self", query={"error": "Invalid session token"})
        email = request.session.get("email", "")
        old = str(form.get("old_password", ""))
        new = str(form.get("new_password", ""))
        if not mailbox_auth(email, old):
            return _safe_redirect("/self", query={"error": "Current password incorrect"})
        if len(new) < 8:
            return _safe_redirect("/self", query={"error": "New password too short (min 8)"})
        if um.user_passwd(email, password=new) != 0:
            return _safe_redirect("/self", query={"error": "Password change failed"})
        audit_log("self_passwd", email, client_ip(request))
        return _safe_redirect("/self", query={"msg": "Password changed"})

    @app.post("/self/spam-policy")
    async def self_spam_policy(request: Request):
        if not require_role(request, "user"):
            return RedirectResponse(url="/self/login", status_code=302)
        form = await request.form()
        if not validate_csrf(request, str(form.get("csrf_token", ""))):
            return _safe_redirect("/self", query={"error": "Invalid session token"})
        email = request.session.get("email", "")
        key = f"setting:user:{email}"
        if str(form.get("action", "set")) == "remove":
            try:
                _get_redis().delete(key)
            except Exception:
                return _safe_redirect("/self", query={"error": "Redis unavailable"})
            audit_log("self_spam_remove", email, client_ip(request))
            return _safe_redirect("/self", query={"msg": "Spam settings reset to baseline"})
        try:
            reject = float(form.get("reject", ""))
            add_header = float(form.get("add_header", ""))
        except (ValueError, TypeError):
            return _safe_redirect("/self", query={"error": "reject and add-header must be numbers"})
        greylist: float | None = None
        greylist_raw = str(form.get("greylist", "")).strip()
        if greylist_raw:
            try:
                greylist = float(greylist_raw)
            except ValueError:
                return _safe_redirect("/self", query={"error": "greylist must be a number"})
        ucl = build_spam_policy_ucl(reject, add_header, greylist)
        try:
            _get_redis().set(key, ucl)
        except Exception:
            return _safe_redirect("/self", query={"error": "Redis unavailable"})
        audit_log("self_spam_set", email, f"{key} -> {ucl}", client_ip(request))
        return _safe_redirect("/self", query={"msg": "Spam settings saved"})

    @app.post("/self/quarantine/release")
    async def self_quarantine_release(request: Request):
        if not require_role(request, "user"):
            return RedirectResponse(url="/self/login", status_code=302)
        form = await request.form()
        if not validate_csrf(request, str(form.get("csrf_token", ""))):
            return _safe_redirect("/self", query={"error": "Invalid session token"})
        # always scope to the session identity; ignore any user-supplied target
        email = request.session.get("email", "")
        message_id = str(form.get("message_id", "")).strip()
        if not message_id:
            return _safe_redirect("/self", query={"error": "message_id required"})
        res = quarantine_release(message_id, email)
        audit_log("self_quarantine_release", email, message_id, client_ip(request))
        msg = "Released to Inbox" if res["moved"] else "Released (mailbox move unavailable)"
        return _safe_redirect("/self", query={"msg": msg})

    # ── Settings ────────────────────────────────────────────────────────

    @app.get("/settings", response_class=HTMLResponse)
    async def settings_page(request: Request):
        if not require_role(request, "admin"):
            return login_redirect()

        profile = _load_profile()
        admin_email = profile.admin_email if profile else ""
        mfa = account_mfa_status()
        wa_creds = wa.credentials_for(request.session.get("email", ""))

        error = request.query_params.get("error", "")
        msg = request.query_params.get("msg", "")

        # Generate QR code locally — never leak TOTP secret to third-party APIs
        qr_src = ""
        if mfa.get("otpauth_uri"):
            qr_src = qr_svg_b64(mfa["otpauth_uri"])

        return templates.TemplateResponse(
            request, "settings.html",
            {
                "request": request,
                "csrf_token": get_csrf_token(request),
                "profile": profile,
                "admin_email": admin_email,
                "config_dir": str(CONFIG_DIR),
                "state_dir": str(STATE_DIR),
                "mfa": mfa,
                "webauthn": {"credentials": wa_creds, "available": bool(wa_creds)},
                "qr_src": qr_src,
                "branding": _load_branding(),
                "error": error,
                "msg": msg,
            },
        )

    @app.post("/settings/password")
    async def settings_password(request: Request):
        if not require_role(request, "admin"):
            return login_redirect()

        form = await request.form()
        csrf_token = form.get("csrf_token", "")
        if not validate_csrf(request, csrf_token):
            return RedirectResponse(
                url="/settings?error=Invalid+session+token",
                status_code=302,
            )

        current = form.get("current_password", "")
        new_pw = form.get("new_password", "")
        confirm = form.get("confirm_password", "")

        if not current or not new_pw or not confirm:
            return RedirectResponse(
                url="/settings?error=All+fields+required",
                status_code=302,
            )

        if new_pw != confirm:
            return RedirectResponse(
                url="/settings?error=New+passwords+do+not+match",
                status_code=302,
            )

        if len(new_pw) < 8:
            return RedirectResponse(
                url="/settings?error=Password+must+be+at+least+8+characters",
                status_code=302,
            )

        stored = load_admin_hash()
        if not stored or not verify_password(current, stored):
            return RedirectResponse(
                url="/settings?error=Current+password+is+incorrect",
                status_code=302,
            )

        hashed = hash_password(new_pw)
        save_admin_hash(hashed)

        audit_log(
            "admin_password_change", actor_email(request),
            "password changed via web GUI", client_ip(request),
        )

        return RedirectResponse(
            url="/settings?msg=Password+updated+successfully",
            status_code=302,
        )

    @app.post("/settings/branding")
    async def settings_branding(request: Request):
        if not require_role(request, "admin"):
            return login_redirect()

        form = await request.form()
        if not validate_csrf(request, form.get("csrf_token", "")):
            return RedirectResponse(
                url="/settings?error=Invalid+session+token",
                status_code=302,
            )

        org_name = (form.get("org_name", "") or "").strip()
        accent = (form.get("accent", "") or "").strip()
        logo_url = (form.get("logo_url", "") or "").strip()

        # Validate before persisting — Branding rejects unsafe input.
        try:
            Branding(org_name=org_name, accent=accent, logo_url=logo_url).validate()
        except ValueError as exc:
            return RedirectResponse(
                url="/settings?error=" + urllib.parse.quote(str(exc)),
                status_code=302,
            )

        try:
            save_branding(Branding(org_name=org_name, accent=accent,
                                   logo_url=logo_url))
            _branding_cache["val"] = None
            _branding_cache["ts"] = 0.0
            audit_log("branding_change", actor_email(request),
                      "portal branding updated", client_ip(request))
        except Exception as exc:
            logger.exception("saving branding")
            return RedirectResponse(
                url="/settings?error=" + urllib.parse.quote("Save failed: " + str(exc)),
                status_code=302,
            )

        return RedirectResponse(
            url="/settings?msg=Branding+saved",
            status_code=302,
        )

    # ── MFA management ────────────────────────────────────────────────

    @app.post("/settings/mfa/enable")
    async def settings_mfa_enable(request: Request):
        if not require_role(request, "admin"):
            return login_redirect()

        form = await request.form()
        csrf_token = form.get("csrf_token", "")
        if not validate_csrf(request, csrf_token):
            return RedirectResponse(
                url="/settings?error=Invalid+session+token",
                status_code=302,
            )

        code = str(form.get("totp_code", "")).strip()
        acct = load_admin_account()
        secret = acct.get("mfa_secret", "")

        if not secret:
            return RedirectResponse(
                url="/settings?error=MFA+secret+not+initialized",
                status_code=302,
            )

        if not code or not mfa_mod.verify_totp(secret, code):
            return RedirectResponse(
                url="/settings?error=Invalid+verification+code.+Try+again",
                status_code=302,
            )

        acct["mfa_enabled"] = True
        acct["session_version"] = acct.get("session_version", 0) + 1
        save_admin_account(acct)

        audit_log(
            "mfa_enable", actor_email(request),
            "MFA enabled", client_ip(request),
        )
        return RedirectResponse(
            url="/settings?msg=Two-factor+authentication+enabled",
            status_code=302,
        )

    @app.post("/settings/mfa/disable")
    async def settings_mfa_disable(request: Request):
        if not require_role(request, "admin"):
            return login_redirect()

        form = await request.form()
        csrf_token = form.get("csrf_token", "")
        if not validate_csrf(request, csrf_token):
            return RedirectResponse(
                url="/settings?error=Invalid+session+token",
                status_code=302,
            )

        acct = load_admin_account()
        acct["mfa_enabled"] = False
        acct["mfa_secret"] = None
        acct["mfa_recovery_codes"] = []  # purge stale recovery hashes
        acct["session_version"] = acct.get("session_version", 0) + 1
        save_admin_account(acct)

        audit_log(
            "mfa_disable", actor_email(request),
            "MFA disabled", client_ip(request),
        )
        return RedirectResponse(
            url="/settings?msg=Two-factor+authentication+disabled",
            status_code=302,
        )

    # ── WebAuthn / security-key second factor (P2) ─────────────────────
    # Enrollment is admin self-service: the logged-in admin enrolls keys for
    # their own account. begin/finish are JSON-driven (browser glue in
    # static/webauthn.js).

    @app.post("/settings/webauthn/register/begin")
    async def wa_register_begin(request: Request):
        if not require_role(request, "admin"):
            return login_redirect()
        form = await request.form()
        if not validate_csrf(request, form.get("csrf_token", "")):
            return JSONResponse(
                {"ok": False, "error": "Invalid session token"}, status_code=403)
        email = request.session.get("email", "")
        try:
            opts = wa.begin_registration(request, email)
        except RuntimeError as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=503)
        return JSONResponse(opts)

    @app.post("/settings/webauthn/register/finish")
    async def wa_register_finish(request: Request):
        if not require_role(request, "admin"):
            return login_redirect()
        form = await request.form()
        if not validate_csrf(request, form.get("csrf_token", "")):
            return JSONResponse(
                {"ok": False, "error": "Invalid session token"}, status_code=403)
        try:
            payload = json.loads(form.get("response", "{}"))
        except (ValueError, TypeError):
            return JSONResponse({"ok": False, "error": "Invalid response"},
                                status_code=400)
        ok, err = wa.finish_registration(
            request, request.session.get("email", ""), payload)
        if not ok:
            return JSONResponse(
                {"ok": False, "error": err or "Registration failed"},
                status_code=400)
        audit_log("webauthn_register", actor_email(request),
                  "security key enrolled", client_ip(request))
        return JSONResponse({"ok": True})

    @app.post("/settings/webauthn/remove")
    async def wa_remove(request: Request):
        if not require_role(request, "admin"):
            return login_redirect()
        form = await request.form()
        if not validate_csrf(request, form.get("csrf_token", "")):
            return RedirectResponse(
                url="/settings?error=Invalid+session+token", status_code=302)
        cred_id = form.get("cred_id", "")
        email = request.session.get("email", "")
        if wa.remove_credential(email, cred_id):
            audit_log("webauthn_remove", actor_email(request),
                      "security key removed", client_ip(request))
            return RedirectResponse(url="/settings?msg=Security+key+removed",
                                    status_code=302)
        return RedirectResponse(url="/settings?error=Key+not+found",
                                status_code=302)

    @app.post("/settings/mfa/recovery")
    async def settings_mfa_recovery(request: Request):
        """Regenerate one-time recovery codes (operator-gated).

        Old codes are invalidated; new plaintext codes are shown ONCE
        in the redirect message.  Stored only as SHA-256 hashes.
        """
        if not require_role(request, "operator"):
            return login_redirect()
        form = await request.form()
        csrf_token = form.get("csrf_token", "")
        if not validate_csrf(request, csrf_token):
            return RedirectResponse(
                url="/settings?error=Invalid+session+token",
                status_code=302,
            )
        from .mfa import generate_recovery_codes, hash_recovery_code
        plain = generate_recovery_codes()
        acct = load_admin_account()
        acct["mfa_recovery_codes"] = [hash_recovery_code(c) for c in plain]
        acct["session_version"] = acct.get("session_version", 0) + 1
        save_admin_account(acct)
        audit_log(
            "mfa_recovery_regen", actor_email(request),
            f"{len(plain)} recovery codes regenerated", client_ip(request),
        )
        # Show plaintext codes ONCE in the response body — never in the URL
        # (a query string would leak them into access logs / history / Referer).
        return templates.TemplateResponse(
            request, "mfa_codes.html",
            {
                "request": request,
                "title": "Recovery Codes",
                "intro": "Recovery codes regenerated.",
                "codes": "\n".join(plain),
            },
        )

    @app.post("/settings/mfa/init")
    async def settings_mfa_init(request: Request):
        """Generate a new TOTP secret (replaces any existing one)."""
        if not require_role(request, "admin"):
            return login_redirect()

        form = await request.form()
        csrf_token = form.get("csrf_token", "")
        if not validate_csrf(request, csrf_token):
            return RedirectResponse(
                url="/settings?error=Invalid+session+token",
                status_code=302,
            )

        acct = load_admin_account()
        secret = mfa_mod.generate_secret()
        acct["mfa_secret"] = secret
        # One-time recovery codes: show once, store hashed only.
        from .mfa import generate_recovery_codes, hash_recovery_code
        plain = generate_recovery_codes()
        acct["mfa_recovery_codes"] = [hash_recovery_code(c) for c in plain]
        # Don't enable yet — must verify first code
        acct["mfa_enabled"] = False
        acct["session_version"] = acct.get("session_version", 0) + 1
        save_admin_account(acct)

        audit_log(
            "mfa_init", actor_email(request),
            "MFA secret generated", client_ip(request),
        )
        # Show plaintext recovery codes ONCE in the response body — never in
        # the URL (would leak into access logs / history / Referer).
        return templates.TemplateResponse(
            request, "mfa_codes.html",
            {
                "request": request,
                "title": "MFA Initialized",
                "intro": "Scan the QR code on Settings, then verify. Recovery codes:",
                "codes": "\n".join(plain),
            },
        )

    # ── DKIM management ────────────────────────────────────────────────

    @app.get("/dkim", response_class=HTMLResponse)
    async def dkim_page(request: Request):
        if not require_role(request, "operator"):
            return login_redirect()
        profile = _load_profile()
        domain = profile.domain if profile else ""
        keys = _list_dkim_keys(domain) if domain else []
        error = request.query_params.get("error", "")
        msg = request.query_params.get("msg", "")
        return templates.TemplateResponse(
            request, "dkim.html",
            {
                "request": request,
                "csrf_token": get_csrf_token(request),
                "keys": keys,
                "profile": profile,
                "domain": domain,
                "error": error,
                "msg": msg,
            },
        )

    @app.post("/dkim/generate")
    async def dkim_generate(request: Request):
        if not require_role(request, "admin"):
            return login_redirect()

        form = await request.form()
        csrf_token = form.get("csrf_token", "")
        if not validate_csrf(request, csrf_token):
            return RedirectResponse(
                url="/dkim?error=Invalid+session+token",
                status_code=302,
            )

        selector = str(form.get("selector", "default")).strip()
        if not re.match(r'^[a-zA-Z0-9_-]+$', selector):
            return _safe_redirect(
                "/dkim", query={"error": "Invalid selector"})

        profile = _load_profile()
        if not profile:
            return RedirectResponse(
                url="/dkim?error=Setup+profile+not+found",
                status_code=302,
            )

        try:
            from .config_renderer import dkim_generate as _dkim_gen

            priv_pem, _dns_record = _dkim_gen(profile.domain, selector)
            key_path = DKIM_DIR / f"{selector}.private"
            key_path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_bytes(key_path, priv_pem)
            audit_log(
                "dkim_generate", actor_email(request),
                f"selector={selector}", client_ip(request),
            )
            return RedirectResponse(url="/dkim", status_code=302)
        except Exception as exc:
            return _safe_redirect("/dkim",
                                  query={"error": f"Generation failed: {exc}"})

    # ── Log viewer ─────────────────────────────────────────────────────

    @app.get("/logs", response_class=HTMLResponse)
    async def logs_page(request: Request):
        if not require_role(request, "operator"):
            return login_redirect()

        # Group sources for the tabbed UI: {group: [(key, label), ...]}
        grouped: dict[str, list[tuple[str, str]]] = {}
        for key, spec in LOG_SOURCES.items():
            grouped.setdefault(spec["group"], []).append((key, spec["label"]))
        # Stable group order: KTC Mail, Mail stack, Files.
        group_order = ["KTC Mail", "Mail stack", "Files"]
        ordered_groups = [
            (g, grouped[g]) for g in group_order if g in grouped
        ] + [(g, v) for g, v in grouped.items() if g not in group_order]

        source = request.query_params.get("source", "ktc-admin")
        if source not in LOG_SOURCES:
            source = "ktc-admin"
        raw_lines = request.query_params.get("lines", "100")
        filter_str = request.query_params.get("filter", "")

        try:
            n_lines = max(10, min(int(raw_lines), 2000))
        except (ValueError, TypeError):
            n_lines = 100

        log_text = _read_log_source(source, n_lines)

        if filter_str:
            log_lines = log_text.splitlines()
            filtered = [l for l in log_lines if filter_str.lower() in l.lower()]
            log_text = "\n".join(filtered) if filtered else "(no matching lines)"

        return templates.TemplateResponse(
            request, "logs.html",
            {
                "request": request,
                "source": source,
                "source_label": LOG_SOURCES[source]["label"],
                "groups": ordered_groups,
                "lines": n_lines,
                "filter": filter_str,
                "log_text": log_text,
            },
        )

    # ── DNS status ─────────────────────────────────────────────────────

    @app.get("/dns", response_class=HTMLResponse)
    async def dns_page(request: Request):
        if not require_role(request, "operator"):
            return login_redirect()

        profile = _load_profile()
        dns_state = _read_state(DNS_STATE_PATH)
        expected_records = dns_state.get("records", []) if dns_state else []

        error = request.query_params.get("error", "")
        msg = request.query_params.get("msg", "")

        return templates.TemplateResponse(
            request, "dns_status.html",
            {
                "request": request,
                "csrf_token": get_csrf_token(request),
                "profile": profile,
                "dns_state": dns_state,
                "expected_records": expected_records,
                "error": error,
                "msg": msg,
            },
        )

    @app.post("/dns/verify")
    async def dns_verify(request: Request):
        if not require_role(request, "operator"):
            return login_redirect()

        form = await request.form()
        csrf_token = form.get("csrf_token", "")
        if not validate_csrf(request, csrf_token):
            return RedirectResponse(
                url="/dns?error=Invalid+session+token",
                status_code=302,
            )

        if not SETUP_PATH.exists():
            return RedirectResponse(
                url="/dns?error=Setup+profile+not+found",
                status_code=302,
            )

        try:
            from .dns_provider import verify_records, provider_from_config

            data = read_json(SETUP_PATH)
            profile = SetupProfile.from_dict(data)
            secrets = (
                read_json(SECRETS_PATH) if SECRETS_PATH.exists() else {}
            )
            transport = provider_from_config(data, secrets, dry_run=False)
            local_records = profile.generate_dns_records()
            issues = verify_records(
                local_records, transport, profile.domain,
            )
            if issues:
                return _safe_redirect(
                    "/dns",
                    query={"msg": f"Found {len(issues)} issues"})
            return _safe_redirect(
                "/dns", query={"msg": "All records verified OK"})
        except Exception as exc:
            return _safe_redirect(
                "/dns", query={"error": f"Verification failed: {exc}"})

    @app.post("/dns/apply")
    async def dns_apply(request: Request):
        if not require_role(request, "admin"):
            return login_redirect()

        form = await request.form()
        csrf_token = form.get("csrf_token", "")
        if not validate_csrf(request, csrf_token):
            return RedirectResponse(
                url="/dns?error=Invalid+session+token",
                status_code=302,
            )

        if not SETUP_PATH.exists():
            return RedirectResponse(
                url="/dns?error=Setup+profile+not+found",
                status_code=302,
            )

        try:
            from .dns_provider import sync_records, provider_from_config

            data = read_json(SETUP_PATH)
            profile = SetupProfile.from_dict(data)
            secrets = (
                read_json(SECRETS_PATH) if SECRETS_PATH.exists() else {}
            )
            transport = provider_from_config(data, secrets, dry_run=False)
            local = profile.generate_dns_records()
            actions = await asyncio.wait_for(
                asyncio.to_thread(
                    sync_records, local, transport, profile.domain, False),
                timeout=120,
            )

            state = {
                "domain": profile.domain,
                "records": [r.to_dict() for r in local],
                "hash": local.content_hash(),
                "updated_at": int(time.time()),
                "actions": actions,
            }
            save_json_private(DNS_STATE_PATH, state)

            audit_log(
                "dns_apply", actor_email(request),
                f"domain={profile.domain}, records={len(actions)}",
                client_ip(request),
            )
            return RedirectResponse(
                url="/dns?msg=DNS+records+synced+OK",
                status_code=302,
            )
        except TimeoutError:
            return _safe_redirect("/dns",
                                  query={"error": "DNS sync timed out"})
        except Exception as exc:
            return _safe_redirect("/dns",
                                  query={"error": f"Sync failed: {exc}"})

    # ── Mail queue ──────────────────────────────────────────────────────

    @app.get("/queue", response_class=HTMLResponse)
    async def queue_page(request: Request):
        if not require_role(request, "operator"):
            return login_redirect()

        entries = _parse_queue()
        error = request.query_params.get("error", "")
        msg = request.query_params.get("msg", "")

        return templates.TemplateResponse(
            request, "queue.html",
            {
                "request": request,
                "csrf_token": get_csrf_token(request),
                "entries": entries,
                "error": error,
                "msg": msg,
            },
        )

    @app.post("/queue/flush")
    async def queue_flush(request: Request):
        if not require_role(request, "admin"):
            return login_redirect()

        form = await request.form()
        csrf_token = form.get("csrf_token", "")
        if not validate_csrf(request, csrf_token):
            return RedirectResponse(
                url="/queue?error=Invalid+session+token",
                status_code=302,
            )

        try:
            result = subprocess.run(
                ["postqueue", "-f"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                return RedirectResponse(
                    url="/queue?error=Flush+failed:+"
                        + result.stderr.strip(),
                    status_code=302,
                )
            audit_log(
                "queue_flush", actor_email(request),
                "flushed all", client_ip(request),
            )
            return RedirectResponse(
                url="/queue?msg=Queue+flushed",
                status_code=302,
            )
        except Exception as exc:
            return _safe_redirect("/queue",
                                  query={"error": f"Flush failed: {exc}"})

    @app.post("/queue/del")
    async def queue_del(request: Request):
        if not require_role(request, "admin"):
            return login_redirect()

        form = await request.form()
        csrf_token = form.get("csrf_token", "")
        if not validate_csrf(request, csrf_token):
            return RedirectResponse(
                url="/queue?error=Invalid+session+token",
                status_code=302,
            )

        queue_id = str(form.get("queue_id", "")).strip()
        if not queue_id:
            return RedirectResponse(
                url="/queue?error=Missing+queue+ID",
                status_code=302,
            )

        try:
            result = subprocess.run(
                ["postsuper", "-d", queue_id],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                return RedirectResponse(
                    url="/queue?error=Delete+failed:+"
                        + result.stderr.strip(),
                    status_code=302,
                )
            audit_log(
                "queue_delete", actor_email(request),
                f"queue_id={queue_id}", client_ip(request),
            )
            return RedirectResponse(
                url="/queue?msg=Deleted+" + queue_id,
                status_code=302,
            )
        except Exception as exc:
            return _safe_redirect("/queue",
                                  query={"error": f"Delete failed: {exc}"})

    # ── Certificate status ─────────────────────────────────────────────

    @app.get("/certs", response_class=HTMLResponse)
    async def certs_page(request: Request):
        if not require_role(request, "admin"):
            return login_redirect()

        profile = _load_profile()
        tls_state = _read_state(TLS_STATE_PATH)

        cert_details: dict[str, Any] = {}
        cert_path = Path(f"/etc/letsencrypt/live/{CERT_NAME}/fullchain.pem")
        if cert_path.exists():
            cert_details = _cert_info_from_path(cert_path)
            if "end_date" in cert_details:
                cert_details["expiry_days"] = _cert_expiry_days(
                    cert_details["end_date"],
                )

        error = request.query_params.get("error", "")
        msg = request.query_params.get("msg", "")

        return templates.TemplateResponse(
            request, "certs.html",
            {
                "request": request,
                "csrf_token": get_csrf_token(request),
                "profile": profile,
                "tls_state": tls_state,
                "cert_details": cert_details,
                "cert_path": str(cert_path),
                "error": error,
                "msg": msg,
            },
        )

    @app.post("/certs/renew")
    async def certs_renew(request: Request):
        if not require_role(request, "admin"):
            return login_redirect()

        form = await request.form()
        csrf_token = form.get("csrf_token", "")
        if not validate_csrf(request, csrf_token):
            return RedirectResponse(
                url="/certs?error=Invalid+session+token",
                status_code=302,
            )

        try:
            from .acme_manager import renew as acme_renew

            result = await asyncio.wait_for(
                asyncio.to_thread(acme_renew, False), timeout=120)
            if result != 0:
                return RedirectResponse(
                    url="/certs?error=Renewal+failed",
                    status_code=302,
                )

            audit_log(
                "cert_renew", actor_email(request),
                "manual renewal triggered from admin GUI",
                client_ip(request),
            )
            return RedirectResponse(
                url="/certs?msg=Certificate+renewed+successfully",
                status_code=302,
            )
        except TimeoutError:
            return _safe_redirect("/certs",
                                  query={"error": "Certificate renewal timed out"})
        except Exception as exc:
            return _safe_redirect("/certs",
                                  query={"error": f"Renewal failed: {exc}"})

    # ── Backup status ──────────────────────────────────────────────────

    @app.get("/backup", response_class=HTMLResponse)
    async def backup_page(request: Request):
        if not require_role(request, "operator"):
            return login_redirect()

        from .backup_manager import (
            BackupConfig,
            BackupStatus,
            load_config as bk_load_config,
            load_status as bk_load_status,
            restic_installed,
            restic_version,
        )

        bk_config = bk_load_config()
        bk_status = bk_load_status()

        # Format timestamps for display
        def _fmt_ts(ts: int | None) -> str:
            if ts is None:
                return "never"
            return datetime.fromtimestamp(ts, tz=timezone.utc).strftime(
                "%Y-%m-%d %H:%M UTC"
            )

        # Human-readable size
        def _human_size(b: int) -> str:
            for unit in ("B", "K", "M", "G", "T"):
                if b < 1024:
                    return f"{b:.1f}{unit}"
                b /= 1024
            return f"{b:.1f}P"

        error = request.query_params.get("error", "")
        msg = request.query_params.get("msg", "")

        return templates.TemplateResponse(
            request, "backup.html",
            {
                "request": request,
                "csrf_token": get_csrf_token(request),
                "config": bk_config,
                "status": bk_status,
                "restic_installed": restic_installed(),
                "restic_version": restic_version(),
                "last_success_str": _fmt_ts(bk_status.last_success),
                "last_run_str": _fmt_ts(bk_status.last_run),
                "last_failure_str": _fmt_ts(bk_status.last_failure),
                "size_str": _human_size(bk_status.total_size),
                "error": error,
                "msg": msg,
            },
        )

    @app.post("/backup/run")
    async def backup_run(request: Request):
        if not require_role(request, "admin"):
            return login_redirect()

        form = await request.form()
        csrf_token = form.get("csrf_token", "")
        if not validate_csrf(request, csrf_token):
            return RedirectResponse(
                url="/backup?error=Invalid+session+token",
                status_code=302,
            )

        from .backup_manager import run_backup

        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(run_backup, False), timeout=600)
        except TimeoutError:
            return RedirectResponse(
                url="/backup?error=Backup+timed+out+after+10+minutes",
                status_code=302,
            )

        if result == 0:
            audit_log("backup_run", actor_email(request),
                      "manual backup triggered", client_ip(request))
            return RedirectResponse(
                url="/backup?msg=Backup+completed+successfully",
                status_code=302,
            )
        else:
            return RedirectResponse(
                url="/backup?error=Backup+failed+(check+server+logs)",
                status_code=302,
            )

    # ── Backup destination configuration (GUI) ───────────────────────

    @app.post("/backup/configure")
    async def backup_configure(request: Request):
        if not require_role(request, "admin"):
            return login_redirect()

        form = await request.form()
        csrf_token = form.get("csrf_token", "")
        if not validate_csrf(request, csrf_token):
            return RedirectResponse(
                url="/backup?error=Invalid+session+token",
                status_code=302,
            )

        backend = form.get("backend", "local").strip()
        repository = form.get("repository", "").strip()
        password = form.get("password", "")
        access_id = form.get("access_id", "").strip()
        access_key = form.get("access_key", "")
        enable = form.get("enable", "") == "1"

        from .backup_manager import init_repo

        try:
            rc = init_repo(
                repository=repository,
                password=password,
                backend=backend,
                access_id=access_id,
                access_key=access_key,
                enable=enable,
            )
        except Exception as exc:  # real error surfaced, not swallowed
            logger.exception("backup configure failed")
            return RedirectResponse(
                url="/backup?error=" + str(exc).replace(" ", "+"),
                status_code=302,
            )

        if rc == 0:
            audit_log("backup_configure", actor_email(request),
                      f"backup destination set: {backend} ({repository})",
                      client_ip(request))
            return RedirectResponse(
                url="/backup?msg=Backup+destination+configured",
                status_code=302,
            )
        return RedirectResponse(
            url="/backup?error=Backup+configuration+failed+(see+server+logs)",
            status_code=302,
        )

    # ── JSON health endpoint ───────────────────────────────────────────

    # ── API key management ─────────────────────────────────────────

    API_KEYS_PATH = STATE_DIR / "api-keys.json"

    def _load_api_keys() -> list[dict[str, Any]]:
        """Load API keys from disk. Returns list of dicts with metadata."""
        try:
            data = read_json(API_KEYS_PATH)
            return data if isinstance(data, list) else []
        except (FileNotFoundError, ValueError):
            return []

    def _save_api_keys(keys: list[dict[str, Any]]) -> None:
        """Persist API key list to disk."""
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        save_json_private(API_KEYS_PATH, {"keys": keys})

    def _verify_api_key(token: str) -> bool:
        """Check if a Bearer token matches any stored API key (SHA-256).

        Constant-time compare against stored hashes. Does NOT mutate or
        persist state — last_used_at is left to key-creation time, avoiding a
        read-modify-write of the whole key file on every authenticated request
        (which would be a concurrency race under parallel calls).
        """
        if not token.startswith("ktc_"):
            return False
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        keys = _load_api_keys()
        for key in keys:
            if hmac.compare_digest(key.get("key_hash", ""), token_hash):
                return True
        return False

    # ── API key routes ─────────────────────────────────────────────

    @app.get("/api/keys", response_class=HTMLResponse)
    async def api_keys_page(request: Request):
        if not require_role(request, "admin"):
            return login_redirect()
        keys = _load_api_keys()
        return templates.TemplateResponse(
            "api_keys.html", {
                "request": request,
                "keys": keys,
                "csrf_token": get_csrf_token(request),
            }
        )

    @app.post("/api/keys/create")
    async def api_key_create(request: Request):
        if not require_role(request, "admin"):
            return forbidden_response()
        form = await request.form()
        if not validate_csrf(request, str(form.get("csrf_token", ""))):
            return templates.TemplateResponse(
                "api_keys.html", {
                    "request": request,
                    "keys": _load_api_keys(),
                    "csrf_token": get_csrf_token(request),
                    "error": "Invalid CSRF token",
                },
                status_code=403,
            )
        description = str(form.get("description", "")).strip()

        raw_key = "ktc_" + secrets.token_hex(32)
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

        keys = _load_api_keys()
        keys.append({
            "id": secrets.token_hex(8),
            "key_hash": key_hash,
            "description": description or "Unnamed key",
            "created_at": int(time.time()),
            "last_used_at": 0,
        })
        _save_api_keys(keys)

        # Show the key once, never again
        return templates.TemplateResponse(
            "api_key_created.html", {
                "request": request,
                "raw_key": raw_key,
                "description": description,
                "csrf_token": get_csrf_token(request),
            },
        )

    @app.post("/api/keys/revoke")
    async def api_key_revoke(request: Request):
        if not require_role(request, "admin"):
            return forbidden_response()
        form = await request.form()
        if not validate_csrf(request, str(form.get("csrf_token", ""))):
            return templates.TemplateResponse(
                "api_keys.html", {
                    "request": request,
                    "keys": _load_api_keys(),
                    "csrf_token": get_csrf_token(request),
                    "error": "Invalid CSRF token",
                },
                status_code=403,
            )
        key_id = str(form.get("id", ""))
        keys = _load_api_keys()
        keys = [k for k in keys if k.get("id") != key_id]
        _save_api_keys(keys)
        return RedirectResponse("/api/keys", status_code=303)

    # ── API routes (key-authenticated) ─────────────────────────────

    @app.get("/api/status")
    async def api_status(request: Request):
        # Accept session auth OR Bearer token
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer ") and _verify_api_key(auth_header[7:]):
            pass  # authorized via API key
        elif not require_role(request, "readonly"):
            return login_redirect()

        services = _all_service_status()

        return {
            "services": services,
            "queue_depth": _queue_depth(),
            "user_count": _user_count(),
            "admin_configured": admin_is_configured(),
            "setup_exists": SETUP_PATH.exists(),
            "timestamp": int(time.time()),
        }

    # ── Health check (no auth — for external monitoring) ─────────────

    @app.get("/api/health")
    async def api_health():
        """Unauthenticated health check for monitoring tools.

        Returns service status, queue depth, and certificate expiry.
        No session or auth required — designed for Uptime Kuma,
        Prometheus, Nagios, and similar external health checkers.
        """
        services = _all_service_status()
        queue = _queue_depth()

        # Overall status: all tracked services must be active
        tracked = ("postfix", "dovecot", "rspamd", "nginx",
                   "ktc-mail-olefy", "ktc-mail-mta-sts")
        all_active = all(services.get(s) == "active" for s in tracked)
        overall = "healthy" if all_active and queue >= 0 else "degraded"

        # Cert expiry
        cert_days: int | None = None
        cert_path = Path(f"/etc/letsencrypt/live/{CERT_NAME}/fullchain.pem")
        if cert_path.exists():
            info = _cert_info_from_path(cert_path)
            if "end_date" in info:
                cert_days = _cert_expiry_days(info["end_date"])

        return {
            "status": overall,
            "services": services,
            "queue_depth": queue,
            "user_count": _user_count(),
            "cert_expiry_days": cert_days,
            "setup_exists": SETUP_PATH.exists(),
            "timestamp": int(time.time()),
        }

    return app


# ─── CLI handler ──────────────────────────────────────────────────────────────


def cmd_admin_init(args: argparse.Namespace) -> int:
    """Initialize or reset the admin password. Prints the new password."""
    if not args.force and admin_is_configured():
        print("Admin password is already configured.", file=sys.stderr)
        print("Use --force to reset.", file=sys.stderr)
        return 1

    password = bootstrap_admin_password()
    print(f"Admin password initialized: {password}", file=sys.stderr)
    print(f"Stored at: {ADMIN_HASH_PATH}", file=sys.stderr)
    print()
    print("LOGIN WITH:", file=sys.stderr)
    profile = None
    if SETUP_PATH.exists():
        try:
            profile = SetupProfile.from_dict(read_json(SETUP_PATH))
            print(f"  Email: {profile.admin_email}", file=sys.stderr)
        except (OSError, ValueError, json.JSONDecodeError):
            pass
    print(f"  Password: {password}", file=sys.stderr)
    print()
    print("CHANGE THIS PASSWORD after first login via the web interface.",
          file=sys.stderr)
    return 0


def cmd_admin_start(args: argparse.Namespace) -> int:
    """Start the admin web server."""
    setup_logging(level=args.log_level or logging.INFO)
    if not admin_is_configured():
        print("Admin password not configured.", file=sys.stderr)
        print("Run: ktc-mail admin init", file=sys.stderr)
        return 1

    # Bind is ALWAYS loopback. The admin GUI is authenticated but still must
    # not bind 0.0.0.0 raw — there is no TLS terminator here. Remote access
    # goes through the rendered nginx proxy (ktc-mail-admin vhost) which
    # terminates TLS and enforces the CSP/HSTS headers. No --expose flag.
    host = "127.0.0.1"
    port = args.port

    app = create_app()

    print(f"KTC Mail admin: http://{host}:{port}")
    print(f"Login with admin credentials (set via 'ktc-mail admin init')")

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level=args.log_level or "info",
        access_log=args.access_log,
    )
    return 0


def cmd_admin_check(args: argparse.Namespace) -> int:
    """Check admin configuration status."""
    configured = admin_is_configured()
    print(f"Admin configured: {'YES' if configured else 'NO'}")
    if SETUP_PATH.exists():
        print(f"Setup profile: {SETUP_PATH} (exists)")
    else:
        print(f"Setup profile: {SETUP_PATH} (MISSING — run setup first)")
    return 0 if configured else 1


# ── Argparse subcommand builder ──────────────────────────────────────────────


def add_subparser(sub) -> None:
    """Add the 'admin' subcommand parser to the CLI."""
    p_admin = sub.add_parser("admin", help="Admin web interface management")
    p_admin.add_argument(
        "admin_cmd",
        choices=("start", "init", "check", "break-glass"),
        help="admin start | init | check | break-glass",
    )
    p_admin.add_argument(
        "--operator", default="",
        help="Operator identity requesting break-glass access",
    )
    p_admin.add_argument(
        "--reason", default="",
        help="Why normal auth is unavailable (audited)",
    )
    p_admin.add_argument(
        "--ttl", type=int, default=900,
        help="Token validity in seconds (default 900)",
    )
    p_admin.add_argument(
        "--i-understand", action="store_true",
        help="REQUIRED: acknowledge this is a single-use audited credential",
    )
    p_admin.add_argument("--host", default="127.0.0.1",
                         help="Bind address (fixed at 127.0.0.1; use the "
                              "rendered nginx reverse proxy for remote access)")
    p_admin.add_argument("--port", type=int, default=8081,
                         help="Listen port (default 8081)")
    p_admin.add_argument("--force", action="store_true",
                         help="Force re-initialization of admin password")
    p_admin.add_argument("--log-level", default=None,
                         choices=("debug", "info", "warning", "error"),
                         help="Log level")
    p_admin.add_argument("--access-log", action="store_true",
                         help="Enable uvicorn access log")


def dispatch(args: argparse.Namespace) -> int:
    """Dispatch admin subcommands."""
    dispatch_map = {
        "init": cmd_admin_init,
        "start": cmd_admin_start,
        "check": cmd_admin_check,
        "break-glass": cmd_admin_breakglass,
    }
    handler = dispatch_map.get(args.admin_cmd)
    if handler is None:
        return 1
    return handler(args)


def cmd_admin_breakglass(args: argparse.Namespace) -> int:
    """Issue a single-use break-glass operator token (Phase 5).

    Requires explicit --i-understand.  The plaintext token is printed
    ONCE to stdout; only its SHA-256 hash is persisted (0400 file).
    Every use is audited via the admin audit log.
    """
    if not args.i_understand:
        print(
            "error: break-glass is a single-use audited credential.",
            file=sys.stderr,
        )
        print(
            "Re-run with --i-understand to acknowledge.",
            file=sys.stderr,
        )
        return 1
    if not args.operator:
        print("error: --operator <identity> is required", file=sys.stderr)
        return 1
    if not args.reason:
        print("error: --reason <why> is required (audited)", file=sys.stderr)
        return 1
    from .breakglass import issue as breakglass_issue

    token = breakglass_issue(
        operator=args.operator,
        reason=args.reason,
        ttl=args.ttl,
    )
    # Mirror into the append-only audit log.
    try:
        audit_log(
            "break_glass", args.operator,
            f"issued ({args.ttl}s TTL): {args.reason}",
            "local",
        )
    except Exception:  # auditing must not block issuance
        pass
    print("BREAK-GLASS TOKEN (single use, show ONCE):")
    print(f"  {token.token}")
    print(f"  expires: {token.expires_at} (TTL {args.ttl}s)")
    print("Stored hashed at /etc/ktc-mail/breakglass.token (0400).")
    print("Use it once to log in as operator, then rotate.")
    return 0


# ── Direct entry point (for testing) ─────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(description="KTC Mail admin server")
    parser.add_argument("command", nargs="?",
                        choices=("start", "init", "check"), default="start")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--expose", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--log-level", default=None)
    parser.add_argument("--access-log", action="store_true")
    args = parser.parse_args()

    sub_dispatch = {
        "init": cmd_admin_init,
        "start": cmd_admin_start,
        "check": cmd_admin_check,
    }
    handler = sub_dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        return 1
    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
