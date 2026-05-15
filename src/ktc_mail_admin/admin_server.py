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
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader
from starlette.middleware.sessions import SessionMiddleware

from . import user_manager as um
from . import mfa as mfa_mod
from .config import (
    CONFIG_DIR,
    SETUP_PATH,
    STATE_DIR,
    SECRETS_PATH,
    TLS_STATE_PATH,
    DNS_STATE_PATH,
    DKIM_DIR,
    BACKUP_STATE_PATH,
    read_json,
    save_json_private,
    SetupProfile,
)

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
    except Exception:
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
    except Exception:
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
        "updated_at": 0,
    }
    if not ADMIN_HASH_PATH.exists():
        return default
    try:
        data = read_json(ADMIN_HASH_PATH)
        default.update(data)
        return default
    except Exception:
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
    except Exception:
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

    svcs = ["postfix", "dovecot", "rspamd", "nginx", "redis-server"]
    try:
        result = subprocess.run(
            ["systemctl", "show", "-p", "ActiveState", "--value", *svcs],
            capture_output=True, text=True, timeout=5,
        )
    except Exception:
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
    except Exception:
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
    except Exception:
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
    except Exception:
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
        except Exception:
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


# ── Certificate helpers ────────────────────────────────────────────────────────


def _cert_info_from_path(cert_path: Path) -> dict[str, Any]:
    """Parse certificate metadata using openssl.

    Returns a dict with keys: end_date, issuer, subject, sans, fingerprint.
    Empty dict if the cert file does not exist or parsing fails.
    """
    info: dict[str, Any] = {}
    if not cert_path.exists():
        return info
    try:
        # End date
        r = subprocess.run(
            ["openssl", "x509", "-in", str(cert_path), "-noout", "-enddate"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0 and r.stdout.strip():
            info["end_date"] = r.stdout.strip().replace("notAfter=", "")

        # Issuer
        r = subprocess.run(
            ["openssl", "x509", "-in", str(cert_path), "-noout", "-issuer"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0 and r.stdout.strip():
            info["issuer"] = r.stdout.strip().replace("issuer=", "")

        # Subject
        r = subprocess.run(
            ["openssl", "x509", "-in", str(cert_path), "-noout", "-subject"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0 and r.stdout.strip():
            info["subject"] = r.stdout.strip().replace("subject=", "")

        # SANs
        r = subprocess.run(
            ["openssl", "x509", "-in", str(cert_path), "-noout",
             "-ext", "subjectAltName"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0 and r.stdout.strip():
            info["sans"] = r.stdout.strip()

        # SHA-256 fingerprint
        r = subprocess.run(
            ["openssl", "x509", "-in", str(cert_path), "-noout",
             "-fingerprint", "-sha256"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0 and r.stdout.strip():
            info["fingerprint"] = (
                r.stdout.strip().replace("SHA256 Fingerprint=", "")
            )
    except Exception:
        logger.exception("reading cert info from %s", cert_path)
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


# ── FastAPI app setup ─────────────────────────────────────────────────────────


def create_app() -> FastAPI:
    """Create and configure the FastAPI admin application."""
    app = FastAPI(title="KTC Mail Admin")

    # ── Session key ───────────────────────────────────────────────────
    # Generate a random key on first start, persist it so sessions
    # survive restarts. The key is unique per install, unlike a
    # deterministic hash of a known value.
    session_key: str = ""
    sk_path = CONFIG_DIR / "session-key"
    if sk_path.exists():
        try:
            session_key = sk_path.read_text(encoding="utf-8").strip()
        except Exception:
            pass
    if not session_key:
        session_key = secrets.token_hex(32)
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        try:
            sk_path.write_text(session_key, encoding="utf-8")
            sk_path.chmod(0o600)
        except Exception:
            logger.exception("writing session key to %s", sk_path)

    # Allow env override for testing
    session_key = os.environ.get("KTC_ADMIN_SECRET", session_key)

    # Allow env override for dev/testing over plain HTTP.
    # Production defaults to True (Secure flag on session cookie).
    https_only = os.environ.get("KTC_SESSION_HTTPS", "1") == "1"

    app.add_middleware(
        SessionMiddleware,
        secret_key=session_key,
        session_cookie="ktc_admin_session",
        max_age=86400,  # 24 hours
        same_site="lax",
        https_only=https_only,
    )

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
        except Exception:
            return "unknown"
    templates.env.filters["datetime_from_ts"] = datetime_from_ts

    # ── Auth / RBAC helpers ────────────────────────────────────────────

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
        return request.session.get("authenticated", False)

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
        """Extract client IP from request, respecting X-Forwarded-For."""
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
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
        error = request.query_params.get("error", "")

        return templates.TemplateResponse(
            request, "login.html",
            {
                "request": request,
                "error": error,
                "csrf_token": get_csrf_token(request),
                "mfa_step": is_mfa_step,
            },
        )

    @app.post("/login")
    async def login_post(request: Request):
        form = await request.form()
        email = form.get("email", "")
        password = form.get("password", "")
        csrf_token = form.get("csrf_token", "")

        if not validate_csrf(request, csrf_token):
            return RedirectResponse(
                url="/login?error=Invalid+session+token",
                status_code=302,
            )

        acct = load_admin_account()
        stored_hash = acct.get("password_hash", "")
        if not stored_hash:
            return RedirectResponse(
                url="/login?error=Admin+not+configured.+Run+ktc-mail+admin+init",
                status_code=302,
            )

        if not verify_password(password, stored_hash):
            return RedirectResponse(
                url="/login?error=Invalid+credentials",
                status_code=302,
            )

        # Password OK — check if MFA is required
        mfa_enabled = bool(acct.get("mfa_enabled", False))
        if mfa_enabled:
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

        audit_log("login", email, "login (no MFA)", client_ip(request))
        return RedirectResponse(url="/", status_code=302)

    @app.post("/login/mfa")
    async def login_mfa(request: Request):
        """Verify TOTP code after password authentication."""
        if not request.session.get("mfa_pending", False):
            return RedirectResponse(url="/login", status_code=302)

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
            return RedirectResponse(
                url="/login?error=Invalid+verification+code",
                status_code=302,
            )

        email = request.session.get("mfa_pending_email", "unknown")
        request.session["authenticated"] = True
        request.session["email"] = email
        request.session["role"] = acct.get("role", DEFAULT_ROLE)
        request.session["mfa_verified"] = True
        request.session["login_time"] = int(time.time())
        # Clear pending state
        request.session.pop("mfa_pending", None)
        request.session.pop("mfa_pending_email", None)
        request.session.pop("mfa_pending_time", None)

        audit_log("login", email, "login (MFA)", client_ip(request))
        return RedirectResponse(url="/", status_code=302)

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

        if not email or not password:
            return RedirectResponse(
                url="/users?error=Email+and+password+required",
                status_code=302,
            )

        result = um.user_add(email, password=password, quota=quota, dry_run=False)
        if result != 0:
            return RedirectResponse(
                url=f"/users?error=Failed+to+add+{email}",
                status_code=302,
            )

        audit_log("user_add", actor_email(request), email, client_ip(request))
        return RedirectResponse(
            url=f"/users?msg=Added+{email}",
            status_code=302,
        )

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

        if not email:
            return RedirectResponse(
                url="/users?error=Email+required",
                status_code=302,
            )

        result = um.user_delete(email, dry_run=False)
        if result != 0:
            return RedirectResponse(
                url=f"/users?error=Failed+to+remove+{email}",
                status_code=302,
            )

        audit_log("user_del", actor_email(request), email, client_ip(request))
        return RedirectResponse(
            url=f"/users?msg=Removed+{email}",
            status_code=302,
        )

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

        if not email or not password:
            return RedirectResponse(
                url="/users?error=Email+and+password+required",
                status_code=302,
            )

        result = um.user_passwd(email, dry_run=False, password=password)
        if result != 0:
            return RedirectResponse(
                url=f"/users?error=Failed+to+change+password+for+{email}",
                status_code=302,
            )

        audit_log("user_passwd", actor_email(request), email, client_ip(request))

    # ── Settings ────────────────────────────────────────────────────────

    @app.get("/settings", response_class=HTMLResponse)
    async def settings_page(request: Request):
        if not require_role(request, "admin"):
            return login_redirect()

        profile = _load_profile()
        admin_email = profile.admin_email if profile else ""
        mfa = account_mfa_status()

        error = request.query_params.get("error", "")
        msg = request.query_params.get("msg", "")

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
        save_admin_account(acct)

        audit_log(
            "mfa_disable", actor_email(request),
            "MFA disabled", client_ip(request),
        )
        return RedirectResponse(
            url="/settings?msg=Two-factor+authentication+disabled",
            status_code=302,
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
        # Don't enable yet — must verify first code
        acct["mfa_enabled"] = False
        save_admin_account(acct)

        audit_log(
            "mfa_init", actor_email(request),
            "MFA secret generated", client_ip(request),
        )
        return RedirectResponse(
            url="/settings?msg=MFA+secret+generated.+Scan+the+QR+code+and+verify",
            status_code=302,
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
        if not selector or "/" in selector or ".." in selector:
            return RedirectResponse(
                url="/dkim?error=Invalid+selector",
                status_code=302,
            )

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
            key_path.write_bytes(priv_pem)
            key_path.chmod(0o600)
            audit_log(
                "dkim_generate", actor_email(request),
                f"selector={selector}", client_ip(request),
            )
            return RedirectResponse(url="/dkim", status_code=302)
        except Exception as exc:
            return RedirectResponse(
                url=f"/dkim?error=Generation+failed:+{exc}",
                status_code=302,
            )

    # ── Log viewer ─────────────────────────────────────────────────────

    @app.get("/logs", response_class=HTMLResponse)
    async def logs_page(request: Request):
        if not require_role(request, "operator"):
            return login_redirect()

        source = request.query_params.get("source", "mail")
        raw_lines = request.query_params.get("lines", "100")
        filter_str = request.query_params.get("filter", "")

        try:
            n_lines = max(10, min(int(raw_lines), 2000))
        except (ValueError, TypeError):
            n_lines = 100

        if source == "audit":
            log_path = AUDIT_LOG_PATH
        else:
            log_path = Path("/var/log/mail.log")

        log_text = _tail_file(log_path, n_lines)

        if filter_str:
            log_lines = log_text.splitlines()
            filtered = [
                l for l in log_lines if filter_str.lower() in l.lower()
            ]
            log_text = "\n".join(filtered) if filtered else "(no matching lines)"

        return templates.TemplateResponse(
            request, "logs.html",
            {
                "request": request,
                "source": source,
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
                msg = f"Found+{len(issues)}+issues"
                return RedirectResponse(
                    url=f"/dns?msg={msg}",
                    status_code=302,
                )
            return RedirectResponse(
                url="/dns?msg=All+records+verified+OK",
                status_code=302,
            )
        except Exception as exc:
            return RedirectResponse(
                url=f"/dns?error=Verification+failed:+{exc}",
                status_code=302,
            )

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
            actions = sync_records(local, transport, profile.domain,
                                   dry_run=False)

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
        except Exception as exc:
            return RedirectResponse(
                url=f"/dns?error=Sync+failed:+{exc}",
                status_code=302,
            )

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
            return RedirectResponse(
                url=f"/queue?error=Flush+failed:+{exc}",
                status_code=302,
            )

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
            return RedirectResponse(
                url=f"/queue?error=Delete+failed:+{exc}",
                status_code=302,
            )

    # ── Certificate status ─────────────────────────────────────────────

    @app.get("/certs", response_class=HTMLResponse)
    async def certs_page(request: Request):
        if not require_role(request, "admin"):
            return login_redirect()

        profile = _load_profile()
        tls_state = _read_state(TLS_STATE_PATH)

        cert_details: dict[str, Any] = {}
        cert_path = Path("/etc/letsencrypt/live/ktc-mail/fullchain.pem")
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

            result = acme_renew(dry_run=False)
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
        except Exception as exc:
            return RedirectResponse(
                url=f"/certs?error=Renewal+failed:+{exc}",
                status_code=302,
            )

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

        result = run_backup(dry_run=False)
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

    # ── JSON health endpoint ───────────────────────────────────────────

    @app.get("/api/status")
    async def api_status(request: Request):
        if not require_role(request, "readonly"):
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
        tracked = ("postfix", "dovecot", "rspamd", "nginx")
        all_active = all(services.get(s) == "active" for s in tracked)
        overall = "healthy" if all_active and queue >= 0 else "degraded"

        # Cert expiry
        cert_days: int | None = None
        cert_path = Path("/etc/letsencrypt/live/ktc-mail/fullchain.pem")
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
        except Exception:
            pass
    print(f"  Password: {password}", file=sys.stderr)
    print()
    print("CHANGE THIS PASSWORD after first login via the web interface.",
          file=sys.stderr)
    return 0


def cmd_admin_start(args: argparse.Namespace) -> int:
    """Start the admin web server."""
    if not admin_is_configured():
        print("Admin password not configured.", file=sys.stderr)
        print("Run: ktc-mail admin init", file=sys.stderr)
        return 1

    host = "0.0.0.0" if args.expose else args.host
    port = args.port

    app = create_app()

    if host == "0.0.0.0":
        print(f"WARNING: Listening on all interfaces. Use a firewall.",
              file=sys.stderr)
        print(f"         If behind Nginx, bind to 127.0.0.1 instead.",
              file=sys.stderr)

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
        choices=("start", "init", "check"),
        help="admin start | init | check",
    )
    p_admin.add_argument("--host", default="127.0.0.1",
                         help="Bind address (default 127.0.0.1)")
    p_admin.add_argument("--port", type=int, default=8081,
                         help="Listen port (default 8081)")
    p_admin.add_argument("--expose", action="store_true",
                         help="Bind to 0.0.0.0 (behind reverse proxy)")
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
    }
    handler = dispatch_map.get(args.admin_cmd)
    if handler is None:
        return 1
    return handler(args)


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
