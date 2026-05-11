#!/usr/bin/env python3
"""Phase 5 HTTPS-ready admin portal foundation for KTC Mail."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import time
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

CONFIG_DIR = Path(os.environ.get("KTC_MAIL_CONFIG_DIR", "/etc/ktc-mail"))
STATE_DIR = Path(os.environ.get("KTC_MAIL_STATE_DIR", "/var/lib/ktc-mail"))
ADMIN_PATH = CONFIG_DIR / "admin.json"
SETUP_PATH = CONFIG_DIR / "setup.json"
AUDIT_PATH = STATE_DIR / "admin-audit.jsonl"
SESSION_TTL = 3600
PBKDF2_ROUNDS = 310_000


def now() -> int:
    return int(time.time())


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def hash_password(password: str, salt: bytes | None = None) -> dict[str, str | int]:
    salt = salt or secrets.token_bytes(32)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return {"algorithm": "pbkdf2_sha256", "rounds": PBKDF2_ROUNDS, "salt": b64(salt), "hash": b64(digest)}


def verify_password(password: str, stored: dict[str, str | int]) -> bool:
    salt = base64.urlsafe_b64decode(str(stored["salt"]))
    expected = base64.urlsafe_b64decode(str(stored["hash"]))
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(stored["rounds"]))
    return hmac.compare_digest(digest, expected)


def read_json(path: Path, default: dict) -> dict:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def write_private(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)


def audit(event: str, user: str, address: str, ok: bool, detail: str = "") -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    record = {"ts": now(), "event": event, "user": user, "address": address, "ok": ok, "detail": detail}
    with AUDIT_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
    AUDIT_PATH.chmod(0o600)


def bootstrap_admin(email: str, password: str) -> None:
    if ADMIN_PATH.exists():
        raise RuntimeError(f"admin already bootstrapped: {ADMIN_PATH}")
    payload = {
        "users": {
            email: {
                "password": hash_password(password),
                "roles": ["global_admin", "break_glass"],
                "mfa_required": True,
                "webauthn_credentials": [],
                "recovery_codes": [secrets.token_urlsafe(18) for _ in range(8)],
                "created_at": now(),
            }
        },
        "sessions": {},
    }
    write_private(ADMIN_PATH, payload)


class AdminHandler(BaseHTTPRequestHandler):
    server_version = "KTCMailAdmin/0.1"

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self.respond_json({"ok": True, "phase": "Phase 5"})
            return
        user = self.current_user()
        if self.path == "/" and user:
            self.respond_html("Dashboard", self.dashboard(user))
            return
        if self.path == "/login":
            self.respond_html("Login", self.login_form())
            return
        self.send_response(HTTPStatus.FOUND)
        self.send_header("Location", "/login")
        self.end_headers()

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        fields = {key: values[0] for key, values in parse_qs(self.rfile.read(length).decode("utf-8")).items()}
        if self.path == "/login":
            self.login(fields)
            return
        if self.path == "/logout":
            self.logout(fields)
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def client_address_text(self) -> str:
        return self.client_address[0] if self.client_address else "unknown"

    def admin_state(self) -> dict:
        return read_json(ADMIN_PATH, {"users": {}, "sessions": {}})

    def save_admin_state(self, state: dict) -> None:
        write_private(ADMIN_PATH, state)

    def session_cookie(self) -> str:
        cookie = SimpleCookie(self.headers.get("Cookie"))
        morsel = cookie.get("ktc_admin_session")
        return morsel.value if morsel else ""

    def current_user(self) -> str | None:
        sid = self.session_cookie()
        state = self.admin_state()
        session = state.get("sessions", {}).get(sid)
        if not session or int(session.get("expires_at", 0)) < now():
            return None
        return str(session.get("user"))

    def csrf_token(self, sid: str | None = None) -> str:
        state = self.admin_state()
        session = state.get("sessions", {}).get(sid or self.session_cookie(), {})
        return str(session.get("csrf", ""))

    def valid_csrf(self, fields: dict[str, str]) -> bool:
        token = fields.get("csrf", "")
        expected = self.csrf_token()
        return bool(token and expected and hmac.compare_digest(token, expected))

    def login(self, fields: dict[str, str]) -> None:
        email = fields.get("email", "").strip()
        password = fields.get("password", "")
        state = self.admin_state()
        user = state.get("users", {}).get(email)
        ok = bool(user and verify_password(password, user["password"]))
        audit("login", email, self.client_address_text(), ok)
        if not ok:
            self.respond_html("Login failed", self.login_form("Invalid credentials"), HTTPStatus.UNAUTHORIZED)
            return
        sid = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        state.setdefault("sessions", {})[sid] = {"user": email, "csrf": csrf, "expires_at": now() + SESSION_TTL, "created_at": now()}
        self.save_admin_state(state)
        self.send_response(HTTPStatus.FOUND)
        self.send_header("Set-Cookie", f"ktc_admin_session={sid}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={SESSION_TTL}")
        self.send_header("Location", "/")
        self.end_headers()

    def logout(self, fields: dict[str, str]) -> None:
        if not self.valid_csrf(fields):
            audit("csrf_reject", self.current_user() or "unknown", self.client_address_text(), False, "logout")
            self.send_error(HTTPStatus.FORBIDDEN, "CSRF token rejected")
            return
        sid = self.session_cookie()
        state = self.admin_state()
        user = self.current_user() or "unknown"
        state.get("sessions", {}).pop(sid, None)
        self.save_admin_state(state)
        audit("logout", user, self.client_address_text(), True)
        self.send_response(HTTPStatus.FOUND)
        self.send_header("Set-Cookie", "ktc_admin_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0")
        self.send_header("Location", "/login")
        self.end_headers()

    def login_form(self, error: str = "") -> str:
        error_html = f"<p class='error'>{html.escape(error)}</p>" if error else ""
        return f"""<section class='card'><h1>KTC Mail Admin</h1>{error_html}<form method='post' action='/login'>
<label>Email<input name='email' type='email' required></label>
<label>Password<input name='password' type='password' required></label>
<button type='submit'>Sign in</button></form></section>"""

    def dashboard(self, user: str) -> str:
        setup = read_json(SETUP_PATH, {})
        state = self.admin_state()
        roles = ", ".join(state.get("users", {}).get(user, {}).get("roles", []))
        csrf = html.escape(self.csrf_token())
        return f"""<section class='card'><h1>Admin dashboard</h1><p>Signed in as {html.escape(user)} ({html.escape(roles)})</p>
<ul>
<li>Domain: {html.escape(str(setup.get('domain', 'not configured')))}</li>
<li>Admin host: {html.escape(str(setup.get('admin_host', 'not configured')))}</li>
<li>Webmail host: {html.escape(str(setup.get('webmail_host', 'not configured')))}</li>
<li>Implementation: Phase 5 admin identity foundation</li>
</ul><form method='post' action='/logout'><input type='hidden' name='csrf' value='{csrf}'><button type='submit'>Sign out</button></form></section>"""

    def respond_html(self, title: str, body: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        page = f"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>
<title>{html.escape(title)} · KTC Mail</title><style>body{{font-family:system-ui;margin:2rem;background:#f8fafc;color:#0f172a}}.card{{max-width:720px;background:white;padding:2rem;border-radius:20px;box-shadow:0 10px 30px #0f172a22}}label{{display:block;margin:1rem 0}}input{{width:100%;padding:.8rem}}button{{padding:.8rem 1rem}}.error{{color:#b91c1c}}</style></head><body>{body}</body></html>""".encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.end_headers()
        self.wfile.write(page)

    def respond_json(self, payload: dict, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = (json.dumps(payload) + "\n").encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run KTC Mail admin portal")
    sub = parser.add_subparsers(dest="command")
    run_parser = sub.add_parser("serve")
    run_parser.add_argument("--host", default="127.0.0.1")
    run_parser.add_argument("--port", type=int, default=8081)
    boot = sub.add_parser("bootstrap-admin")
    boot.add_argument("--email", required=True)
    boot.add_argument("--password", required=True)
    args = parser.parse_args()
    if args.command == "bootstrap-admin":
        bootstrap_admin(args.email, args.password)
        return 0
    server = ThreadingHTTPServer((args.host, args.port), AdminHandler)
    print(f"KTC Mail admin portal listening on http://{args.host}:{args.port}")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
