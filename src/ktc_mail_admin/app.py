#!/usr/bin/env python3
"""KTC Mail initial bare-metal web setup wizard.

This intentionally uses the Python standard library so the first boot GUI can
start immediately after a .deb install, before the rest of the mail stack has
been configured.
"""

from __future__ import annotations

import argparse
import html
import ipaddress
import json
import os
import re
import subprocess
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

CONFIG_DIR = Path(os.environ.get("KTC_MAIL_CONFIG_DIR", "/etc/ktc-mail"))
STATE_DIR = Path(os.environ.get("KTC_MAIL_STATE_DIR", "/var/lib/ktc-mail"))
SETUP_PATH = CONFIG_DIR / "setup.json"
SECRETS_PATH = CONFIG_DIR / "secrets.json"
DEFAULT_OPEN_PORTS = [22, 25, 443, 587, 993, 4190]
HTTP01_OPEN_PORTS = [22, 25, 80, 443, 587, 993, 4190]

IMPLEMENTATION_PHASES = [
    ("Phase 0", "Threat model and hard rules"),
    ("Phase 1", "First-run installer and setup profile"),
    ("Phase 2", "DNS and certificate automation"),
    ("Phase 3", "Mail stack configuration"),
    ("Phase 4", "Firewall and abuse controls"),
    ("Phase 5", "Admin GUI and identity"),
    ("Phase 6", "Backup, restore, and observability"),
    ("Phase 7", "Release hardening"),
]
DOMAIN_PATTERN = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")
HOSTNAME_PATTERN = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")


CSS = """
:root { color-scheme: light; --ink:#1f2a44; --brand:#5b67f1; --warm:#ffb86b; --ok:#1f9d55; }
* { box-sizing: border-box; }
body { margin: 0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif; background: linear-gradient(135deg,#eef4ff,#fff7ed); color: var(--ink); }
header { padding: 2.5rem clamp(1rem, 4vw, 4rem); background: radial-gradient(circle at top left,#ffffff 0,#e4e8ff 45%,#ffe7c7 100%); }
.logo { display:inline-flex; align-items:center; gap:.75rem; font-weight:800; font-size:1.6rem; }
.logo span:first-child { display:grid; place-items:center; width:3rem; height:3rem; border-radius:1rem; background:var(--brand); color:white; box-shadow:0 1rem 2rem #5b67f155; }
main { max-width: 1120px; margin: -1.5rem auto 3rem; padding: 0 1rem; }
.hero, .card { background: rgba(255,255,255,.9); border:1px solid #ffffff; border-radius: 28px; box-shadow:0 24px 70px #52607a24; }
.hero { padding: clamp(1.5rem, 4vw, 3rem); display:grid; grid-template-columns: minmax(0,1.25fr) minmax(280px,.75fr); gap:2rem; }
h1 { font-size: clamp(2rem,5vw,4rem); line-height:1; margin:.2rem 0 1rem; letter-spacing:-.05em; }
.pill { display:inline-flex; align-items:center; gap:.5rem; background:#ecfdf5; color:#065f46; border:1px solid #bbf7d0; padding:.45rem .8rem; border-radius:999px; font-weight:700; }
.grid { display:grid; grid-template-columns: repeat(auto-fit,minmax(240px,1fr)); gap:1rem; margin-top:1rem; }
.card { padding:1.25rem; }
.card h3 { margin:.2rem 0 .4rem; }
form { display:grid; gap:1rem; }
label { display:grid; gap:.35rem; font-weight:700; }
input, select { width:100%; border:1px solid #cbd5e1; border-radius:14px; padding:.85rem 1rem; font:inherit; background:white; }
button { border:0; border-radius:16px; padding:1rem 1.2rem; font-weight:800; font:inherit; color:white; background:linear-gradient(135deg,var(--brand),#8b5cf6); cursor:pointer; box-shadow:0 1rem 2rem #5b67f144; }
.records { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background:#0f172a; color:#e2e8f0; border-radius:18px; padding:1rem; overflow:auto; }
.notice { border-left:5px solid var(--warm); background:#fff7ed; padding:1rem; border-radius:16px; }
.error { border-left-color:#ef4444; background:#fef2f2; }
@media (max-width: 760px) { .hero { grid-template-columns:1fr; } }
"""


def dns_records(domain: str, hostname: str, admin_host: str, webmail_host: str, public_ipv4: str, public_ipv6: str = "") -> list[dict[str, str]]:
    """Return baseline DNS records required for a modern mail domain."""
    records = [
        {"type": "A", "name": hostname, "value": public_ipv4, "purpose": "Mail host address"},
        {"type": "CNAME", "name": admin_host, "value": f"{hostname}.", "purpose": "Admin GUI endpoint, separate from webmail"},
        {"type": "CNAME", "name": webmail_host, "value": f"{hostname}.", "purpose": "SOGo webmail endpoint"},
        {"type": "MX", "name": domain, "value": f"10 {hostname}.", "purpose": "Inbound mail routing"},
        {"type": "TXT", "name": domain, "value": "v=spf1 mx -all", "purpose": "SPF anti-spoofing"},
        {"type": "TXT", "name": f"_dmarc.{domain}", "value": "v=DMARC1; p=quarantine; rua=mailto:dmarc@" + domain, "purpose": "DMARC reporting and policy"},
        {"type": "TXT", "name": f"_smtp._tls.{domain}", "value": "v=TLSRPTv1; rua=mailto:tls-rpt@" + domain, "purpose": "SMTP TLS reporting"},
        {"type": "TXT", "name": f"default._domainkey.{domain}", "value": "<rspamd generated DKIM public key>", "purpose": "DKIM signing"},
        {"type": "TLSA", "name": f"_25._tcp.{hostname}", "value": "<DANE TLSA from active certificate>", "purpose": "Optional DANE SMTP TLS pin, update on renewal"},
        {"type": "SRV", "name": f"_submission._tcp.{domain}", "value": f"0 1 587 {hostname}.", "purpose": "Autodiscovery for submission"},
        {"type": "SRV", "name": f"_imaps._tcp.{domain}", "value": f"0 1 993 {hostname}.", "purpose": "Autodiscovery for IMAPS"},
    ]
    if public_ipv6:
        records.insert(1, {"type": "AAAA", "name": hostname, "value": public_ipv6, "purpose": "Mail host IPv6 address"})
    return records


def open_ports_for(certificate_mode: str) -> list[int]:
    if certificate_mode == "http-01":
        return HTTP01_OPEN_PORTS.copy()
    return DEFAULT_OPEN_PORTS.copy()


def render_page(title: str, body: str, status: HTTPStatus = HTTPStatus.OK) -> bytes:
    document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)} · KTC Mail</title>
  <style>{CSS}</style>
</head>
<body>
<header><div class="logo"><span>✉</span><span>KTC Mail</span></div></header>
<main>{body}</main>
</body>
</html>"""
    return document.encode("utf-8")


def save_json_private(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)


def save_setup(values: dict[str, str]) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    admin_host = values.get("admin_host", f"admin.{values['domain']}")
    webmail_host = values.get("webmail_host", f"webmail.{values['domain']}")
    payload = {
        "domain": values["domain"],
        "hostname": values["hostname"],
        "admin_host": admin_host,
        "webmail_host": webmail_host,
        "admin_email": values["admin_email"],
        "public_ipv4": values["public_ipv4"],
        "public_ipv6": values.get("public_ipv6", ""),
        "dns_provider": values["dns_provider"],
        "certificate_mode": values["certificate_mode"],
        "manage_system_hostname": values.get("manage_system_hostname") == "on",
        "open_ports": open_ports_for(values["certificate_mode"]),
        "dns_records": dns_records(values["domain"], values["hostname"], admin_host, webmail_host, values["public_ipv4"], values.get("public_ipv6", "")),
        "renewal_hooks": {
            "update_tlsa_on_certificate_renewal": values["certificate_mode"] == "dns-01-api",
            "reload_services": ["postfix", "dovecot", "nginx"],
        },
        "abuse_controls": {
            "crowdsec_decision": "defer until package maturity and ops policy are approved",
            "submission_message_rate_limit": 100,
            "submission_connection_rate_limit": 20,
            "sasl_auth_failures_findtime": 600,
            "sasl_auth_failures_maxretry": 5,
            "quarantine_group": "ktc-quarantine",
        },
        "ops_controls": {
            "backup_repository": "sftp:user@backup-host:/srv/restic/ktc-mail",
            "backup_paths": ["/etc/ktc-mail", "/var/lib/ktc-mail", "/var/vmail", "/var/lib/rspamd/dkim"],
            "retention": {"daily": 7, "weekly": 4, "monthly": 6},
            "queue_alert_threshold": 500,
            "disk_alert_percent": 85,
            "certificate_expiry_days": 21,
            "audit_log_target": "local-jsonl; remote syslog/SIEM pending",
        },
        "implementation_phase": "Phase 6",
    }
    save_json_private(SETUP_PATH, payload)
    token = values.get("dns_api_token", "")
    if token:
        save_json_private(SECRETS_PATH, {"dns_provider": values["dns_provider"], "dns_api_token": token})


def validate_setup(fields: dict[str, str]) -> list[str]:
    errors: list[str] = []
    if not DOMAIN_PATTERN.match(fields.get("domain", "")):
        errors.append("Enter a valid mail domain such as example.com.")
    if not HOSTNAME_PATTERN.match(fields.get("hostname", "")):
        errors.append("Enter a valid mail server hostname such as mail.example.com.")
    if "@" not in fields.get("admin_email", ""):
        errors.append("Enter a valid administrator email address.")
    try:
        if ipaddress.ip_address(fields.get("public_ipv4", "")).version != 4:
            errors.append("Enter a valid public IPv4 address.")
    except ValueError:
        errors.append("Enter a valid public IPv4 address.")
    public_ipv6 = fields.get("public_ipv6", "")
    if public_ipv6:
        try:
            if ipaddress.ip_address(public_ipv6).version != 6:
                errors.append("Enter a valid public IPv6 address or leave IPv6 blank.")
        except ValueError:
            errors.append("Enter a valid public IPv6 address or leave IPv6 blank.")
    if fields.get("dns_provider") not in {"cloudflare", "route53", "digitalocean", "hetzner", "manual"}:
        errors.append("Choose a supported DNS provider.")
    if fields.get("certificate_mode") not in {"dns-01-api", "http-01", "upload-existing"}:
        errors.append("Choose a valid certificate mode.")
    for host_field in ("admin_host", "webmail_host"):
        if not HOSTNAME_PATTERN.match(fields.get(host_field, "")):
            errors.append(f"Enter a valid {host_field.replace('_', ' ')} such as admin.example.com.")
    if fields.get("admin_host") == fields.get("webmail_host"):
        errors.append("Admin GUI and SOGo webmail hostnames must be different.")
    if fields.get("certificate_mode") == "dns-01-api" and fields.get("dns_provider") == "manual":
        errors.append("DNS-01 API mode needs a real DNS provider, not manual DNS.")
    return errors


def phase_cards() -> str:
    return "".join(
        f"<section class='card'><h3>{html.escape(number)}</h3><p>{html.escape(name)}</p></section>"
        for number, name in IMPLEMENTATION_PHASES
    )


def status_cards() -> str:
    checks = [
        ("Postfix", "postfix", "SMTP transfer agent"),
        ("Dovecot", "dovecot", "IMAP and mailbox access"),
        ("Rspamd", "rspamd", "Spam, DKIM, ARC, DMARC checks"),
        ("Fail2ban", "fail2ban", "Abuse and brute-force response"),
    ]
    cards = []
    for label, unit, description in checks:
        state = "not installed"
        if os.geteuid() == 0:
            result = subprocess.run(["systemctl", "is-active", unit], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
            state = result.stdout.strip() or "unknown"
        cards.append(f"<section class='card'><h3>{html.escape(label)}</h3><p>{html.escape(description)}</p><strong>{html.escape(state)}</strong></section>")
    return "".join(cards)


class KtcMailHandler(BaseHTTPRequestHandler):
    server_version = "KTCMailSetup/0.1"

    def do_GET(self) -> None:
        if self.path not in {"/", "/setup"}:
            self.send_error(HTTPStatus.NOT_FOUND, "Not found")
            return
        body = self.setup_body()
        self.respond(render_page("Setup", body))

    def do_POST(self) -> None:
        if self.path != "/setup":
            self.send_error(HTTPStatus.NOT_FOUND, "Not found")
            return
        length = int(self.headers.get("Content-Length", "0"))
        data = self.rfile.read(length).decode("utf-8")
        fields = {key: values[0].strip() for key, values in parse_qs(data).items()}
        errors = validate_setup(fields)
        if errors:
            body = self.setup_body(errors=errors, fields=fields)
            self.respond(render_page("Setup needs attention", body, HTTPStatus.BAD_REQUEST), HTTPStatus.BAD_REQUEST)
            return
        save_setup(fields)
        records = "\n".join(f"{r['type']:5} {r['name']:35} {r['value']}  # {r['purpose']}" for r in dns_records(fields["domain"], fields["hostname"], fields["admin_host"], fields["webmail_host"], fields["public_ipv4"], fields.get("public_ipv6", "")))
        body = f"""
<section class="hero"><div><span class="pill">✅ Setup profile saved</span><h1>DNS plan ready for {html.escape(fields['domain'])}</h1>
<p>KTC Mail stored the bootstrap profile, least-open firewall ports, separate admin/SOGo hostnames, and renewal hook intent. DNS API tokens are written separately with 0600 permissions.</p>
<div class="records">{html.escape(records)}</div></div><aside class="card"><h3>Next safe step</h3><p>Run the package bootstrap on a fresh Debian or Ubuntu server, then verify DNS before enabling inbound SMTP.</p></aside></section>
"""
        self.respond(render_page("Setup saved", body))

    def setup_body(self, errors: list[str] | None = None, fields: dict[str, str] | None = None) -> str:
        fields = fields or {}
        error_html = ""
        if errors:
            items = "".join(f"<li>{html.escape(error)}</li>" for error in errors)
            error_html = f"<div class='notice error'><strong>Please fix these items:</strong><ul>{items}</ul></div>"
        return f"""
<section class="hero">
  <div>
    <span class="pill">Family-friendly · Bare-metal · Security-first</span>
    <h1>Your mail home base, without containers.</h1>
    <p>KTC Mail will orchestrate rendered mail configs, ACME/DNS automation, nftables-first security controls, admin identity, backups, restore drills, and observability from one guided interface.</p>
    <div class="grid">{status_cards()}</div>
  </div>
  <aside class="card">
    <h3>Initial domain setup</h3>
    {error_html}
    <form method="post" action="/setup">
      <label>Mail domain<input name="domain" placeholder="example.com" value="{html.escape(fields.get('domain',''))}" required></label>
      <label>Mail hostname<input name="hostname" placeholder="mail.example.com" value="{html.escape(fields.get('hostname',''))}" required></label>
      <label>Admin email<input name="admin_email" type="email" placeholder="admin@example.com" value="{html.escape(fields.get('admin_email',''))}" required></label>
      <label>Server public IPv4<input name="public_ipv4" placeholder="203.0.113.10" value="{html.escape(fields.get('public_ipv4',''))}" required></label>
      <label>Server public IPv6<input name="public_ipv6" placeholder="2001:db8::10" value="{html.escape(fields.get('public_ipv6',''))}"></label>
      <label>Admin GUI hostname<input name="admin_host" placeholder="admin.example.com" value="{html.escape(fields.get('admin_host',''))}" required></label>
      <label>SOGo webmail hostname<input name="webmail_host" placeholder="webmail.example.com" value="{html.escape(fields.get('webmail_host',''))}" required></label>
      <label>DNS provider<select name="dns_provider">
        <option value="cloudflare">Cloudflare API</option><option value="route53">AWS Route 53</option><option value="digitalocean">DigitalOcean</option><option value="hetzner">Hetzner DNS</option><option value="manual">Manual DNS for lab use</option>
      </select></label>
      <label>DNS API token<input name="dns_api_token" type="password" autocomplete="off" placeholder="Stored separately with 0600 permissions"></label>
      <label>Certificates<select name="certificate_mode"><option value="dns-01-api">ACME DNS-01 through provider API</option><option value="http-01">ACME HTTP-01, opens port 80</option><option value="upload-existing">Upload existing enterprise certificate</option></select></label>
      <label><input name="manage_system_hostname" type="checkbox"> Let KTC Mail set the system hostname during activation</label>
      <button type="submit">Build DNS, TLS, and firewall plan</button>
    </form>
  </aside>
</section>
<section class="grid">
  <article class="card"><h3>Enterprise controls</h3><p>Planned controls include MFA for admins, immutable audit logs, least-privilege service users, MTA-STS, TLS-RPT, DKIM rotation, DMARC enforcement, and encrypted backups.</p></article>
  <article class="card"><h3>Open source core</h3><p>Use mature packages instead of reinventing mail: Postfix, Dovecot, Rspamd, Redis, Fail2ban, OpenDKIM-compatible DNS, nftables/iptables, and ACME DNS APIs.</p></article>
  <article class="card"><h3>Ports policy</h3><p>Only 22/tcp, 25/tcp, 443/tcp, 587/tcp, 993/tcp, and optional 4190/tcp are expected open. Port 80/tcp is added only for HTTP-01 certificate mode; DNS-01 keeps it closed.</p></article>
</section>
<section class="card"><h2>Build phases</h2><p>This project is being built in locked phases. Current code is Phase 6: admin identity, backup, restore, and observability foundations.</p><div class="grid">{phase_cards()}</div></section>
"""

    def respond(self, body: bytes, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the KTC Mail initial web setup GUI")
    parser.add_argument("--host", default="0.0.0.0", help="Address to bind")
    parser.add_argument("--port", type=int, default=8080, help="Port to bind")
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), KtcMailHandler)
    print(f"KTC Mail setup GUI listening on http://{args.host}:{args.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
