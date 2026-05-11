#!/usr/bin/env python3
"""KTC Mail — caveman-simple first-run web setup wizard.

Three fields. Everything else is auto-detected.

Architecture:
  - Python stdlib only (no Flask, no jinja2, no pip dependencies)
  - Three screens: Welcome → Auto-detect → Execute
  - Hidden "Advanced" toggle for enterprise knobs
  - ThreadingHTTPServer (single admin user, short-lived)
"""

from __future__ import annotations

import argparse
import html
import json
import os
import sys
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

from .config import (
    CONFIG_DIR,
    STATE_DIR,
    SETUP_PATH,
    SECRETS_PATH,
    SetupProfile,
    SecurityPolicy,
    SmtpRelayConfig,
    DkimKeyPair,
    save_json_private,
    detect_public_ipv4,
    detect_public_ipv6,
    detect_port_25_blocked,
    detect_registrar,
    validate_domain,
    system_hostname,
    PROVIDER_CLOUDFLARE,
    PROVIDER_NAMEECHEAP,
    PROVIDER_GODADDY,
    PROVIDER_PORKBUN,
    PROVIDER_ROUTE53,
    PROVIDER_DIGITALOCEAN,
    PROVIDER_HETZNER,
    PROVIDER_MANUAL,
    ALL_PROVIDERS,
)

from . import dns_provider as dns


# ── CSS (single block, loaded once) ─────────────────────────────────────────

CSS = """
:root {
  color-scheme: light;
  --ink: #1f2a44;
  --brand: #5b67f1;
  --warm: #f59e0b;
  --ok: #10b981;
  --red: #ef4444;
  --bg: #f8fafc;
  --card: #ffffff;
  --border: #e2e8f0;
  --muted: #64748b;
}
* { box-sizing: border-box; margin: 0; }
body {
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, sans-serif;
  background: var(--bg);
  color: var(--ink);
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}
header {
  padding: 1.5rem 2rem;
  background: var(--card);
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  gap: 0.75rem;
}
.logo-mark {
  display: grid; place-items: center;
  width: 2.5rem; height: 2.5rem;
  border-radius: 0.75rem;
  background: var(--brand);
  color: white;
  font-weight: 800;
  font-size: 1.25rem;
}
.logo-text { font-weight: 800; font-size: 1.25rem; letter-spacing: -0.02em; }
.logo-version { color: var(--muted); font-size: 0.75rem; margin-left: 0.5rem; }
main {
  flex: 1;
  max-width: 720px;
  width: 100%;
  margin: 2rem auto;
  padding: 0 1rem;
}
.card {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 1.25rem;
  padding: 2rem;
  box-shadow: 0 1px 3px rgba(0,0,0,0.05);
}
.card + .card { margin-top: 1rem; }
h1 { font-size: 1.75rem; font-weight: 800; letter-spacing: -0.03em; margin-bottom: 0.5rem; }
h2 { font-size: 1.25rem; font-weight: 700; margin-bottom: 0.5rem; }
p { color: var(--muted); line-height: 1.5; margin-bottom: 1rem; }
label { display: block; font-weight: 600; margin-top: 1rem; margin-bottom: 0.3rem; }
input, select {
  width: 100%;
  padding: 0.75rem 1rem;
  border: 1px solid var(--border);
  border-radius: 0.75rem;
  font: inherit;
  font-size: 1rem;
  background: var(--card);
  transition: border-color 0.15s;
}
input:focus, select:focus {
  outline: none;
  border-color: var(--brand);
  box-shadow: 0 0 0 3px rgba(91,103,241,0.15);
}
button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  width: 100%;
  padding: 0.85rem 1.5rem;
  border: 0;
  border-radius: 0.85rem;
  font: inherit;
  font-size: 1rem;
  font-weight: 700;
  color: white;
  background: linear-gradient(135deg, var(--brand), #8b5cf6);
  cursor: pointer;
  margin-top: 1.25rem;
  transition: opacity 0.15s;
}
button:hover { opacity: 0.9; }
button.secondary {
  background: var(--card);
  color: var(--ink);
  border: 1px solid var(--border);
  background: none;
}
button.success { background: var(--ok); }
button.warning { background: var(--warm); color: #1a1a1a; }
.btn-row { display: flex; gap: 0.75rem; margin-top: 1.25rem; }
.btn-row button { margin-top: 0; }
.check-row { display: flex; align-items: flex-start; gap: 0.75rem; margin-top: 1rem; }
.check-row input[type=checkbox] { width: auto; margin-top: 0.3rem; }
.error-box {
  border-left: 4px solid var(--red);
  background: #fef2f2;
  padding: 1rem;
  border-radius: 0.75rem;
  margin-bottom: 1rem;
}
.error-box li { margin-left: 1.25rem; color: var(--red); }
.warning-box {
  border-left: 4px solid var(--warm);
  background: #fffbeb;
  padding: 1rem;
  border-radius: 0.75rem;
  margin-bottom: 1rem;
}
.info-box {
  border-left: 4px solid var(--brand);
  background: #eef2ff;
  padding: 1rem;
  border-radius: 0.75rem;
  margin-bottom: 1rem;
}
.detection-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.6rem 0;
  border-bottom: 1px solid var(--border);
}
.detection-item:last-child { border-bottom: 0; }
.detection-label { color: var(--muted); }
.detection-value { font-weight: 600; font-family: ui-monospace, monospace; font-size: 0.9rem; }
.detection-badge {
  display: inline-block;
  padding: 0.15rem 0.5rem;
  border-radius: 999px;
  font-size: 0.75rem;
  font-weight: 700;
}
.badge-ok { background: #d1fae5; color: #065f46; }
.badge-warn { background: #fef3c7; color: #92400e; }
.badge-err { background: #fee2e2; color: #991b1b; }
.records {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 0.8rem;
  background: #0f172a;
  color: #e2e8f0;
  border-radius: 0.85rem;
  padding: 1rem;
  overflow-x: auto;
  line-height: 1.6;
  margin-top: 0.75rem;
}
.record-line { white-space: nowrap; }
.record-type { color: #60a5fa; }
.record-name { color: #a78bfa; }
.record-value { color: #34d399; }
.record-purpose { color: #64748b; font-style: italic; }
.dns-ok { color: var(--ok); font-weight: 700; }
.dns-warn { color: var(--warm); font-weight: 700; }
.advanced-toggle {
  display: block;
  text-align: center;
  margin-top: 1rem;
  color: var(--muted);
  cursor: pointer;
  font-size: 0.875rem;
  text-decoration: underline;
  text-underline-offset: 2px;
}
.advanced-toggle:hover { color: var(--ink); }
.advanced-settings { display: none; margin-top: 1rem; padding-top: 1rem; border-top: 1px solid var(--border); }
.advanced-settings.visible { display: block; }
.hostname-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; }
.tag { font-size: 0.75rem; font-weight: 600; padding: 0.15rem 0.4rem; border-radius: 4px; background: var(--border); }
.chk { display: flex; align-items: center; gap: 0.5rem; margin-top: 0.5rem; }
.chk input[type=checkbox] { width: auto; }
"""


# ── HTML helpers ───────────────────────────────────────────────────────────


def _page(title: str, body: str, status: HTTPStatus = HTTPStatus.OK) -> tuple[bytes, HTTPStatus]:
    doc = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)} · KTC Mail</title>
  <style>{CSS}</style>
</head>
<body>
<header>
  <div class="logo-mark">✉</div>
  <span class="logo-text">KTC Mail</span>
  <span class="logo-version">setup</span>
</header>
<main>{body}</main>
</body>
</html>"""
    return doc.encode("utf-8"), status


def _card(title: str, content: str) -> str:
    return f'<div class="card"><h2>{html.escape(title)}</h2>{content}</div>'


def _error_box(errors: list[str]) -> str:
    if not errors:
        return ""
    items = "".join(f"<li>{html.escape(e)}</li>" for e in errors)
    return f'<div class="error-box"><strong>Please fix:</strong><ul>{items}</ul></div>'


def _field(name: str, label: str, value: str = "", placeholder: str = "",
           type: str = "text", required: bool = True) -> str:
    req = " required" if required else ""
    val = f' value="{html.escape(value)}"' if value else ""
    ph = f' placeholder="{html.escape(placeholder)}"' if placeholder else ""
    return f'<label for="{name}">{html.escape(label)}</label><input id="{name}" name="{name}" type="{type}"{val}{ph}{req}>'


def _checkbox(name: str, label: str, checked: bool = False) -> str:
    chk = " checked" if checked else ""
    return f'<div class="chk"><input id="{name}" name="{name}" type="checkbox"{chk}><label for="{name}" style="margin:0">{html.escape(label)}</label></div>'


def _select(name: str, label: str, options: list[tuple[str, str]], selected: str = "") -> str:
    opts = "".join(
        f'<option value="{html.escape(v)}"{' selected' if v == selected else ""}>{html.escape(t)}</option>'
        for v, t in options
    )
    return f'<label for="{name}">{html.escape(label)}</label><select id="{name}" name="{name}">{opts}</select>'


# ── Auto-detection ─────────────────────────────────────────────────────────


@dataclass
class DetectionResult:
    """Results of auto-detection phase."""
    ipv4: str
    ipv6: str
    registrar: str
    port_25_blocked: bool
    current_hostname: str

    @classmethod
    def run(cls) -> DetectionResult:
        return cls(
            ipv4=detect_public_ipv4(),
            ipv6=detect_public_ipv6(),
            registrar=detect_registrar(""),
            port_25_blocked=False,
            current_hostname=system_hostname(),
        )

    def detect_for_domain(self, domain: str) -> None:
        """Run registrar and port detection that needs the domain."""
        if self.registrar:
            return
        self.registrar = detect_registrar(domain)

    def detect_port_25(self) -> None:
        if not self.port_25_blocked:
            self.port_25_blocked = detect_port_25_blocked()


def _provider_display_name(pid: str) -> str:
    names = {
        PROVIDER_CLOUDFLARE: "Cloudflare",
        PROVIDER_NAMEECHEAP: "Namecheap",
        PROVIDER_GODADDY: "GoDaddy",
        PROVIDER_PORKBUN: "Porkbun",
        PROVIDER_ROUTE53: "AWS Route 53",
        PROVIDER_DIGITALOCEAN: "DigitalOcean",
        PROVIDER_HETZNER: "Hetzner",
        PROVIDER_MANUAL: "Manual DNS (I'll add records myself)",
    }
    return names.get(pid, pid)


# ── Request handler ─────────────────────────────────────────────────────────


SESSION: dict[str, Any] = {}


class KtcMailHandler(BaseHTTPRequestHandler):
    server_version = "KTCMailSetup/0.2"

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]

        if path == "/":
            body = self._screen_welcome()
            data, status = _page("Welcome", body)
            return self._respond(data, status)

        if path == "/detect":
            # Show auto-detection results after form submission
            body = self._screen_detect()
            data, status = _page("Auto-detection", body)
            return self._respond(data, status)

        if path == "/plan":
            body = self._screen_plan()
            data, status = _page("DNS plan", body)
            return self._respond(data, status)

        if path == "/done":
            body = self._screen_done()
            data, status = _page("Setup complete", body)
            return self._respond(data, status)

        self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]

        if path == "/detect":
            # Step 1: user submitted the 3 fields
            length = int(self.headers.get("Content-Length", "0"))
            data = self.rfile.read(length).decode("utf-8")
            fields = {key: values[0].strip() for key, values in parse_qs(data).items()}

            errors = self._validate_welcome(fields)
            if errors:
                body = self._screen_welcome(errors, fields)
                data, status = _page("Welcome", body, HTTPStatus.BAD_REQUEST)
                return self._respond(data, status)

            # Build profile and auto-detect
            profile = SetupProfile(
                domain=fields.get("domain", "").strip().lower(),
                dns_api_token=fields.get("dns_api_token", ""),
                admin_email=fields.get("admin_email", "").strip(),
            )

            # Auto-detect
            profile.public_ipv4 = detect_public_ipv4()
            profile.public_ipv6 = detect_public_ipv6()
            profile.has_ipv6 = bool(profile.public_ipv6)
            profile.registrar = detect_registrar(profile.domain)
            profile.port_25_blocked = detect_port_25_blocked()

            # Default DNS provider = detected registrar
            if profile.registrar:
                profile.dns_provider = profile.registrar
            else:
                profile.dns_provider = PROVIDER_CLOUDFLARE

            # Advanced fields (if provided)
            if fields.get("certificate_mode"):
                profile.certificate_mode = fields["certificate_mode"]
            if fields.get("dns_provider"):
                profile.dns_provider = fields["dns_provider"]
            profile.dns_provider_manual = (profile.dns_provider == PROVIDER_MANUAL)

            # SSH policy
            profile.security.ssh_key_only = fields.get("ssh_key_only") != "off"
            if fields.get("ssh_password_auth"):
                profile.security.ssh_password_auth = True
                profile.security.ssh_key_only = False
                profile.security.ssh_password_warning_acknowledged = bool(
                    fields.get("ssh_password_warning")
                )

            # SMTP relay
            if fields.get("smtp_relay_mode"):
                profile.smtp_relay.mode = fields["smtp_relay_mode"]

            # Generate DKIM keys
            profile.dkim = DkimKeyPair.generate()

            # Generate DNS records
            dns_set = profile.generate_dns_records()

            # Save to session
            SESSION["profile"] = profile
            SESSION["dns_set"] = dns_set

            # Redirect to /detect
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", "/detect")
            self.end_headers()
            return

        if path == "/execute":
            # Step 2: user confirmed — execute the setup
            profile: SetupProfile | None = SESSION.get("profile")
            if profile is None:
                self.send_response(HTTPStatus.SEE_OTHER)
                self.send_header("Location", "/")
                self.end_headers()
                return

            # Save setup profile
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            STATE_DIR.mkdir(parents=True, exist_ok=True)
            save_json_private(SETUP_PATH, profile.to_dict())

            # Save secrets separately
            save_json_private(SECRETS_PATH, {
                "dns_provider": profile.dns_provider,
                "dns_api_token": profile.dns_api_token,
            })

            # Save DKIM private key
            if profile.dkim:
                dkim_dir = CONFIG_DIR / "dkim"
                dkim_dir.mkdir(parents=True, exist_ok=True)
                dkim_path = dkim_dir / f"{profile.dkim.selector}.private"
                dkim_path.write_text(profile.dkim.private_key_pem, encoding="utf-8")
                dkim_path.chmod(0o600)

            # Push DNS records
            if not profile.dns_provider_manual:
                try:
                    secrets = {"dns_api_token": profile.dns_api_token}
                    transport = dns.provider_from_config(
                        profile, secrets, dry_run=False,
                    )
                    dns_set = SESSION.get("dns_set")
                    if dns_set:
                        actions = dns.sync_records(
                            dns_set, transport, profile.domain,
                        )
                        SESSION["dns_actions"] = actions
                except Exception as exc:
                    SESSION["dns_actions"] = [f"DNS push failed: {exc}"]

            SESSION["executed"] = True

            # Redirect to /plan (shows what was done)
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", "/plan")
            self.end_headers()
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    # ── Screen: Welcome ──────────────────────────────────────────────

    def _screen_welcome(self, errors: list[str] | None = None,
                        fields: dict[str, str] | None = None) -> str:
        f = fields or {}
        err_html = _error_box(errors or [])

        return f"""
<div class="card">
  <h1>Your mail home base, without containers.</h1>
  <p>KTC Mail orchestrates Postfix, Dovecot, Rspamd, and ACME
  certificates on a bare Debian or Ubuntu server. I'll detect
  everything I can — you just need three things.</p>

  {err_html}

  <form method="post" action="/detect">
    {_field("domain", "What domain do you want email for?",
            value=f.get("domain",""),
            placeholder="example.com")}

    {_field("dns_api_token", "DNS provider API token",
            value=f.get("dns_api_token",""),
            placeholder=f"From {' '.join(sorted(ALL_PROVIDERS - {PROVIDER_MANUAL}))}",
            type="password")}

    {_field("admin_email", "Administrator email (for cert & DMARC reports)",
            value=f.get("admin_email",""),
            placeholder="admin@example.com")}

    <div class="warning-box">
      <strong>🔑 SSH keys</strong>
      <p style="margin-bottom:0">Password SSH login is disabled by default.
      Make sure you have SSH key access before proceeding, or check
      the Advanced settings below to enable passwords (at your own risk).</p>
    </div>

    <button type="submit">Check everything →</button>

    <span class="advanced-toggle" onclick="toggleAdvanced()">Advanced settings ▾</span>

    <div class="advanced-settings" id="advanced">
      <h2>Advanced settings</h2>

      <h2>Certificate</h2>
      {_select("certificate_mode", "Certificate mode", [
          ("dns-01", "DNS-01 (wildcard cert, port 80 stays closed)"),
          ("http-01", "HTTP-01 (individual certs, opens port 80)"),
          ("upload", "Upload existing enterprise certificate"),
      ], selected=f.get("certificate_mode","dns-01"))}

      <h2>DNS provider</h2>
      {_select("dns_provider", "DNS provider (override auto-detect)", [
          ("", "Auto-detect"),
          *((pid, _provider_display_name(pid)) for pid in sorted(ALL_PROVIDERS)),
      ], selected=f.get("dns_provider",""))}

      <h2>Port 25</h2>
      {_select("smtp_relay_mode", "SMTP relay", [
          ("direct", "Auto-detect (recommended)"),
          ("vps_relay", "VPS relay (if port 25 is blocked)"),
          ("smarthost", "Third-party smarthost"),
      ], selected=f.get("smtp_relay_mode","direct"))}

      <h2>SSH</h2>
      {_checkbox("ssh_key_only", "SSH key authentication only (recommended)",
                 checked=f.get("ssh_key_only","on") != "off")}
      {_checkbox("ssh_password_auth", "Enable SSH password authentication (RISKY)",
                 checked=bool(f.get("ssh_password_auth")))}
      <div class="warning-box" id="ssh-warning" style="display:none">
        Password SSH authentication is vulnerable to brute-force attacks.
        Only enable this on trusted networks, and ensure Fail2ban is active.
      </div>
    </div>
  </form>
</div>

<script>
function toggleAdvanced() {{
  var el = document.getElementById('advanced');
  el.classList.toggle('visible');
}}
document.addEventListener('DOMContentLoaded', function() {{
  var el = document.getElementById('ssh_password_auth');
  if (el) {{
    el.addEventListener('change', function() {{
      document.getElementById('ssh-warning').style.display =
        this.checked ? 'block' : 'none';
    }});
  }}
}});
</script>
"""

    # ── Screen: Detection Results ────────────────────────────────────

    def _screen_detect(self) -> str:
        profile: SetupProfile | None = SESSION.get("profile")
        if profile is None:
            return self._redirect_home()

        # Build detection display
        items = ""

        def _add_item(label: str, value: str, badge: str = "",
                      badge_class: str = "badge-ok") -> None:
            nonlocal items
            badge_html = ""
            if badge:
                badge_html = f'<span class="detection-badge {badge_class}">{html.escape(badge)}</span>'
            items += (
                f'<div class="detection-item">'
                f'  <span class="detection-label">{html.escape(label)}</span>'
                f'  <span class="detection-value">{html.escape(value)} {badge_html}</span>'
                f'</div>'
            )

        _add_item("Domain", profile.domain)
        _add_item("Admin email", profile.admin_email)
        _add_item("Public IPv4", profile.public_ipv4 or "Not detected",
                  "⚠" if not profile.public_ipv4 else "✓",
                  "badge-warn" if not profile.public_ipv4 else "badge-ok")
        _add_item("Public IPv6", profile.public_ipv6 or "Not detected",
                  "✓" if profile.public_ipv6 else "—",
                  "badge-ok" if profile.public_ipv6 else "badge-warn")

        if profile.registrar:
            _add_item("Registrar", _provider_display_name(profile.registrar), "detected", "badge-ok")
        else:
            _add_item("Registrar", "Could not detect — using Cloudflare API" if profile.dns_provider == PROVIDER_CLOUDFLARE else profile.dns_provider, "manual", "badge-warn")

        port_badge = "BLOCKED ⚠" if profile.port_25_blocked else "OPEN ✓"
        port_class = "badge-err" if profile.port_25_blocked else "badge-ok"
        _add_item("Port 25 (outbound SMTP)", "Checking...",
                  port_badge, port_class)

        _add_item("Mail server hostname", profile.hostname, "derived", "badge-ok")

        # Hostname grid
        hostnames = "".join(
            f'<span>{html.escape(h)}</span>'
            for h in profile.all_hostnames
        )
        hostname_block = (
            f'<p>All 7 service hostnames — one wildcard certificate:</p>'
            f'<div class="hostname-grid">{hostnames}</div>'
        )

        # Certificate info
        cert_mode_desc = {
            "dns-01": "Wildcard *.domain via DNS-01 (port 80 stays closed)",
            "http-01": "Individual certs via HTTP-01 (port 80 opens)",
            "upload": "Upload your own certificate",
        }
        cert_str = cert_mode_desc.get(profile.certificate_mode, profile.certificate_mode)

        # DNS plan preview
        dns_set = SESSION.get("dns_set")
        dns_plan = self._render_dns_plan(dns_set, profile) if dns_set else ""

        # PTR report
        ptr_advice = dns.ptr_report(profile)

        # SSH warning if password enabled
        ssh_warning = ""
        if profile.security.ssh_password_auth:
            ssh_warning = (
                '<div class="warning-box">'
                '⚠ SSH password authentication is enabled. '
                'This is a security risk. Ensure strong passwords and Fail2ban.'
                '</div>'
            )

        return f"""
{_card("Detection results", f"""
<div class="detection-item" style="border-bottom:2px solid var(--brand); font-weight:700">
  <span>Here's what I found about <strong>{html.escape(profile.domain)}</strong>:</span>
</div>
{items}
""")}

{_card("Service hostnames", hostname_block)}

{_card("Certificate", f"<p>{html.escape(cert_str)}</p>")}

{ssh_warning}

{_card("DNS plan preview", dns_plan)}

{_card("Reverse DNS (PTR)", f'<pre style="font-family:monospace;white-space:pre-wrap">{html.escape(ptr_advice)}</pre>')}

{_card("Ready to build?", f"""
<p>Review the plan above. If everything looks right, click "Build my
mail server" to push DNS records, generate DKIM keys, and write
configuration.</p>
<form method="post" action="/execute">
  <button class="success" type="submit">✓ Build my mail server</button>
  <button class="secondary" type="button" onclick="window.location='/'"
          style="margin-top:0.5rem">← Back and change</button>
</form>
""")}
"""

    # ── Screen: DNS plan + execution result ──────────────────────────

    def _screen_plan(self) -> str:
        profile: SetupProfile | None = SESSION.get("profile")
        dns_set = SESSION.get("dns_set")
        executed = SESSION.get("executed", False)
        dns_actions = SESSION.get("dns_actions", [])

        if profile is None:
            return self._redirect_home()

        # Show what was executed
        status_icon = "✅" if executed else "⏳"
        status_text = "Setup profile saved and DNS records pushed" if executed else "Not yet executed"

        dns_plan = self._render_dns_plan(dns_set, profile) if dns_set else ""
        ptr_advice = dns.ptr_report(profile)

        actions_html = ""
        if dns_actions:
            actions_html = '<ul>' + ''.join(
                f'<li>{html.escape(a)}</li>' for a in dns_actions
            ) + '</ul>'

        next_steps = ""
        if executed:
            if profile.port_25_blocked and profile.smtp_relay.mode == "direct":
                next_steps = (
                    '<div class="warning-box">'
                    '<strong>⚠ Port 25 is blocked</strong>'
                    '<p>Your ISP blocks outbound port 25. You need a VPS relay '
                    'before mail can flow. Run the bootstrap script to install '
                    'the mail stack, then configure the relay.</p>'
                    '</div>'
                )

            next_steps += f"""
<div class="card">
  <h2>Next steps</h2>
  <ol style="margin-left:1.25rem;line-height:2">
    <li><strong>Install the mail stack:</strong>
      <code>/usr/lib/ktc-mail/bootstrap-mail-stack.sh</code></li>
    <li><strong>Verify DNS propagation:</strong>
      Wait 5-10 minutes, then check with <code>dig +short MX {html.escape(profile.domain)}</code></li>
    <li><strong>Set reverse DNS (PTR):</strong>
      {html.escape(ptr_advice.split(chr(10))[-1] if chr(10) in ptr_advice else ptr_advice)}</li>
    <li><strong>Check your email:</strong>
      Send a test to <code>check-auth@verifier.port25.com</code></li>
  </ol>
</div>
"""

        return f"""
<div class="card" style="border-left: 4px solid var(--ok)">
  <h1>{status_icon} {status_text}</h1>
  <p>Setup profile saved to <code>{html.escape(str(SETUP_PATH))}</code></p>
</div>

{_card("DNS records", dns_plan)}

{_card("Execution log", actions_html or "<p>No actions recorded.</p>")}

{next_steps}

{_card("What was configured", f"""
<ul style="margin-left:1.25rem;line-height:1.8">
  <li>Domain: <strong>{html.escape(profile.domain)}</strong></li>
  <li>Mail hostname: <strong>{html.escape(profile.hostname)}</strong></li>
  <li>Admin hostname: <strong>{html.escape(profile.admin_host)}</strong></li>
  <li>Webmail hostname: <strong>{html.escape(profile.webmail_host)}</strong></li>
  <li>Certificate: <strong>{html.escape(profile.certificate_mode)}</strong></li>
  <li>Open ports: {', '.join(str(p) for p in profile.security.actual_open_ports)}</li>
  <li>SSH key-only: <strong>{'Yes' if profile.security.ssh_key_only else 'No (passwords enabled)'}</strong></li>
</ul>
""")}

{_card("Documentation", """
<ul style="margin-left:1.25rem;line-height:1.8">
  <li><a href="/usr/share/doc/ktc-mail/revised-architecture.md">Revised architecture</a></li>
  <li><a href="/usr/share/doc/ktc-mail/architecture.md">Original architecture</a></li>
  <li><a href="/usr/share/doc/ktc-mail/implementation-plan.md">Implementation plan</a></li>
  <li><a href="/usr/share/doc/ktc-mail/security.md">Security</a></li>
</ul>
""")}
"""

    def _render_dns_plan(self, dns_set, profile: SetupProfile) -> str:
        lines = ""
        for r in sorted(dns_set, key=lambda x: (x.type, x.name)):
            name_short = r.name.removesuffix(f".{profile.domain}.")
            if not name_short:
                name_short = profile.domain
            cls_type = "record-type"
            cls_name = "record-name"
            cls_value = "record-value"
            purpose = f'<span class="record-purpose"># {html.escape(r.purpose)}</span>' if r.purpose else ""
            lines += (
                f'<div class="record-line">'
                f'<span class="{cls_type}">{r.type:5}</span> '
                f'<span class="{cls_name}">{html.escape(name_short):30}</span> '
                f'<span class="{cls_value}">{html.escape(r.value)}</span> '
                f'{purpose}'
                f'</div>'
            )

        return f'<div class="records">{lines}</div>'

    def _screen_done(self) -> str:
        return self._screen_plan()

    def _redirect_home(self) -> str:
        return '<div class="card"><p>Session expired. <a href="/">Start over.</a></p></div>'

    # ── Validation ───────────────────────────────────────────────────

    def _validate_welcome(self, fields: dict[str, str]) -> list[str]:
        errors: list[str] = []

        domain = fields.get("domain", "").strip().lower()
        if not validate_domain(domain):
            errors.append("Enter a valid domain, e.g. example.com")

        admin_email = fields.get("admin_email", "").strip()
        if "@" not in admin_email or "." not in admin_email.split("@")[-1]:
            errors.append("Enter a valid administrator email address")

        token = fields.get("dns_api_token", "").strip()
        provider = fields.get("dns_provider", "")
        if provider != PROVIDER_MANUAL and not token:
            errors.append("DNS API token is required (or select 'Manual DNS' in Advanced settings)")

        # SSH password warning
        if fields.get("ssh_password_auth"):
            if not fields.get("ssh_password_warning"):
                errors.append("You must acknowledge the SSH password security warning")

        return errors

    # ── HTTP response helper ─────────────────────────────────────────

    def _respond(self, body: bytes, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.end_headers()
        self.wfile.write(body)


# ── Main entry point ───────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(description="KTC Mail setup GUI (caveman mode)")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Address to bind (default 127.0.0.1 for safety)")
    parser.add_argument("--port", type=int, default=8080,
                        help="Port to bind")
    parser.add_argument("--expose", action="store_true",
                        help="Bind to 0.0.0.0 (DANGEROUS without firewall)")
    args = parser.parse_args()

    host = "0.0.0.0" if args.expose else args.host
    if host == "0.0.0.0":
        print("WARNING: Listening on all interfaces. Ensure firewall is active.",
              file=sys.stderr)

    server = ThreadingHTTPServer((host, args.port), KtcMailHandler)
    print(f"KTC Mail setup: http://{host}:{args.port}")
    print("Open this URL in your browser and follow the guided setup.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()


if __name__ == "__main__":
    main()
