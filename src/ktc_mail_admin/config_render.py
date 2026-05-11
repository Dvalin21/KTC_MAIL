#!/usr/bin/env python3
"""Render Phase 3 mail stack configuration from the KTC setup profile."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
from pathlib import Path
from string import Template
from typing import Any

CONFIG_DIR = Path(os.environ.get("KTC_MAIL_CONFIG_DIR", "/etc/ktc-mail"))
STATE_DIR = Path(os.environ.get("KTC_MAIL_STATE_DIR", "/var/lib/ktc-mail"))
SETUP_PATH = CONFIG_DIR / "setup.json"
DEFAULT_OUTPUT_DIR = STATE_DIR / "rendered-config"
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")


class RenderError(RuntimeError):
    """Raised when config rendering would be unsafe or invalid."""


def load_setup(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise RenderError(f"missing setup profile: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def require_domain(setup: dict[str, Any], key: str) -> str:
    value = str(setup.get(key, "")).strip().rstrip(".")
    if not DOMAIN_RE.match(value):
        raise RenderError(f"invalid {key}: {value}")
    return value


def require_value(setup: dict[str, Any], key: str) -> str:
    value = str(setup.get(key, "")).strip()
    if not value:
        raise RenderError(f"missing required value: {key}")
    return value


def cert_dir() -> str:
    return "/etc/letsencrypt/live/ktc-mail"


def context(setup: dict[str, Any]) -> dict[str, str]:
    domain = require_domain(setup, "domain")
    hostname = require_domain(setup, "hostname")
    admin_host = require_domain(setup, "admin_host")
    webmail_host = require_domain(setup, "webmail_host")
    public_ipv4 = require_value(setup, "public_ipv4")
    try:
        if ipaddress.ip_address(public_ipv4).version != 4:
            raise RenderError(f"invalid public_ipv4: {public_ipv4}")
    except ValueError as exc:
        raise RenderError(f"invalid public_ipv4: {public_ipv4}") from exc
    return {
        "domain": domain,
        "hostname": hostname,
        "admin_host": admin_host,
        "webmail_host": webmail_host,
        "public_ipv4": public_ipv4,
        "admin_email": require_value(setup, "admin_email"),
        "cert_dir": cert_dir(),
        "vmail_uid": "5000",
        "vmail_gid": "5000",
        "mail_root": "/var/vmail",
        "rspamd_socket": "inet:localhost:11332",
        "dovecot_lmtp": "unix:private/dovecot-lmtp",
        "sogo_upstream": "http://127.0.0.1:20000",
        "admin_upstream": "http://127.0.0.1:8081",
    }


TEMPLATES: dict[str, str] = {
    "postfix/main.cf": """# Managed by KTC Mail. Do not edit directly.
smtpd_banner = $hostname ESMTP
myhostname = $hostname
mydomain = $domain
myorigin = $$mydomain
inet_interfaces = all
inet_protocols = all
mydestination = localhost
virtual_mailbox_domains = $domain
virtual_transport = lmtp:$dovecot_lmtp
smtpd_tls_cert_file = $cert_dir/fullchain.pem
smtpd_tls_key_file = $cert_dir/privkey.pem
smtpd_tls_security_level = may
smtpd_tls_auth_only = yes
smtp_tls_security_level = may
smtp_tls_loglevel = 1
smtpd_milters = $rspamd_socket
non_smtpd_milters = $rspamd_socket
milter_protocol = 6
milter_default_action = accept
smtpd_recipient_restrictions = permit_mynetworks, reject_unauth_destination
smtpd_relay_restrictions = permit_mynetworks, reject_unauth_destination
postscreen_greet_action = enforce
postscreen_dnsbl_action = enforce
postscreen_dnsbl_sites = zen.spamhaus.org*2 bl.spamcop.net*1
anvil_rate_time_unit = 60s
smtpd_client_message_rate_limit = 100
""",
    "postfix/master.cf": """# Managed by KTC Mail. Do not edit directly.
smtp      inet  n       -       y       -       1       postscreen
smtpd     pass  -       -       y       -       -       smtpd
dnsblog   unix  -       -       y       -       0       dnsblog
tlsproxy  unix  -       -       y       -       0       tlsproxy
submission inet n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
pickup    unix  n       -       y       60      1       pickup
cleanup   unix  n       -       y       -       0       cleanup
qmgr      unix  n       -       n       300     1       qmgr
lmtp      unix  -       -       y       -       -       lmtp
""",
    "dovecot/dovecot.conf": """# Managed by KTC Mail. Do not edit directly.
protocols = imap lmtp sieve
listen = *, ::
ssl = required
ssl_cert = <$cert_dir/fullchain.pem
ssl_key = <$cert_dir/privkey.pem
mail_location = maildir:$mail_root/%d/%n/Maildir
first_valid_uid = $vmail_uid
first_valid_gid = $vmail_gid
auth_mechanisms = plain login
passdb { driver = passwd-file args = scheme=ARGON2ID /etc/ktc-mail/dovecot-users }
userdb { driver = static args = uid=$vmail_uid gid=$vmail_gid home=$mail_root/%d/%n }
service lmtp { unix_listener /var/spool/postfix/private/dovecot-lmtp { mode = 0600 user = postfix group = postfix } }
service auth { unix_listener /var/spool/postfix/private/auth { mode = 0660 user = postfix group = postfix } }
protocol lmtp { postmaster_address = $admin_email }
plugin { sieve = file:$mail_root/%d/%n/sieve;active=$mail_root/%d/%n/.dovecot.sieve }
""",
    "rspamd/local.d/milter_headers.conf": """# Managed by KTC Mail. Do not edit directly.
use = ["authentication-results", "x-spamd-result", "x-rspamd-server", "x-rspamd-queue-id"];
authenticated_headers = ["authentication-results"];
""",
    "rspamd/local.d/dkim_signing.conf": """# Managed by KTC Mail. Do not edit directly.
allow_username_mismatch = true;
use_domain = "envelope";
selector = "default";
path = "/var/lib/rspamd/dkim/$domain.default.key";
""",
    "rspamd/local.d/redis.conf": """# Managed by KTC Mail. Do not edit directly.
servers = "127.0.0.1:6379";
""",
    "rspamd/local.d/actions.conf": """# Managed by KTC Mail. Do not edit directly.
reject = 15;
add_header = 6;
greylist = 4;
""",
    "nginx/sites-available/ktc-mail-admin.conf": """# Managed by KTC Mail. Do not edit directly.
server {
    listen 443 ssl http2;
    server_name $admin_host;
    ssl_certificate $cert_dir/fullchain.pem;
    ssl_certificate_key $cert_dir/privkey.pem;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    location / {
        proxy_pass $admin_upstream;
        proxy_set_header Host $$host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $$proxy_add_x_forwarded_for;
    }
}
""",
    "nginx/sites-available/ktc-mail-webmail.conf": """# Managed by KTC Mail. Do not edit directly.
server {
    listen 443 ssl http2;
    server_name $webmail_host;
    ssl_certificate $cert_dir/fullchain.pem;
    ssl_certificate_key $cert_dir/privkey.pem;
    client_max_body_size 50M;
    location / {
        proxy_pass $sogo_upstream;
        proxy_set_header Host $$host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $$proxy_add_x_forwarded_for;
    }
}
""",
    "sogo/sogo.conf": """// Managed by KTC Mail. Do not edit directly.
{
  SOGoTimeZone = "UTC";
  SOGoMailDomain = "$domain";
  SOGoDraftsFolderName = Drafts;
  SOGoSentFolderName = Sent;
  SOGoTrashFolderName = Trash;
  SOGoIMAPServer = "imaps://$hostname:993";
  SOGoSMTPServer = "smtp://$hostname:587";
  SOGoSieveServer = "sieve://$hostname:4190";
  SOGoPageTitle = "KTC Mail";
}
""",
}


def render_templates(setup: dict[str, Any]) -> dict[str, str]:
    values = context(setup)
    return {path: Template(template).substitute(values) for path, template in TEMPLATES.items()}


def write_outputs(rendered: dict[str, str], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for relative, content in rendered.items():
        target = output_dir / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        target.chmod(0o640)


def manifest(rendered: dict[str, str]) -> dict[str, Any]:
    return {"files": sorted(rendered), "phase": "Phase 3", "warning": "Review rendered files before copying into /etc."}


def main() -> int:
    parser = argparse.ArgumentParser(description="Render KTC Mail stack configuration")
    parser.add_argument("--config", type=Path, default=SETUP_PATH)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--check", action="store_true", help="validate and print manifest without writing files")
    args = parser.parse_args()

    try:
        rendered = render_templates(load_setup(args.config))
        if args.check:
            print(json.dumps(manifest(rendered), indent=2))
            return 0
        write_outputs(rendered, args.output_dir)
        (args.output_dir / "manifest.json").write_text(json.dumps(manifest(rendered), indent=2) + "\n", encoding="utf-8")
        print(f"rendered {len(rendered)} files into {args.output_dir}")
        return 0
    except (OSError, KeyError, RenderError, json.JSONDecodeError) as exc:
        print(f"render error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
