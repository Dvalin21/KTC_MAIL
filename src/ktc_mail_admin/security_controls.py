#!/usr/bin/env python3
"""Phase 4 firewall and abuse-control renderer/enforcer for KTC Mail."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

CONFIG_DIR = Path(os.environ.get("KTC_MAIL_CONFIG_DIR", "/etc/ktc-mail"))
STATE_DIR = Path(os.environ.get("KTC_MAIL_STATE_DIR", "/var/lib/ktc-mail"))
SETUP_PATH = CONFIG_DIR / "setup.json"
OUTPUT_DIR = STATE_DIR / "security-controls"
DEFAULT_PORTS = (22, 25, 443, 587, 993, 4190)
KTC_TABLE = "ktc_mail"
KTC_CHAIN = "input"


class SecurityError(RuntimeError):
    """Raised when Phase 4 controls cannot be rendered or applied safely."""


def load_setup(path: Path) -> dict[str, Any]:
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {"open_ports": list(DEFAULT_PORTS), "domain": "example.com", "hostname": "mail.example.com"}


def open_ports(setup: dict[str, Any]) -> tuple[int, ...]:
    ports = sorted({int(port) for port in setup.get("open_ports", DEFAULT_PORTS)})
    for port in ports:
        if port < 1 or port > 65535:
            raise SecurityError(f"invalid TCP port: {port}")
    return tuple(ports)


def abuse_policy(setup: dict[str, Any]) -> dict[str, Any]:
    configured = setup.get("abuse_controls", {})
    return {
        "crowdsec_decision": configured.get("crowdsec_decision", "defer until package maturity and ops policy are approved"),
        "submission_message_rate_limit": int(configured.get("submission_message_rate_limit", 100)),
        "submission_connection_rate_limit": int(configured.get("submission_connection_rate_limit", 20)),
        "sasl_auth_failures_findtime": int(configured.get("sasl_auth_failures_findtime", 600)),
        "sasl_auth_failures_maxretry": int(configured.get("sasl_auth_failures_maxretry", 5)),
        "quarantine_group": configured.get("quarantine_group", "ktc-quarantine"),
    }


def nftables_conf(setup: dict[str, Any]) -> str:
    ports = ", ".join(str(port) for port in open_ports(setup))
    return f"""#!/usr/sbin/nft -f
# Managed by KTC Mail. nftables is the primary Phase 4 firewall backend.
flush table inet {KTC_TABLE}
table inet {KTC_TABLE} {{
  set mail_tcp_ports {{
    type inet_service
    flags interval
    elements = {{ {ports} }}
  }}

  chain {KTC_CHAIN} {{
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    ct state invalid drop
    iifname "lo" accept
    tcp dport @mail_tcp_ports accept
    icmp type echo-request limit rate 5/second accept
    ip6 nexthdr ipv6-icmp accept
    counter drop
  }}
}}
"""


def iptables_compat(setup: dict[str, Any]) -> str:
    ports = " ".join(str(port) for port in open_ports(setup))
    return f"""#!/usr/bin/env bash
set -euo pipefail
ports=({ports})
for bin in iptables ip6tables; do
  $bin -N KTC-MAIL-IN 2>/dev/null || true
  $bin -D INPUT -j KTC-MAIL-IN 2>/dev/null || true
  $bin -I INPUT 1 -j KTC-MAIL-IN
  $bin -F KTC-MAIL-IN
  $bin -A KTC-MAIL-IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  $bin -A KTC-MAIL-IN -m conntrack --ctstate INVALID -j DROP
  $bin -A KTC-MAIL-IN -i lo -j ACCEPT
  for port in "${{ports[@]}}"; do
    $bin -A KTC-MAIL-IN -p tcp -m tcp --dport "$port" -j ACCEPT
  done
  $bin -A KTC-MAIL-IN -j DROP
done
"""


def fail2ban_jail(setup: dict[str, Any]) -> str:
    policy = abuse_policy(setup)
    return f"""# Managed by KTC Mail. Baseline abuse controls.
[DEFAULT]
bantime = 1h
findtime = {policy['sasl_auth_failures_findtime']}
maxretry = {policy['sasl_auth_failures_maxretry']}
banaction = nftables-multiport

[postfix-sasl]
enabled = true
port = submission,465
filter = postfix[mode=auth]
logpath = /var/log/mail.log

[dovecot]
enabled = true
port = imap,imaps,pop3,pop3s,submission
logpath = /var/log/mail.log

[nginx-http-auth]
enabled = true
port = https
logpath = /var/log/nginx/error.log
"""


def postfix_abuse_snippet(setup: dict[str, Any]) -> str:
    policy = abuse_policy(setup)
    return f"""# Managed by KTC Mail. Append through postconf during activation review.
smtpd_client_connection_rate_limit = {policy['submission_connection_rate_limit']}
smtpd_client_message_rate_limit = {policy['submission_message_rate_limit']}
smtpd_sasl_authenticated_header = yes
smtpd_restriction_classes = quarantine_sender
quarantine_sender = reject Sender temporarily quarantined by KTC Mail abuse controls
"""


def queue_check_script(setup: dict[str, Any]) -> str:
    policy = abuse_policy(setup)
    return f"""#!/usr/bin/env bash
set -euo pipefail
limit=${{1:-500}}
queue_count=$(mailq 2>/dev/null | awk '/^[A-F0-9]/{{c++}} END{{print c+0}}')
if (( queue_count > limit )); then
  logger -p mail.warning -t ktc-mail-abuse "mail queue depth ${{queue_count}} exceeds ${{limit}}; review compromised accounts and {policy['quarantine_group']}"
  exit 1
fi
printf 'mail queue depth OK: %s\n' "${{queue_count}}"
"""


def render(setup: dict[str, Any]) -> dict[str, str]:
    return {
        "nftables/ktc-mail.nft": nftables_conf(setup),
        "iptables/ktc-mail-compat.sh": iptables_compat(setup),
        "fail2ban/jail.d/ktc-mail.local": fail2ban_jail(setup),
        "postfix/abuse-controls.cf": postfix_abuse_snippet(setup),
        "bin/ktc-mail-queue-check.sh": queue_check_script(setup),
        "abuse-policy.json": json.dumps(abuse_policy(setup), indent=2) + "\n",
    }


def write_outputs(files: dict[str, str], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for relative, content in files.items():
        target = output_dir / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        target.chmod(0o750 if relative.endswith(".sh") else 0o640)


def run(command: list[str], dry_run: bool) -> None:
    if dry_run:
        print("dry-run:", " ".join(command))
        return
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode != 0:
        raise SecurityError(f"command failed {' '.join(command)}: {result.stderr.strip()}")
    if result.stdout.strip():
        print(result.stdout.strip())


def enforce_nftables(config_path: Path, dry_run: bool) -> None:
    setup = load_setup(config_path)
    files = render(setup)
    write_outputs(files, OUTPUT_DIR)
    nft_file = OUTPUT_DIR / "nftables/ktc-mail.nft"
    run(["nft", "-c", "-f", str(nft_file)], dry_run=dry_run)
    run(["nft", "-f", str(nft_file)], dry_run=dry_run)


def check(config_path: Path) -> dict[str, Any]:
    setup = load_setup(config_path)
    ports = open_ports(setup)
    return {
        "phase": "Phase 4",
        "backend": "nftables-primary",
        "open_ports": ports,
        "port_80_open": 80 in ports,
        "abuse_controls": abuse_policy(setup),
        "rendered_files": sorted(render(setup)),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Render/check/enforce KTC Mail Phase 4 security controls")
    parser.add_argument("command", choices=("render", "check", "enforce-nft"))
    parser.add_argument("--config", type=Path, default=SETUP_PATH)
    parser.add_argument("--output-dir", type=Path, default=OUTPUT_DIR)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "check":
            print(json.dumps(check(args.config), indent=2))
            return 0
        if args.command == "render":
            write_outputs(render(load_setup(args.config)), args.output_dir)
            print(f"rendered Phase 4 controls into {args.output_dir}")
            return 0
        enforce_nftables(args.config, args.dry_run)
        return 0
    except (OSError, json.JSONDecodeError, SecurityError, ValueError) as exc:
        print(f"security controls error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
