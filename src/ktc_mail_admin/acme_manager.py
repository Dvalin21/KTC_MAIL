#!/usr/bin/env python3
"""ACME issue/renew/deploy orchestration for KTC Mail."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

CONFIG_DIR = Path(os.environ.get("KTC_MAIL_CONFIG_DIR", "/etc/ktc-mail"))
STATE_DIR = Path(os.environ.get("KTC_MAIL_STATE_DIR", "/var/lib/ktc-mail"))
SETUP_PATH = CONFIG_DIR / "setup.json"
TLS_STATE_PATH = STATE_DIR / "tls-state.json"
ACME_WEBROOT = STATE_DIR / "acme-webroot"
CERT_NAME = "ktc-mail"
DNS_HOOK = "/usr/lib/ktc-mail/dns_provider.py"
ACME_HOOK = "/usr/lib/ktc-mail/acme_manager.py"
CERTBOT_BIN = os.environ.get("KTC_CERTBOT_BIN", "certbot")
SYSTEMCTL_BIN = os.environ.get("KTC_SYSTEMCTL_BIN", "systemctl")
OPENSSL_BIN = os.environ.get("KTC_OPENSSL_BIN", "openssl")


class AcmeError(RuntimeError):
    """Raised when certificate automation cannot complete safely."""


def load_setup(config: Path = SETUP_PATH) -> dict[str, Any]:
    if not config.exists():
        raise AcmeError(f"missing setup profile: {config}")
    return json.loads(config.read_text(encoding="utf-8"))


def cert_domains(setup: dict[str, Any]) -> list[str]:
    values = [setup.get("hostname"), setup.get("admin_host"), setup.get("webmail_host")]
    domains: list[str] = []
    for value in values:
        if value and value not in domains:
            domains.append(str(value))
    if not domains:
        raise AcmeError("setup profile has no certificate hostnames")
    return domains


def run(command: list[str], dry_run: bool = False) -> None:
    printable = " ".join(command)
    if dry_run:
        print(f"dry-run: {printable}")
        return
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode != 0:
        raise AcmeError(f"command failed: {printable}\n{result.stderr.strip()}")
    if result.stdout.strip():
        print(result.stdout.strip())


def certbot_issue_command(setup: dict[str, Any], config: Path = SETUP_PATH) -> list[str]:
    domains = cert_domains(setup)
    command = [CERTBOT_BIN, "certonly", "--non-interactive", "--agree-tos", "--email", str(setup["admin_email"]), "--cert-name", CERT_NAME]
    if setup.get("certificate_mode") == "http-01":
        command.extend(["--webroot", "-w", str(ACME_WEBROOT)])
    elif setup.get("certificate_mode") == "dns-01-api":
        quoted_config = shlex.quote(str(config))
        command.extend([
            "--manual",
            "--preferred-challenges",
            "dns",
            "--manual-auth-hook",
            f"{DNS_HOOK} acme-auth --config {quoted_config}",
            "--manual-cleanup-hook",
            f"{DNS_HOOK} acme-cleanup --config {quoted_config}",
            "--manual-public-ip-logging-ok",
        ])
    else:
        raise AcmeError(f"certificate mode is not automated: {setup.get('certificate_mode')}")
    for domain in domains:
        command.extend(["-d", domain])
    return command


def certbot_renew_command() -> list[str]:
    return [CERTBOT_BIN, "renew", "--deploy-hook", f"{ACME_HOOK} deploy-hook"]


def certificate_path() -> Path:
    env_path = os.environ.get("RENEWED_LINEAGE")
    if env_path:
        return Path(env_path) / "fullchain.pem"
    return Path("/etc/letsencrypt/live") / CERT_NAME / "fullchain.pem"


def tlsa_value(cert_path: Path) -> str:
    if not cert_path.exists():
        raise AcmeError(f"certificate not found for TLSA generation: {cert_path}")
    pubkey = subprocess.run([OPENSSL_BIN, "x509", "-in", str(cert_path), "-pubkey", "-noout"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if pubkey.returncode != 0:
        raise AcmeError(f"openssl failed extracting public key: {pubkey.stderr.decode('utf-8', errors='replace')}")
    der = subprocess.run([OPENSSL_BIN, "pkey", "-pubin", "-outform", "DER"], input=pubkey.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if der.returncode != 0:
        raise AcmeError(f"openssl failed encoding public key: {der.stderr.decode('utf-8', errors='replace')}")
    digest = hashlib.sha256(der.stdout).hexdigest()
    return f"3 1 1 {digest}"


def update_tlsa_in_setup(setup: dict[str, Any], config: Path, cert_path: Path, dry_run: bool) -> None:
    if not setup.get("renewal_hooks", {}).get("update_tlsa_on_certificate_renewal"):
        return
    value = tlsa_value(cert_path)
    target_name = f"_25._tcp.{setup['hostname']}"
    changed = False
    for record in setup.get("dns_records", []):
        if record.get("type") == "TLSA" and record.get("name") == target_name:
            record["value"] = value
            changed = True
    if not changed:
        setup.setdefault("dns_records", []).append({"type": "TLSA", "name": target_name, "value": value, "purpose": "DANE SMTP TLS pin"})
    if dry_run:
        print(f"dry-run: update TLSA {target_name} {value}")
        return
    config.write_text(json.dumps(setup, indent=2) + "\n", encoding="utf-8")
    config.chmod(0o600)
    run([DNS_HOOK, "apply", "--config", str(config)], dry_run=False)


def reload_services(setup: dict[str, Any], dry_run: bool) -> None:
    for service in setup.get("renewal_hooks", {}).get("reload_services", []):
        run([SYSTEMCTL_BIN, "reload-or-restart", str(service)], dry_run=dry_run)


def write_tls_state(setup: dict[str, Any], dry_run: bool) -> None:
    if dry_run:
        return
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    payload = {"cert_name": CERT_NAME, "domains": cert_domains(setup), "certificate_path": str(certificate_path())}
    TLS_STATE_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    TLS_STATE_PATH.chmod(0o600)


def issue(config: Path, dry_run: bool) -> int:
    setup = load_setup(config)
    if setup.get("certificate_mode") == "http-01" and not dry_run:
        ACME_WEBROOT.mkdir(parents=True, exist_ok=True)
    run(certbot_issue_command(setup, config), dry_run=dry_run)
    write_tls_state(setup, dry_run=dry_run)
    return 0


def renew(dry_run: bool) -> int:
    run(certbot_renew_command(), dry_run=dry_run)
    return 0


def deploy_hook(config: Path, dry_run: bool) -> int:
    setup = load_setup(config)
    update_tlsa_in_setup(setup, config, certificate_path(), dry_run=dry_run)
    reload_services(setup, dry_run=dry_run)
    write_tls_state(setup, dry_run=dry_run)
    return 0


def check_tools(mode: str) -> None:
    if shutil.which(CERTBOT_BIN) is None and mode in {"issue", "renew"}:
        raise AcmeError(f"missing required binary: {CERTBOT_BIN}")
    if shutil.which(OPENSSL_BIN) is None and mode == "deploy-hook":
        raise AcmeError(f"missing required binary: {OPENSSL_BIN}")


def main() -> int:
    parser = argparse.ArgumentParser(description="KTC Mail ACME automation")
    parser.add_argument("command", choices=("issue", "renew", "deploy-hook"))
    parser.add_argument("--config", type=Path, default=SETUP_PATH)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    try:
        if not args.dry_run:
            check_tools(args.command)
        if args.command == "issue":
            return issue(args.config, args.dry_run)
        if args.command == "renew":
            return renew(args.dry_run)
        return deploy_hook(args.config, args.dry_run)
    except AcmeError as exc:
        print(f"acme error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
