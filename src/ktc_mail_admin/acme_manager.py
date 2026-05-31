#!/usr/bin/env python3
"""ACME issue/renew/deploy orchestration for KTC Mail.

One wildcard certificate per domain, with explicit SANs for all 7
service hostnames. On renewal, TLSA records are regenerated and the
DNS provider is updated before services are reloaded.

Certbot is the ACME client. DNS-01 uses provider API hooks. HTTP-01
uses a webroot. The deploy hook is chained directly in the certbot
renew command.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from .config import (
    CONFIG_DIR,
    STATE_DIR,
    SETUP_PATH,
    TLS_STATE_PATH,
    ACME_WEBROOT,
    CERT_NAME,
    KTC_MAIL_BIN,
    DnsRecord,
    DnsRecordSet,
    SetupProfile,
    save_json_private,
    read_json,
)


class AcmeError(RuntimeError):
    """Certificate automation cannot complete safely."""


# ── Binary paths (env-overridable for testing) ──────────────────────────────

CERTBOT_BIN = os.environ.get("KTC_CERTBOT_BIN", "certbot")
SYSTEMCTL_BIN = os.environ.get("KTC_SYSTEMCTL_BIN", "systemctl")
OPENSSL_BIN = os.environ.get("KTC_OPENSSL_BIN", "openssl")


# ── Profile loading ────────────────────────────────────────────────────────


def load_profile(config: Path = SETUP_PATH) -> SetupProfile:
    """Load the setup profile and return a SetupProfile object."""
    if not config.exists():
        raise AcmeError(f"missing setup profile: {config}")
    data = read_json(config)
    return SetupProfile.from_dict(data)


# ── Certbot command construction ───────────────────────────────────────────


def certbot_issue_command(profile: SetupProfile) -> list[str]:
    """Build the certbot command for initial certificate issuance.

    Produces a wildcard cert with explicit SANs for all 7 hostnames.
    """
    cmd = [
        CERTBOT_BIN, "certonly",
        "--non-interactive",
        "--agree-tos",
        "--email", profile.admin_email,
        "--cert-name", CERT_NAME,
    ]

    # Key type: ECDSA P-256 (modern, smaller, equally secure)
    cmd.extend(["--key-type", "ecdsa", "--elliptic-curve", "secp256r1"])

    if profile.certificate_mode == "http-01":
        cmd.extend(["--webroot", "-w", str(ACME_WEBROOT)])
        # No wildcard for HTTP-01 (HTTP-01 can't validate wildcards)
        for name in profile.all_hostnames:
            cmd.extend(["-d", name])
    elif profile.certificate_mode == "dns-01":
        quoted_config = shlex.quote(str(SETUP_PATH))
        cmd.extend([
            "--manual",
            "--preferred-challenges", "dns",
            "--manual-auth-hook",
            f"{KTC_MAIL_BIN} acme auth --config {quoted_config}",
            "--manual-cleanup-hook",
            f"{KTC_MAIL_BIN} acme cleanup --config {quoted_config}",
            "--manual-public-ip-logging-ok",
        ])
        # Wildcard + all explicit SANs
        for name in profile.cert_san_names:
            cmd.extend(["-d", name])
    else:
        raise AcmeError(
            f"certificate mode not automated: {profile.certificate_mode}",
        )

    return cmd


def certbot_renew_command() -> list[str]:
    """Build the certbot renew command with deploy hook."""
    return [
        CERTBOT_BIN, "renew",
        "--deploy-hook", f"{KTC_MAIL_BIN} acme deploy-hook --config {SETUP_PATH}",
    ]


# ── Certificate path ────────────────────────────────────────────────────────


def certificate_path() -> Path:
    """Return the path to the current fullchain certificate.

    Respects the RENEWED_LINEAGE env var set by certbot renew.
    """
    env_path = os.environ.get("RENEWED_LINEAGE")
    if env_path:
        return Path(env_path) / "fullchain.pem"
    return Path("/etc/letsencrypt/live") / CERT_NAME / "fullchain.pem"


# ── TLSA value computation ──────────────────────────────────────────────────


def compute_tlsa_value(cert_path: Path) -> str:
    """Compute TLSA 3 1 1 value from a certificate file.

    Usage 3 = domain-issued certificate (DANE-TA, not CA constraint)
    Selector 1 = subject public key
    Matching type 1 = SHA-256 digest

    Returns the TLSA string: "3 1 1 <hexdigest>"
    """
    if not cert_path.exists():
        raise AcmeError(f"certificate not found: {cert_path}")

    # Extract public key from certificate
    pubkey = subprocess.run(
        [OPENSSL_BIN, "x509", "-in", str(cert_path), "-pubkey", "-noout"],
        capture_output=True, check=False,
    )
    if pubkey.returncode != 0:
        raise AcmeError(f"openssl pubkey extraction failed: {pubkey.stderr.decode()}")

    # Convert to DER and compute SHA-256
    der = subprocess.run(
        [OPENSSL_BIN, "pkey", "-pubin", "-outform", "DER"],
        input=pubkey.stdout,
        capture_output=True, check=False,
    )
    if der.returncode != 0:
        raise AcmeError(f"openssl DER conversion failed: {der.stderr.decode()}")

    digest = hashlib.sha256(der.stdout).hexdigest()
    return f"3 1 1 {digest}"


# ── TLSA DNS record generation ──────────────────────────────────────────────


def generate_tlsa_records(profile: SetupProfile, cert_path: Path) -> list[DnsRecord]:
    """Generate TLSA records for all SMTP/IMAP service endpoints.

    Returns a list of DnsRecord objects ready to be pushed to DNS.
    """
    tlsa_value = compute_tlsa_value(cert_path)
    records: list[DnsRecord] = []

    # SMTP on port 25 — primary mail server hostname
    records.append(DnsRecord(
        "TLSA",
        f"_25._tcp.{profile.hostname}.",
        tlsa_value,
        ttl=300,
        purpose="DANE SMTP TLS pin",
    ))

    # SMTP on port 25 — explicit smtp hostname (when different)
    if profile.smtp_host != profile.hostname:
        records.append(DnsRecord(
            "TLSA",
            f"_25._tcp.{profile.smtp_host}.",
            tlsa_value,
            ttl=300,
            purpose="DANE SMTP TLS pin (smtp endpoint)",
        ))

    # Submissions on port 465 — SMTP over implicit TLS (legacy)
    records.append(DnsRecord(
        "TLSA",
        f"_465._tcp.{profile.hostname}.",
        tlsa_value,
        ttl=300,
        purpose="DANE SMTPS TLS pin",
    ))

    # IMAPS on port 993
    records.append(DnsRecord(
        "TLSA",
        f"_993._tcp.{profile.hostname}.",
        tlsa_value,
        ttl=300,
        purpose="DANE IMAPS TLS pin",
    ))

    # IMAPS on explicit imap hostname
    if profile.imap_host != profile.hostname:
        records.append(DnsRecord(
            "TLSA",
            f"_993._tcp.{profile.imap_host}.",
            tlsa_value,
            ttl=300,
            purpose="DANE IMAPS TLS pin (imap endpoint)",
        ))

    return records


# ── Deploy hook ──────────────────────────────────────────────────────────────


def deploy_hook_certonly(profile: SetupProfile, dry_run: bool = False) -> int:
    """Post-issuance/post-renewal deployment: update DNS + reload services.

    This is called by certbot's --deploy-hook after every successful
    renewal. It regenerates TLSA records and pushes them to the DNS
    provider before reloading mail services.
    """
    cert_path = certificate_path()

    # Only update TLSA if configured
    if profile.update_tlsa_on_renewal:
        tlsa_records = generate_tlsa_records(profile, cert_path)
        if dry_run:
            for rec in tlsa_records:
                print(f"dry-run: TLSA {rec.name} → {rec.value}")
        else:
            # Update the setup profile's DNS records with new TLSA values
            setup_data = read_json(SETUP_PATH)
            dns_records = setup_data.get("dns_records", [])

            # Update existing TLSA records in setup profile
            for tlsa in tlsa_records:
                found = False
                for existing in dns_records:
                    if (existing.get("type") == "TLSA" and
                            existing.get("name") == tlsa.name):
                        existing["value"] = tlsa.value
                        found = True
                        break
                if not found:
                    dns_records.append({
                        "type": "TLSA",
                        "name": tlsa.name,
                        "value": tlsa.value,
                        "purpose": tlsa.purpose,
                    })

            setup_data["dns_records"] = dns_records
            save_json_private(SETUP_PATH, setup_data)

            # Push TLSA updates via DNS provider
            try:
                from . import dns_provider as dns_mod
                secrets_path = CONFIG_DIR / "secrets.json"
                secrets = read_json(secrets_path) if secrets_path.exists() else {}
                transport = dns_mod.provider_from_config(
                    setup_data, secrets, dry_run=False,
                )
                for tlsa in tlsa_records:
                    print(f"dns: updating TLSA {tlsa.name}")
                    # Try to find existing record first
                    existing = None
                    for rec in transport.list_all(profile.domain):
                        if rec.type == "TLSA" and rec.name == tlsa.name:
                            existing = rec
                            break
                    if existing:
                        transport.update(existing, tlsa)
                    else:
                        transport.create(tlsa)
            except Exception as exc:
                print(f"dns warning: TLSA update failed: {exc}", file=sys.stderr)
    else:
        print("TLSA update disabled by configuration")

    # Generate DH params (first time only) then reload services
    if not dry_run:
        ensure_dhparams()
    reload_services(profile, dry_run=dry_run)

    # Write TLS state
    if not dry_run:
        write_tls_state(profile)
        print(f"TLS state written: {TLS_STATE_PATH}")

    return 0


def ensure_dhparams(path: Path = Path("/etc/ssl/dhparam.pem")) -> None:
    """Generate DH params if the file does not exist.

    Postfix uses this for DHE ciphersuites (legacy clients that don't
    support ECDHE). Generated once; takes ~5s on modern hardware for
    2048-bit params.
    """
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    print(f"Generating DH params (2048-bit) at {path} ...", flush=True)
    result = subprocess.run(
        [OPENSSL_BIN, "dhparam", "-out", str(path), "2048"],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        print(f"warning: DH param generation failed: {result.stderr.strip()}",
              file=sys.stderr)
        return
    print(f"DH params written: {path}")
    path.chmod(0o600)


def reload_services(profile: SetupProfile, dry_run: bool = False) -> None:
    """Reload (or restart if reload not supported) mail services."""
    for service in profile.reload_services:
        if dry_run:
            print(f"dry-run: {SYSTEMCTL_BIN} reload-or-restart {service}")
        else:
            result = subprocess.run(
                [SYSTEMCTL_BIN, "reload-or-restart", service],
                capture_output=True, text=True, check=False,
            )
            if result.returncode != 0:
                print(f"service warning: {service} reload: {result.stderr.strip()}",
                      file=sys.stderr)
            else:
                print(f"service: {service} reloaded")


def write_tls_state(profile: SetupProfile) -> None:
    """Persist TLS state for health checks and monitoring."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "cert_name": CERT_NAME,
        "domains": profile.cert_san_names,
        "primary_domain": profile.domain,
        "certificate_path": str(certificate_path()),
        "updated_at": __import__("time").time(),
    }
    save_json_private(TLS_STATE_PATH, payload)


# ── Pre-flight checks ─────────────────────────────────────────────────────


def check_dns_propagation(domain: str, timeout: int = 120, interval: int = 10) -> bool:
    """Wait for ACME challenge domain to resolve via public DNS.

    For DNS-01, the challenge is at ``_acme-challenge.<domain>``.
    Polls Cloudflare's DoH API until the TXT record appears or *timeout*
    seconds elapse.
    """
    import urllib.request as _request
    import urllib.error as _error

    challenge = f"_acme-challenge.{domain}"
    url = f"https://cloudflare-dns.com/dns-query?name={challenge}&type=TXT"
    deadline = time.time() + timeout

    print(f"dns: polling {challenge} TXT ...", flush=True)
    while time.time() < deadline:
        try:
            req = _request.Request(url, headers={"Accept": "application/dns-json"})
            resp = _request.urlopen(req, timeout=5)
            data = json.loads(resp.read().decode())
            answers = data.get("Answer", [])
            if any(a.get("type") == 16 for a in answers):  # type 16 = TXT
                print(f"dns: {challenge} resolved — ACME can proceed")
                return True
        except (_error.URLError, _error.HTTPError, OSError, json.JSONDecodeError):
            pass
        print(f"dns: {challenge} not yet visible, waiting {interval}s ...", flush=True)
        time.sleep(interval)

    print(f"dns: {challenge} did not resolve within {timeout}s — proceeding anyway")
    return False


# ── Issue command ──────────────────────────────────────────────────────────


def issue(config: Path, dry_run: bool) -> int:
    """Issue initial certificate."""
    profile = load_profile(config)

    if profile.certificate_mode == "dns-01" and not dry_run:
        check_dns_propagation(profile.domain)

    if profile.certificate_mode == "http-01" and not dry_run:
        ACME_WEBROOT.mkdir(parents=True, exist_ok=True)

    cmd = certbot_issue_command(profile)
    printable = " ".join(cmd)

    if dry_run:
        print(f"dry-run: {printable}")
        return 0

    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise AcmeError(
            f"certbot failed (exit {result.returncode}):\n"
            f"{result.stderr.strip()}"
        )
    if result.stdout.strip():
        print(result.stdout.strip())

    # Run deploy hook after successful issuance
    deploy_hook_certonly(profile, dry_run=False)
    return 0


# ── Renew command ──────────────────────────────────────────────────────────


def renew(dry_run: bool) -> int:
    """Renew all certificates via certbot renew."""
    cmd = certbot_renew_command()
    printable = " ".join(cmd)

    if dry_run:
        print(f"dry-run: {printable}")
        return 0

    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise AcmeError(
            f"certbot renew failed (exit {result.returncode}):\n"
            f"{result.stderr.strip()}"
        )
    if result.stdout.strip():
        print(result.stdout.strip())
    return 0


# ── Deploy hook CLI entry (called by certbot after renewal) ────────────────


def deploy_hook(config: Path, dry_run: bool) -> int:
    """Called by certbot after successful renewal."""
    profile = load_profile(config)
    return deploy_hook_certonly(profile, dry_run=dry_run)


# ── Tool check ─────────────────────────────────────────────────────────────


def check_tools(mode: str) -> None:
    """Verify required binaries are available."""
    if shutil.which(CERTBOT_BIN) is None and mode in ("issue", "renew"):
        raise AcmeError(f"missing required binary: {CERTBOT_BIN}")
    if shutil.which(OPENSSL_BIN) is None and mode in ("deploy-hook", "issue"):
        raise AcmeError(f"missing required binary: {OPENSSL_BIN}")


# ── CLI entry point ────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(
        description="KTC Mail ACME certificate automation",
    )
    parser.add_argument(
        "command",
        choices=("issue", "renew", "deploy-hook"),
        help="Operation to perform",
    )
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
        if args.command == "deploy-hook":
            return deploy_hook(args.config, args.dry_run)

        return 1
    except AcmeError as exc:
        print(f"acme error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
