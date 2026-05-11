#!/usr/bin/env python3
"""DNS provider transports for KTC Mail.

Each provider implements the DnsTransport protocol:
  - list_all(domain)  →  list[DnsRecord]
  - create(record)     →  None
  - update(old, new)   →  None
  - delete(record)     →  None

The DnsRecordSet in config.py is the SOURCE OF TRUTH. Providers are
just the transport layer that syncs local state to the remote API.

Registrar auto-detection lives here. PTR handling is provider-specific
(the provider adapter.supports_ptr() tells you if it can do it).

Current production adapters:
  - CloudflareProvider
  - DryRunProvider (for testing and preview)

Future adapters (stubbed, need API credentials/docs):
  - NamecheapProvider
  - GoDaddyProvider
  - PorkbunProvider
  - Route53Provider (AWS)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

# Import shared data structures from config.py
from .config import (
    CONFIG_DIR,
    STATE_DIR,
    SETUP_PATH,
    SECRETS_PATH,
    DNS_STATE_PATH,
    PROVIDER_CLOUDFLARE,
    PROVIDER_NAMEECHEAP,
    PROVIDER_GODADDY,
    PROVIDER_PORKBUN,
    PROVIDER_ROUTE53,
    PROVIDER_DIGITALOCEAN,
    PROVIDER_HETZNER,
    ALL_PROVIDERS,
    DnsRecord,
    DnsRecordSet,
    DnsTransport,
    SetupProfile,
    save_json_private,
    read_json,
    detect_registrar,
)


class DnsError(RuntimeError):
    """DNS automation cannot complete safely."""


# ── Cloudflare Provider ─────────────────────────────────────────────────────


class CloudflareProvider:
    """Cloudflare API v4 DNS transport.

    Cloudflare acts as both DNS host and (optionally) registrar. The
    API manages DNS records in a zone. Works for ANY domain using
    Cloudflare DNS, not just Cloudflare-registered domains.
    """

    api_base = "https://api.cloudflare.com/client/v4"

    def __init__(self, token: str, zone_name: str, timeout: int = 30) -> None:
        if not token:
            raise DnsError("Cloudflare API token is empty")
        self.token = token
        self.zone_name = zone_name.rstrip(".")
        self.timeout = timeout
        self._zone_id: str | None = None

    def _request(
        self, method: str, path: str,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        req = Request(
            f"{self.api_base}{path}",
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8")
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise DnsError(f"Cloudflare HTTP {exc.code}: {detail}") from exc
        except URLError as exc:
            raise DnsError(f"Cloudflare request failed: {exc.reason}") from exc
        parsed = json.loads(body)
        if not parsed.get("success"):
            raise DnsError(f"Cloudflare API error: {parsed.get('errors', parsed)}")
        return parsed

    def _get_zone_id(self) -> str:
        if self._zone_id:
            return self._zone_id
        result = self._request("GET", f"/zones?{urlencode({'name': self.zone_name})}")
        zones = result.get("result", [])
        if not zones:
            raise DnsError(f"Cloudflare zone not found: {self.zone_name}")
        self._zone_id = str(zones[0]["id"])
        return self._zone_id

    def _to_dns_record(self, raw: dict[str, Any]) -> DnsRecord:
        """Convert a Cloudflare API record to our DnsRecord."""
        name = str(raw["name"])
        rtype = str(raw["type"]).upper()
        value = str(raw["content"])

        # Cloudflare returns fully qualified names; ensure trailing dot
        if rtype in {"MX", "CNAME", "SRV", "NS", "TLSA"}:
            if value.endswith("."):
                pass  # already qualified
            elif rtype == "MX":
                # "10 mail.example.com" → split priority
                parts = value.split(None, 1)
                if len(parts) == 2:
                    value = f"{parts[0]} {parts[1]}."

        return DnsRecord(
            type=rtype,
            name=name if name.endswith(".") else name + ".",
            value=value,
            ttl=int(raw.get("ttl", 300)),
            proxied=bool(raw.get("proxied", False)),
        )

    # ── DnsTransport protocol implementation ───────────────────────

    def list_all(self, domain: str) -> list[DnsRecord]:
        """Fetch ALL DNS records for the zone."""
        records: list[DnsRecord] = []
        page = 1
        while True:
            result = self._request(
                "GET",
                f"/zones/{self._get_zone_id()}/dns_records?"
                f"{urlencode({'per_page': 100, 'page': page})}",
            )
            for raw in result.get("result", []):
                records.append(self._to_dns_record(raw))
            total_pages = result.get("result_info", {}).get("total_pages", 1)
            if page >= total_pages:
                break
            page += 1
        return records

    def create(self, record: DnsRecord) -> None:
        payload: dict[str, Any] = {
            "type": record.type,
            "name": record.name.rstrip("."),
            "content": record.value,
            "ttl": record.ttl,
        }
        if record.type in {"A", "AAAA", "CNAME"}:
            payload["proxied"] = False  # never proxy mail traffic
        self._request("POST", f"/zones/{self._get_zone_id()}/dns_records", payload)

    def update(self, old: DnsRecord, new: DnsRecord) -> None:
        """Find the existing record by type+name, replace its content."""
        # We need the remote record ID. Search for it.
        existing = self._find_record_id(new.type, new.name)
        if existing is None:
            # Doesn't exist remotely — create instead
            self.create(new)
            return
        payload: dict[str, Any] = {
            "type": new.type,
            "name": new.name.rstrip("."),
            "content": new.value,
            "ttl": new.ttl,
        }
        if new.type in {"A", "AAAA", "CNAME"}:
            payload["proxied"] = False
        self._request(
            "PUT",
            f"/zones/{self._get_zone_id()}/dns_records/{existing}",
            payload,
        )

    def delete(self, record: DnsRecord) -> None:
        existing = self._find_record_id(record.type, record.name)
        if existing is None:
            return  # already gone
        self._request(
            "DELETE",
            f"/zones/{self._get_zone_id()}/dns_records/{existing}",
        )

    def supports_ptr(self) -> bool:
        """Cloudflare does NOT manage PTR records (ISP handles those)."""
        return False

    def _find_record_id(self, rtype: str, name: str) -> str | None:
        """Get the Cloudflare record ID for a given type+name."""
        result = self._request(
            "GET",
            f"/zones/{self._get_zone_id()}/dns_records?"
            f"{urlencode({'type': rtype, 'name': name.rstrip('.')})}",
        )
        records = result.get("result", [])
        return str(records[0]["id"]) if records else None


# ── Dry-run provider (for preview / testing) ────────────────────────────────


class DryRunProvider:
    """Pretends to manage DNS, records everything in .actions.

    Used during setup preview to show what WOULD change without
    actually changing anything.
    """

    def __init__(self) -> None:
        self.actions: list[dict[str, str]] = []

    def list_all(self, domain: str) -> list[DnsRecord]:
        return []  # pretend empty — forces "create all" view

    def create(self, record: DnsRecord) -> None:
        self.actions.append({
            "action": "create", "type": record.type,
            "name": record.name, "value": record.value,
        })

    def update(self, old: DnsRecord, new: DnsRecord) -> None:
        self.actions.append({
            "action": "update", "type": new.type,
            "name": new.name, "value": new.value,
        })

    def delete(self, record: DnsRecord) -> None:
        self.actions.append({
            "action": "delete", "type": record.type,
            "name": record.name,
        })

    def supports_ptr(self) -> bool:
        return False


# ── Provider factory ────────────────────────────────────────────────────────


def provider_from_config(
    setup: dict[str, Any] | SetupProfile,
    secrets: dict[str, Any] | None = None,
    dry_run: bool = False,
) -> CloudflareProvider | DryRunProvider:
    """Build a provider instance from setup profile + secrets.

    Raises DnsError if the provider is not yet supported or if the
    token is missing.
    """
    if dry_run:
        return DryRunProvider()

    if isinstance(setup, dict):
        provider_name = str(setup.get("dns_provider", ""))
        domain = str(setup.get("domain", ""))
        token = str((secrets or {}).get("dns_api_token", ""))
    elif isinstance(setup, SetupProfile):
        provider_name = setup.dns_provider
        domain = setup.domain
        token = setup.dns_api_token
    else:
        raise DnsError(f"invalid setup type: {type(setup)}")

    if not token and provider_name != PROVIDER_MANUAL:
        raise DnsError(f"DNS API token is required for {provider_name}")

    if provider_name == PROVIDER_CLOUDFLARE:
        return CloudflareProvider(token=token, zone_name=domain)

    raise DnsError(f"provider not yet supported: {provider_name}")


# ── Sync operations ────────────────────────────────────────────────────────


def sync_records(
    local: DnsRecordSet,
    transport: DnsTransport,
    domain: str,
    dry_run: bool = False,
) -> list[str]:
    """Sync local DNS records to the provider via diff+apply.

    Returns list of action descriptions for logging/display.
    """
    remote_records = transport.list_all(domain)
    remote_set = DnsRecordSet(domain)
    for rec in remote_records:
        remote_set.add(rec)

    diff = local.diff(remote_set)
    actions: list[str] = []

    for record in diff.to_delete:
        if not dry_run:
            transport.delete(record)
        actions.append(f"delete: {record.type} {record.name}")

    for record in diff.to_create:
        if not dry_run:
            transport.create(record)
        actions.append(f"create: {record.type} {record.name} {record.value}")

    for old, new in diff.to_update:
        if not dry_run:
            transport.update(old, new)
        actions.append(f"update: {new.type} {new.name} → {new.value}")

    if not actions:
        actions.append("no changes (all records up to date)")

    return actions


def verify_records(
    local: DnsRecordSet,
    transport: DnsTransport,
    domain: str,
) -> list[str]:
    """Compare local DNS state against the provider.

    Returns list of issues found (empty = clean).
    """
    remote_records = transport.list_all(domain)
    remote_set = DnsRecordSet(domain)
    for rec in remote_records:
        remote_set.add(rec)
    return local.verify(remote_set)


# ── ACME hook helpers ──────────────────────────────────────────────────────


def acme_challenge_record() -> DnsRecord:
    """Build the ACME DNS-01 challenge TXT record from env vars.

    Called by certbot's manual-auth-hook and manual-cleanup-hook.
    """
    domain = os.environ.get("CERTBOT_DOMAIN", "").strip().rstrip(".")
    validation = os.environ.get("CERTBOT_VALIDATION", "").strip()
    if not domain or not validation:
        raise DnsError("CERTBOT_DOMAIN and CERTBOT_VALIDATION must be set")
    return DnsRecord(
        "TXT",
        f"_acme-challenge.{domain}.",
        validation,
        ttl=120,
        purpose="ACME DNS-01 challenge",
    )


def acme_hook(
    config_path: Path,
    secrets_path: Path,
    cleanup: bool,
    dry_run: bool,
    propagation_seconds: int,
) -> int:
    """certbot manual-auth-hook / manual-cleanup-hook entry point."""
    setup = read_json(config_path)
    secrets = {} if dry_run else read_json(secrets_path)
    transport = provider_from_config(setup, secrets, dry_run=dry_run)
    record = acme_challenge_record()
    domain = os.environ.get("CERTBOT_DOMAIN", "").strip()

    if cleanup:
        transport.delete(record)
        print(f"cleaned: TXT _acme-challenge.{domain}")
    else:
        transport.create(record)
        print(f"created: TXT _acme-challenge.{domain}")
        if not dry_run and propagation_seconds > 0:
            print(f"waiting {propagation_seconds}s for DNS propagation...")
            time.sleep(propagation_seconds)
    return 0


# ── PTR report ─────────────────────────────────────────────────────────────


def ptr_report(profile: SetupProfile) -> str:
    """Generate the PTR/reverse DNS section for the setup summary.

    PTR is special: it lives at the ISP level, not in the DNS zone.
    The system can only detect and advise, not automate (unless the
    provider API supports it, which almost none do).
    """
    if not profile.public_ipv4:
        return "PTR: no public IPv4 detected — cannot advise"

    ip = profile.public_ipv4
    # Reverse the octets for in-addr.arpa
    octets = ip.split(".")
    ptr_name = ".".join(reversed(octets)) + ".in-addr.arpa."
    target = profile.hostname

    # Check if the provider supports PTR management
    try:
        secrets = read_json(SECRETS_PATH)
        transport = provider_from_config(
            profile.to_dict(), secrets, dry_run=False,
        )
        if transport.supports_ptr():
            return (
                f"PTR: {ptr_name} → {target}\n"
                f"     Your DNS provider supports PTR management. "
                f"Will attempt to set automatically."
            )
    except Exception:
        pass

    return (
        f"PTR: {ptr_name} → {target}\n"
        f"     ⚠  PTR must be set manually with your ISP or hosting\n"
        f"     provider. Most residential ISPs require a business\n"
        f"     account upgrade to set reverse DNS.\n"
        f"     If using a VPS: check your provider's control panel\n"
        f"     or API for 'Reverse DNS' / 'PTR' settings."
    )


# ── CLI entry point ────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(
        description="KTC Mail DNS provider automation",
    )
    parser.add_argument(
        "command",
        choices=("apply", "verify", "acme-auth", "acme-cleanup", "plan"),
        help="Operation to perform",
    )
    parser.add_argument("--config", type=Path, default=SETUP_PATH)
    parser.add_argument("--secrets", type=Path, default=SECRETS_PATH)
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview changes without writing")
    parser.add_argument(
        "--propagation-seconds", type=int, default=45,
        help="DNS propagation wait time (ACME auth only)",
    )
    args = parser.parse_args()

    try:
        if args.command == "acme-auth":
            return acme_hook(
                args.config, args.secrets, cleanup=False,
                dry_run=args.dry_run,
                propagation_seconds=args.propagation_seconds,
            )
        if args.command == "acme-cleanup":
            return acme_hook(
                args.config, args.secrets, cleanup=True,
                dry_run=args.dry_run,
                propagation_seconds=args.propagation_seconds,
            )

        # All other commands need a full setup profile
        setup = read_json(args.config)
        profile = SetupProfile.from_dict(setup)
        secrets = {} if args.dry_run else read_json(args.secrets)
        transport = provider_from_config(setup, secrets, dry_run=args.dry_run)

        if args.command == "plan":
            # Generate and display the DNS plan
            local = profile.generate_dns_records()
            print(profile.generate_dns_plan())
            print()
            print(ptr_report(profile))
            return 0

        if args.command == "apply":
            local = profile.generate_dns_records()
            actions = sync_records(local, transport, profile.domain, args.dry_run)
            for action in actions:
                print(action)
            # Write state after successful apply
            if not args.dry_run:
                state = {
                    "domain": profile.domain,
                    "records": [r.to_dict() for r in local],
                    "hash": local.content_hash(),
                    "updated_at": int(time.time()),
                    "actions": actions,
                }
                save_json_private(DNS_STATE_PATH, state)
            return 0

        if args.command == "verify":
            local = profile.generate_dns_records()
            issues = verify_records(local, transport, profile.domain)
            if issues:
                for issue in issues:
                    print(f"DRIFT: {issue}", file=sys.stderr)
                return 1
            print("DNS verification: all records match provider state.")
            return 0

        return 0

    except DnsError as exc:
        print(f"dns error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
