#!/usr/bin/env python3
"""DNS provider automation for KTC Mail.

The command is intentionally stdlib-only. Provider-specific dependencies do not
belong in first boot. Cloudflare is the first production adapter; dry-run mode is
used by tests and by admins before writing DNS.
"""

from __future__ import annotations

import argparse
import hashlib
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

CONFIG_DIR = Path(os.environ.get("KTC_MAIL_CONFIG_DIR", "/etc/ktc-mail"))
SETUP_PATH = CONFIG_DIR / "setup.json"
SECRETS_PATH = CONFIG_DIR / "secrets.json"
STATE_DIR = Path(os.environ.get("KTC_MAIL_STATE_DIR", "/var/lib/ktc-mail"))
DNS_STATE_PATH = STATE_DIR / "dns-state.json"


class DnsError(RuntimeError):
    """Raised when DNS automation cannot complete safely."""


@dataclass(frozen=True)
class DnsRecord:
    record_type: str
    name: str
    value: str
    ttl: int = 300
    proxied: bool = False
    purpose: str = ""

    @classmethod
    def from_setup(cls, item: dict[str, Any]) -> "DnsRecord":
        return cls(
            record_type=str(item["type"]).upper(),
            name=str(item["name"]).rstrip("."),
            value=str(item["value"]),
            ttl=int(item.get("ttl", 300)),
            proxied=bool(item.get("proxied", False)),
            purpose=str(item.get("purpose", "")),
        )


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_setup(config: Path = SETUP_PATH) -> dict[str, Any]:
    if not config.exists():
        raise DnsError(f"missing setup profile: {config}")
    return read_json(config)


def load_secrets(secrets: Path = SECRETS_PATH) -> dict[str, Any]:
    if not secrets.exists():
        raise DnsError(f"missing secrets file: {secrets}")
    return read_json(secrets)


def setup_records(setup: dict[str, Any]) -> list[DnsRecord]:
    return [DnsRecord.from_setup(item) for item in setup.get("dns_records", [])]


def is_pending_record(record: DnsRecord) -> bool:
    return record.value.startswith("<") and record.value.endswith(">")


class CloudflareProvider:
    api_base = "https://api.cloudflare.com/client/v4"

    def __init__(self, token: str, zone_name: str, timeout: int = 30) -> None:
        if not token:
            raise DnsError("Cloudflare API token is empty")
        self.token = token
        self.zone_name = zone_name.rstrip(".")
        self.timeout = timeout
        self._zone_id: str | None = None

    def request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = Request(
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
            with urlopen(request, timeout=self.timeout) as response:
                body = response.read().decode("utf-8")
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise DnsError(f"Cloudflare HTTP {exc.code}: {detail}") from exc
        except URLError as exc:
            raise DnsError(f"Cloudflare request failed: {exc.reason}") from exc
        parsed = json.loads(body)
        if not parsed.get("success"):
            raise DnsError(f"Cloudflare API error: {parsed.get('errors', parsed)}")
        return parsed

    def zone_id(self) -> str:
        if self._zone_id:
            return self._zone_id
        result = self.request("GET", f"/zones?{urlencode({'name': self.zone_name})}")
        zones = result.get("result", [])
        if not zones:
            raise DnsError(f"Cloudflare zone not found: {self.zone_name}")
        self._zone_id = str(zones[0]["id"])
        return self._zone_id

    def find_record(self, record: DnsRecord) -> str | None:
        result = self.request("GET", f"/zones/{self.zone_id()}/dns_records?{urlencode({'type': record.record_type, 'name': record.name})}")
        records = result.get("result", [])
        return str(records[0]["id"]) if records else None

    def upsert_record(self, record: DnsRecord) -> str:
        payload = {
            "type": record.record_type,
            "name": record.name,
            "content": record.value,
            "ttl": record.ttl,
            "proxied": record.proxied if record.record_type in {"A", "AAAA", "CNAME"} else False,
            "comment": f"KTC Mail: {record.purpose}"[:100],
        }
        existing_id = self.find_record(record)
        if existing_id:
            self.request("PUT", f"/zones/{self.zone_id()}/dns_records/{existing_id}", payload)
            return "updated"
        self.request("POST", f"/zones/{self.zone_id()}/dns_records", payload)
        return "created"

    def delete_record(self, record: DnsRecord) -> str:
        existing_id = self.find_record(record)
        if not existing_id:
            return "missing"
        self.request("DELETE", f"/zones/{self.zone_id()}/dns_records/{existing_id}")
        return "deleted"


class DryRunProvider:
    def __init__(self) -> None:
        self.actions: list[dict[str, str]] = []

    def upsert_record(self, record: DnsRecord) -> str:
        self.actions.append({"action": "upsert", "type": record.record_type, "name": record.name, "value": record.value})
        return "dry-run"

    def delete_record(self, record: DnsRecord) -> str:
        self.actions.append({"action": "delete", "type": record.record_type, "name": record.name, "value": record.value})
        return "dry-run"


def provider_from_config(setup: dict[str, Any], secrets: dict[str, Any] | None, dry_run: bool = False) -> CloudflareProvider | DryRunProvider:
    if dry_run:
        return DryRunProvider()
    provider = setup.get("dns_provider")
    if provider != "cloudflare":
        raise DnsError(f"provider not automated yet: {provider}")
    token = str((secrets or {}).get("dns_api_token", ""))
    return CloudflareProvider(token=token, zone_name=str(setup["domain"]))


def write_state(records: list[DnsRecord], actions: list[dict[str, str]] | None = None) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "records_hash": hashlib.sha256(json.dumps([record.__dict__ for record in records], sort_keys=True).encode("utf-8")).hexdigest(),
        "records": [record.__dict__ for record in records],
        "actions": actions or [],
        "updated_at": int(time.time()),
    }
    DNS_STATE_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    DNS_STATE_PATH.chmod(0o600)


def apply_records(config: Path, secrets_path: Path, dry_run: bool) -> int:
    setup = load_setup(config)
    secrets = {} if dry_run else load_secrets(secrets_path)
    records = setup_records(setup)
    provider = provider_from_config(setup, secrets, dry_run=dry_run)
    for record in records:
        if is_pending_record(record):
            print(f"skipped-pending: {record.record_type} {record.name} {record.value}")
            continue
        result = provider.upsert_record(record)
        print(f"{result}: {record.record_type} {record.name} {record.value}")
    write_state(records, getattr(provider, "actions", []))
    return 0


def acme_record() -> DnsRecord:
    domain = os.environ.get("CERTBOT_DOMAIN", "").strip().rstrip(".")
    validation = os.environ.get("CERTBOT_VALIDATION", "").strip()
    if not domain or not validation:
        raise DnsError("CERTBOT_DOMAIN and CERTBOT_VALIDATION must be set")
    return DnsRecord("TXT", f"_acme-challenge.{domain}", validation, ttl=120, purpose="ACME DNS-01 challenge")


def acme_hook(config: Path, secrets_path: Path, cleanup: bool, dry_run: bool, propagation_seconds: int) -> int:
    setup = load_setup(config)
    secrets = {} if dry_run else load_secrets(secrets_path)
    provider = provider_from_config(setup, secrets, dry_run=dry_run)
    record = acme_record()
    result = provider.delete_record(record) if cleanup else provider.upsert_record(record)
    print(f"{result}: {record.record_type} {record.name}")
    if not cleanup and not dry_run and propagation_seconds > 0:
        time.sleep(propagation_seconds)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="KTC Mail DNS provider automation")
    parser.add_argument("command", choices=("apply", "acme-auth", "acme-cleanup"))
    parser.add_argument("--config", type=Path, default=SETUP_PATH)
    parser.add_argument("--secrets", type=Path, default=SECRETS_PATH)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--propagation-seconds", type=int, default=45)
    args = parser.parse_args()

    try:
        if args.command == "apply":
            return apply_records(args.config, args.secrets, args.dry_run)
        return acme_hook(args.config, args.secrets, cleanup=args.command == "acme-cleanup", dry_run=args.dry_run, propagation_seconds=args.propagation_seconds)
    except DnsError as exc:
        print(f"dns error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
