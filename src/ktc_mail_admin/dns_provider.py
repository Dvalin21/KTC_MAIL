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

Production adapters:
  - CloudflareProvider
  - Route53Provider (AWS)
  - HetznerProvider
  - PorkbunProvider
  - GoDaddyProvider
  - DigitalOceanProvider
  - DryRunProvider (for testing and preview)

Not yet implemented (stub needs XML API reverse-engineering, IP whitelist):
  - NamecheapProvider
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


# ── Route53 Provider (AWS Route53) ───────────────────────────────────────────
#
# Uses boto3 (optional dependency).  Required IAM permissions:
#   route53:ListHostedZonesByName
#   route53:ListResourceRecordSets
#   route53:ChangeResourceRecordSets
#
# Token setup (choose ONE):
#   a) IAM user with above permissions → AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY
#   b) IAM role (EC2/Lambda)          → instance profile
#   c) Environment variables           → export AWS_* in the systemd unit


class Route53Provider:
    """AWS Route53 DNS transport via boto3.

    Zone lookup is by domain name (strips trailing dot).  Record
    operations use the standard Route53 ChangeResourceRecordSets API
    with UPSERT for create/update and DELETE for delete.
    """

    def __init__(self, token: str = "", zone_name: str = "") -> None:
        boto3 = _import_boto3()
        if boto3 is None:
            raise DnsError(
                "Route53 requires boto3: pip install boto3 "
                "(or apt install python3-boto3 on Debian/Ubuntu)"
            )
        if token and token != "__env__":
            # Credentials passed inline (less secure — prefer env vars)
            import os as _os
            _os.environ.setdefault("AWS_ACCESS_KEY_ID", token.split(":")[0])
            _os.environ.setdefault("AWS_SECRET_ACCESS_KEY", token.split(":")[1] if ":" in token else "")
        self.zone_name = zone_name.rstrip(".")
        self._client = boto3.client("route53")
        self._zone_id: str | None = None

    def _get_zone_id(self) -> str:
        if self._zone_id:
            return self._zone_id
        paginator = self._client.get_paginator("list_hosted_zones_by_name")
        for page in paginator.paginate():
            for zone in page.get("HostedZones", []):
                name = zone["Name"].rstrip(".")
                if name == self.zone_name or name == self.zone_name + ".":
                    self._zone_id = zone["Id"].removeprefix("/hostedzone/")
                    return self._zone_id
        raise DnsError(f"Route53 zone not found: {self.zone_name}")

    def _to_record(self, rset: dict) -> list[DnsRecord]:
        """Convert a Route53 resource record set to one or more DnsRecords."""
        name = rset["Name"]  # already has trailing dot
        rtype = rset["Type"]
        ttl = int(rset.get("TTL", 300))
        records: list[DnsRecord] = []
        for value in rset.get("ResourceRecords", []):
            content = value["Value"]
            if rtype in ("MX", "SRV"):
                content = content.replace(" ", "\t")  # normalize sep
            records.append(DnsRecord(type=rtype, name=name, value=content, ttl=ttl))
        # Alias records (e.g. A/AAAA for ELB/CloudFront) have AliasTarget instead
        if not records and "AliasTarget" in rset:
            records.append(DnsRecord(
                type=rtype, name=name,
                value=rset["AliasTarget"]["DNSName"],
                ttl=ttl,
            ))
        return records

    # ── DnsTransport protocol ───────────────────────────────────────

    def list_all(self, domain: str) -> list[DnsRecord]:
        records: list[DnsRecord] = []
        paginator = self._client.get_paginator("list_resource_record_sets")
        for page in paginator.paginate(HostedZoneId=self._get_zone_id()):
            for rset in page.get("ResourceRecordSets", []):
                records.extend(self._to_record(rset))
        return records

    def create(self, record: DnsRecord) -> None:
        self._change("UPSERT", record)

    def update(self, old: DnsRecord, new: DnsRecord) -> None:
        # Route53 UPSERT is idempotent — same as create
        self._change("UPSERT", new)

    def delete(self, record: DnsRecord) -> None:
        self._change("DELETE", record)

    def supports_ptr(self) -> bool:
        return False  # Route53 manages forward DNS only

    def _change(self, action: str, record: DnsRecord) -> None:
        value = record.value
        if record.type in ("MX", "SRV"):
            value = value.replace("\t", " ")  # Route53 uses space sep
        self._client.change_resource_record_sets(
            HostedZoneId=self._get_zone_id(),
            ChangeBatch={
                "Changes": [{
                    "Action": action,
                    "ResourceRecordSet": {
                        "Name": record.name,
                        "Type": record.type,
                        "TTL": record.ttl,
                        "ResourceRecords": [{"Value": value}],
                    },
                }],
            },
        )


def _import_boto3():
    """Lazy boto3 import.  Returns None if not installed."""
    try:
        import boto3  # noqa: F401
        return __import__("boto3")
    except ImportError:
        return None


# ── Hetzner Provider ─────────────────────────────────────────────────────────
#
# REST API: https://dns.hetzner.com/api/v1
# Auth:     Bearer token from Hetzner DNS Console → API Tokens → Show token
# Required token permissions: read + write


class HetznerProvider:
    """Hetzner DNS API transport — stdlib only, no extra dependencies.

    Docs: https://dns.hetzner.com/api-docs
    """

    api_base = "https://dns.hetzner.com/api/v1"

    def __init__(self, token: str, zone_name: str, timeout: int = 30) -> None:
        if not token:
            raise DnsError("Hetzner API token is empty")
        self.token = token
        self.zone_name = zone_name.rstrip(".")
        self.timeout = timeout
        self._zone_id: str | None = None

    def _headers(self) -> dict[str, str]:
        return {
            "Auth-API-Token": self.token,
            "Content-Type": "application/json",
        }

    def _request(
        self, method: str, path: str,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        from urllib.request import Request, urlopen
        from urllib.error import HTTPError, URLError

        data = None if payload is None else json.dumps(payload).encode("utf-8")
        req = Request(
            f"{self.api_base}{path}",
            data=data, method=method,
            headers=self._headers(),
        )
        try:
            with urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8")
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise DnsError(f"Hetzner HTTP {exc.code}: {detail}") from exc
        except URLError as exc:
            raise DnsError(f"Hetzner request failed: {exc.reason}") from exc
        return json.loads(body) if body else {}

    def _get_zone_id(self) -> str:
        if self._zone_id:
            return self._zone_id
        result = self._request("GET", "/zones")
        for zone in result.get("zones", []):
            if zone["name"] == self.zone_name:
                self._zone_id = str(zone["id"])
                return self._zone_id
        raise DnsError(f"Hetzner zone not found: {self.zone_name}")

    def _to_record(self, raw: dict[str, Any]) -> DnsRecord:
        name = str(raw.get("name", ""))
        rtype = str(raw["type"]).upper()
        value = str(raw["value"])
        # Hetzner returns record name without zone suffix
        # e.g. "mail" for mail.example.com
        if name:
            fqdn = f"{name}.{self.zone_name}."
        else:
            fqdn = f"{self.zone_name}."
        return DnsRecord(
            type=rtype, name=fqdn, value=value,
            ttl=int(raw.get("ttl", 300)),
        )

    # ── DnsTransport protocol ───────────────────────────────────────

    def list_all(self, domain: str) -> list[DnsRecord]:
        records: list[DnsRecord] = []
        page = 1
        while True:
            result = self._request(
                "GET",
                f"/records?zone_id={self._get_zone_id()}&page={page}&per_page=100",
            )
            for raw in result.get("records", []):
                records.append(self._to_record(raw))
            meta = result.get("meta", {})
            pagination = meta.get("pagination", {})
            total = pagination.get("total_pages", 1)
            if page >= total:
                break
            page += 1
        return records

    def create(self, record: DnsRecord) -> None:
        payload = self._record_payload(record)
        self._request("POST", "/records", payload)

    def update(self, old: DnsRecord, new: DnsRecord) -> None:
        existing = self._find_record_id(new.type, new.name)
        if existing is None:
            self.create(new)
            return
        payload = self._record_payload(new)
        self._request("PUT", f"/records/{existing}", payload)

    def delete(self, record: DnsRecord) -> None:
        rid = self._find_record_id(record.type, record.name)
        if rid is None:
            return  # already gone
        self._request("DELETE", f"/records/{rid}")

    def supports_ptr(self) -> bool:
        return False

    def _record_payload(self, record: DnsRecord) -> dict[str, Any]:
        name = record.name.removesuffix(f".{self.zone_name}.")
        return {
            "zone_id": self._get_zone_id(),
            "type": record.type,
            "name": name,
            "value": record.value,
            "ttl": record.ttl,
        }

    def _find_record_id(self, rtype: str, name: str) -> str | None:
        needle = name.rstrip(".")
        result = self._request(
            "GET",
            f"/records?zone_id={self._get_zone_id()}&type={rtype}",
        )
        for rec in result.get("records", []):
            rec_name = str(rec.get("name", ""))
            if rec_name:
                fqdn = f"{rec_name}.{self.zone_name}."
            else:
                fqdn = f"{self.zone_name}."
            if fqdn.rstrip(".") == needle:
                return str(rec["id"])
        return None


# ── Porkbun Provider ─────────────────────────────────────────────────────────
#
# REST API: https://api.porkbun.com/api/json/v3
# Auth:     API Key + Secret Key (colon-separated in the token field)
#           Store as "apikey:secretapikey" in secrets.json → dns_api_token
# All API calls are POST.  Credentials go in the request body, not headers.


class PorkbunProvider:
    """Porkbun DNS API transport — stdlib only, no extra dependencies.

    Docs: https://porkbun.com/api/json/v3/documentation
    Porkbun uses two keys (API Key + Secret Key) passed as POST body.
    Store as "apikey:secretapikey" in the dns_api_token field.
    """

    api_base = "https://api.porkbun.com/api/json/v3"

    def __init__(self, token: str, zone_name: str, timeout: int = 30) -> None:
        if not token:
            raise DnsError("Porkbun API token is empty")
        parts = token.split(":", 1)
        if len(parts) != 2 or not parts[0] or not parts[1]:
            raise DnsError(
                "Porkbun requires 'apikey:secretapikey' in dns_api_token "
                "(colon-separated, both non-empty)"
            )
        self.apikey = parts[0]
        self.secretapikey = parts[1]
        self.zone_name = zone_name.rstrip(".")
        self.timeout = timeout

    def _auth_body(self) -> dict[str, str]:
        return {"apikey": self.apikey, "secretapikey": self.secretapikey}

    def _request(
        self, path: str, payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        from urllib.request import Request, urlopen
        from urllib.error import HTTPError, URLError

        body = self._auth_body()
        if payload:
            body.update(payload)
        data = json.dumps(body).encode("utf-8")
        req = Request(
            f"{self.api_base}{path}",
            data=data, method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urlopen(req, timeout=self.timeout) as resp:
                result = json.loads(resp.read().decode("utf-8"))
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise DnsError(f"Porkbun HTTP {exc.code}: {detail}") from exc
        except URLError as exc:
            raise DnsError(f"Porkbun request failed: {exc.reason}") from exc

        if result.get("status") != "SUCCESS":
            raise DnsError(
                f"Porkbun API error: {result.get('message', result)}"
            )
        return result

    def _to_record(self, raw: dict[str, Any]) -> DnsRecord:
        """Convert a Porkbun API record to our DnsRecord."""
        name = str(raw["name"])
        rtype = str(raw["type"]).upper()
        content = str(raw["content"])
        ttl = int(raw.get("ttl", 300))

        # Porkbun returns FQDNs with trailing dot for some types
        if rtype in ("CNAME", "MX", "SRV", "NS", "ALIAS"):
            if content.endswith("."):
                pass
            elif rtype == "MX":
                parts = content.split(None, 1)
                if len(parts) == 2:
                    content = f"{parts[0]} {parts[1]}."

        if not name.endswith("."):
            name = name + "."

        return DnsRecord(type=rtype, name=name, value=content, ttl=ttl)

    # ── DnsTransport protocol ───────────────────────────────────────

    def list_all(self, domain: str) -> list[DnsRecord]:
        result = self._request(f"/dns/retrieve/{domain}")
        records: list[DnsRecord] = []
        for raw in result.get("response", []):
            if raw.get("type") and raw.get("name"):
                records.append(self._to_record(raw))
        return records

    def create(self, record: DnsRecord) -> None:
        payload = self._record_payload(record)
        domain = record.name.rstrip(".")
        # Extract just the domain from the FQDN
        parts = record.name.rstrip(".").split(".")
        if len(parts) >= 2:
            domain = ".".join(parts[-2:])
        self._request(f"/dns/create/{domain}", payload)

    def update(self, old: DnsRecord, new: DnsRecord) -> None:
        rid = self._find_record_id(new.type, new.name)
        if rid is None:
            self.create(new)
            return
        domain = new.name.rstrip(".").split(".")
        domain = ".".join(domain[-2:]) if len(domain) >= 2 else new.name
        payload = self._record_payload(new)
        self._request(f"/dns/edit/{domain}/{rid}", payload)

    def delete(self, record: DnsRecord) -> None:
        rid = self._find_record_id(record.type, record.name)
        if rid is None:
            return
        domain = record.name.rstrip(".").split(".")
        domain = ".".join(domain[-2:]) if len(domain) >= 2 else record.name
        self._request(f"/dns/delete/{domain}/{rid}")

    def supports_ptr(self) -> bool:
        return False

    def _record_payload(self, record: DnsRecord) -> dict[str, Any]:
        content = record.value
        if record.type in ("MX", "SRV"):
            content = content.replace("\t", " ")
        return {
            "type": record.type,
            "name": record.name.rstrip("."),
            "content": content,
            "ttl": record.ttl,
        }

    def _find_record_id(self, rtype: str, name: str) -> str | None:
        domain = name.rstrip(".").split(".")
        domain = ".".join(domain[-2:]) if len(domain) >= 2 else name
        needle = name.rstrip(".")
        result = self._request(f"/dns/retrieve/{domain}")
        for raw in result.get("response", []):
            if raw.get("type") == rtype and str(raw.get("name", "")).rstrip(".") == needle:
                return str(raw.get("id"))
        return None


# ── GoDaddy Provider ─────────────────────────────────────────────────────────
#
# REST API: https://api.godaddy.com/api/v1
# Auth:     SSO Key + SSO Secret (colon-separated in token field)
#           Store as "key:secret" in secrets.json → dns_api_token
# NOTE: GoDaddy PATCH replaces ALL records — this adapter uses PUT
# for individual record upserts to avoid bulk-data races.


class GoDaddyProvider:
    """GoDaddy DNS API transport — stdlib only, no extra dependencies.

    Docs: https://developer.godaddy.com/doc/endpoint/domains
    Token format is "key:secret" — the SSO keypair from GoDaddy's
    API Key Management page (not your account password).
    """

    api_base = "https://api.godaddy.com/api/v1"

    def __init__(self, token: str, zone_name: str, timeout: int = 30) -> None:
        if not token:
            raise DnsError("GoDaddy API token is empty")
        parts = token.split(":", 1)
        if len(parts) != 2 or not parts[0] or not parts[1]:
            raise DnsError(
                "GoDaddy requires 'key:secret' in dns_api_token "
                "(colon-separated SSO key and secret, both non-empty)"
            )
        self._key = parts[0]
        self._secret = parts[1]
        self.zone_name = zone_name.rstrip(".")
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        import base64
        return {
            "Authorization": f"sso-key {self._key}:{self._secret}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _request(
        self, method: str, path: str,
        payload: list[dict] | dict | None = None,
    ) -> Any:
        from urllib.request import Request, urlopen
        from urllib.error import HTTPError, URLError

        data = None if payload is None else json.dumps(payload).encode("utf-8")
        req = Request(
            f"{self.api_base}{path}",
            data=data, method=method,
            headers=self._headers(),
        )
        try:
            with urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8")
                return json.loads(body) if body else {}
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise DnsError(f"GoDaddy HTTP {exc.code}: {detail}") from exc
        except URLError as exc:
            raise DnsError(f"GoDaddy request failed: {exc.reason}") from exc

    def _to_record(self, raw: dict[str, Any]) -> DnsRecord:
        name = str(raw.get("name", ""))
        rtype = str(raw["type"]).upper()
        data = str(raw.get("data", ""))
        ttl = int(raw.get("ttl", 300))

        # GoDaddy returns names without trailing dot and without domain suffix
        if name:
            fqdn = f"{name}.{self.zone_name}."
        else:
            fqdn = f"{self.zone_name}."

        if rtype in ("MX", "SRV"):
            parts_raw = data.split(None, 1)
            if len(parts_raw) == 2:
                data = f"{parts_raw[0]} {parts_raw[1]}."

        return DnsRecord(type=rtype, name=fqdn, value=data, ttl=ttl)

    # ── DnsTransport protocol ───────────────────────────────────────

    def list_all(self, domain: str) -> list[DnsRecord]:
        result = self._request("GET", f"/domains/{domain}/records")
        records: list[DnsRecord] = []
        for raw in result if isinstance(result, list) else []:
            if raw.get("type") and "name" in raw:
                records.append(self._to_record(raw))
        return records

    def create(self, record: DnsRecord) -> None:
        self._upsert(record)

    def update(self, old: DnsRecord, new: DnsRecord) -> None:
        self._upsert(new)

    def delete(self, record: DnsRecord) -> None:
        name = record.name.removesuffix(f".{self.zone_name}.") or "@"
        if name == self.zone_name:
            name = "@"
        self._request(
            "DELETE",
            f"/domains/{self.zone_name}/records/{record.type}/{name}",
        )

    def supports_ptr(self) -> bool:
        return False

    def _upsert(self, record: DnsRecord) -> None:
        name = record.name.removesuffix(f".{self.zone_name}.") or "@"
        if name == self.zone_name:
            name = "@"
        data = record.value
        if record.type in ("MX", "SRV"):
            data = data.replace("\t", " ")
        payload: list[dict[str, Any]] = [
            {"data": data, "ttl": record.ttl},
        ]
        if record.type in ("MX", "SRV") and record.priority is not None:
            payload[0]["priority"] = record.priority
        # Use PUT (upsert). Takes an array body.
        self._request(
            "PUT",
            f"/domains/{self.zone_name}/records/{record.type}/{name}",
            payload,
        )


# ── DigitalOcean Provider ────────────────────────────────────────────────────
#
# REST API: https://api.digitalocean.com/v2
# Auth:     Bearer token (personal access token with read + write scope)


class DigitalOceanProvider:
    """DigitalOcean DNS API transport — stdlib only.

    Docs: https://docs.digitalocean.com/reference/api/api-reference/#tag/Domains
    Token is a personal access token with `read` + `write` scope
    for the Domains API.
    """

    api_base = "https://api.digitalocean.com/v2"

    def __init__(self, token: str, zone_name: str, timeout: int = 30) -> None:
        if not token:
            raise DnsError("DigitalOcean API token is empty")
        self.token = token
        self.zone_name = zone_name.rstrip(".")
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }

    def _request(
        self, method: str, path: str,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        from urllib.request import Request, urlopen
        from urllib.error import HTTPError, URLError

        data = None if payload is None else json.dumps(payload).encode("utf-8")
        req = Request(
            f"{self.api_base}{path}",
            data=data, method=method,
            headers=self._headers(),
        )
        try:
            with urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8")
                return json.loads(body) if body else {}
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise DnsError(f"DigitalOcean HTTP {exc.code}: {detail}") from exc
        except URLError as exc:
            raise DnsError(f"DigitalOcean request failed: {exc.reason}") from exc

    def _to_record(self, raw: dict[str, Any]) -> DnsRecord:
        rtype = str(raw["type"]).upper()
        name = str(raw.get("name", ""))
        data = str(raw.get("data", ""))
        ttl = int(raw.get("ttl", 1800))

        # DigitalOcean returns bare names (no domain suffix, no trailing dot)
        if name:
            fqdn = f"{name}.{self.zone_name}."
        else:
            fqdn = f"{self.zone_name}."

        if rtype in ("MX", "SRV"):
            parts = data.split(None, 1)
            if len(parts) == 2:
                data = f"{parts[0]} {parts[1]}."

        return DnsRecord(
            type=rtype, name=fqdn, value=data, ttl=ttl,
        )

    def _domain_arg(self, record: DnsRecord) -> str:
        """Extract the DO record name from a FQDN."""
        name = record.name.removesuffix(f".{self.zone_name}.")
        return name if name else "@"

    # ── DnsTransport protocol ───────────────────────────────────────

    def list_all(self, domain: str) -> list[DnsRecord]:
        records: list[DnsRecord] = []
        page = 1
        while True:
            result = self._request(
                "GET",
                f"/domains/{domain}/records?page={page}&per_page=100",
            )
            for raw in result.get("domain_records", []):
                records.append(self._to_record(raw))
            meta = result.get("meta", {})
            total = meta.get("total", len(records))
            if len(records) >= total:
                break
            page += 1
        return records

    def create(self, record: DnsRecord) -> None:
        payload = self._record_payload(record)
        self._request(
            "POST",
            f"/domains/{self.zone_name}/records",
            payload,
        )

    def update(self, old: DnsRecord, new: DnsRecord) -> None:
        rid = self._find_record_id(new.type, new.name)
        if rid is None:
            self.create(new)
            return
        payload = self._record_payload(new)
        self._request(
            "PUT",
            f"/domains/{self.zone_name}/records/{rid}",
            payload,
        )

    def delete(self, record: DnsRecord) -> None:
        rid = self._find_record_id(record.type, record.name)
        if rid is None:
            return
        self._request(
            "DELETE",
            f"/domains/{self.zone_name}/records/{rid}",
        )

    def supports_ptr(self) -> bool:
        return False

    def _record_payload(self, record: DnsRecord) -> dict[str, Any]:
        data = record.value
        if record.type in ("MX", "SRV"):
            data = data.replace("\t", " ")
        return {
            "type": record.type,
            "name": self._domain_arg(record),
            "data": data,
            "ttl": record.ttl,
        }

    def _find_record_id(self, rtype: str, name: str) -> str | None:
        domain = self.zone_name
        needle = name.rstrip(".")
        page = 1
        while True:
            result = self._request(
                "GET",
                f"/domains/{domain}/records?page={page}&per_page=100",
            )
            for raw in result.get("domain_records", []):
                raw_type = str(raw.get("type", "")).upper()
                raw_name = str(raw.get("name", ""))
                fqdn = f"{raw_name}.{domain}." if raw_name else f"{domain}."
                if raw_type == rtype and fqdn.rstrip(".") == needle:
                    return str(raw["id"])
            meta = result.get("meta", {})
            total = meta.get("total", 0)
            if len(result.get("domain_records", [])) == 0:
                break
            page += 1
        return None


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
) -> CloudflareProvider | Route53Provider | HetznerProvider | PorkbunProvider | GoDaddyProvider | DigitalOceanProvider | DryRunProvider:
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
    if provider_name == PROVIDER_ROUTE53:
        return Route53Provider(token=token, zone_name=domain)
    if provider_name == PROVIDER_HETZNER:
        return HetznerProvider(token=token, zone_name=domain)
    if provider_name == PROVIDER_PORKBUN:
        return PorkbunProvider(token=token, zone_name=domain)
    if provider_name == PROVIDER_GODADDY:
        return GoDaddyProvider(token=token, zone_name=domain)
    if provider_name == PROVIDER_DIGITALOCEAN:
        return DigitalOceanProvider(token=token, zone_name=domain)

    if provider_name == PROVIDER_NAMEECHEAP:
        raise DnsError(
            f"provider '{provider_name}' is not yet implemented.\n"
            "Namecheap requires reverse-engineering their XML API\n"
            "(no documented REST API) and IP whitelist setup.\n"
            "Contributions welcome at https://github.com/forgeos/ktc-mail"
        )

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


# ── Provider documentation ──────────────────────────────────────────────────


SUPPORTED_PROVIDERS: dict[str, dict[str, str]] = {
    PROVIDER_CLOUDFLARE: {
        "name": "Cloudflare",
        "token_type": "API Token (not Global API Key)",
        "token_scope": "Zone:Read, DNS:Edit",
        "token_docs": "https://developers.cloudflare.com/fundamentals/api/get-started/create-token/",
        "dep": "none (stdlib urllib)",
    },
    PROVIDER_ROUTE53: {
        "name": "AWS Route53",
        "token_type": "IAM access key (or IAM role for EC2)",
        "token_scope": "route53:ListHostedZonesByName, route53:ListResourceRecordSets, route53:ChangeResourceRecordSets",
        "token_docs": "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/access-control-overview.html",
        "dep": "boto3 (pip install boto3)",
    },
    PROVIDER_HETZNER: {
        "name": "Hetzner DNS",
        "token_type": "API Token",
        "token_scope": "Read + Write",
        "token_docs": "https://docs.hetzner.com/dns-console/dns/general/api-access-token/",
        "dep": "none (stdlib urllib)",
    },
    PROVIDER_PORKBUN: {
        "name": "Porkbun",
        "token_type": "API Key + Secret Key (colon-separated)",
        "token_scope": "Read, Write DNS records",
        "token_docs": "https://porkbun.com/api/json/v3/documentation",
        "dep": "none (stdlib urllib)",
    },
    PROVIDER_GODADDY: {
        "name": "GoDaddy",
        "token_type": "SSO Key + SSO Secret (colon-separated)",
        "token_scope": "DNS Management",
        "token_docs": "https://developer.godaddy.com/keys/",
        "dep": "none (stdlib urllib)",
    },
    PROVIDER_DIGITALOCEAN: {
        "name": "DigitalOcean",
        "token_type": "Personal Access Token",
        "token_scope": "read + write",
        "token_docs": "https://docs.digitalocean.com/reference/api/create-personal-access-token/",
        "dep": "none (stdlib urllib)",
    },
}


def list_providers() -> str:
    """Return a formatted table of supported DNS providers and token docs."""
    lines = ["Supported DNS providers:", ""]
    lines.append(f"{'ID':<16} {'Name':<20} {'Token Scope':<40} {'Dependency':<24}")
    lines.append(f"{'─'*16} {'─'*20} {'─'*40} {'─'*24}")
    for pid, info in sorted(SUPPORTED_PROVIDERS.items()):
        lines.append(
            f"{pid:<16} {info['name']:<20} "
            f"{info['token_scope']:<40} {info['dep']:<24}"
        )
    lines.append("")
    lines.append("Token documentation:")
    for pid, info in sorted(SUPPORTED_PROVIDERS.items()):
        lines.append(f"  {pid:<14} {info['token_docs']}")
    lines.append("")
    lines.append("To add a provider: set dns_provider in setup.json and")
    lines.append("store the API token in secrets.json → dns_api_token.")
    return "\n".join(lines)


# ── CLI entry point ────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(
        description="KTC Mail DNS provider automation",
    )
    parser.add_argument(
        "command",
        choices=("apply", "verify", "acme-auth", "acme-cleanup", "plan", "providers"),
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
        if args.command == "providers":
            print(list_providers())
            return 0

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
