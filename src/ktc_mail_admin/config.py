#!/usr/bin/env python3
"""KTC Mail — shared data structures and configuration paths.

This is the single source of truth for ALL data types used across
every module. If you need to understand the system, read this file.

Rules:
- No business logic here. Just data structures and derivation.
- Every shared path constant lives here exactly once.
- No bare `print()`. No side effects at import time.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import secrets
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable


# ── Shared filesystem paths ────────────────────────────────────────────────
# Defined ONCE. Every module imports these instead of redefining them.

CONFIG_DIR = Path(os.environ.get("KTC_MAIL_CONFIG_DIR", "/etc/ktc-mail"))
STATE_DIR = Path(os.environ.get("KTC_MAIL_STATE_DIR", "/var/lib/ktc-mail"))
SETUP_PATH = CONFIG_DIR / "setup.json"
SECRETS_PATH = CONFIG_DIR / "secrets.json"
DNS_STATE_PATH = STATE_DIR / "dns-state.json"
TLS_STATE_PATH = STATE_DIR / "tls-state.json"
DKIM_DIR = CONFIG_DIR / "dkim"
SSH_CONFIG_PATH = Path("/etc/ssh/sshd_config")
ACME_WEBROOT = STATE_DIR / "acme-webroot"

CERT_NAME = "ktc-mail"
DNS_HOOK = "/usr/lib/ktc-mail/dns_provider.py"
ACME_HOOK = "/usr/lib/ktc-mail/acme_manager.py"

# Known DNS provider IDs
PROVIDER_CLOUDFLARE = "cloudflare"
PROVIDER_NAMEECHEAP = "namecheap"
PROVIDER_GODADDY = "godaddy"
PROVIDER_PORKBUN = "porkbun"
PROVIDER_ROUTE53 = "route53"
PROVIDER_DIGITALOCEAN = "digitalocean"
PROVIDER_HETZNER = "hetzner"
PROVIDER_MANUAL = "manual"

ALL_PROVIDERS = frozenset({
    PROVIDER_CLOUDFLARE,
    PROVIDER_NAMEECHEAP,
    PROVIDER_GODADDY,
    PROVIDER_PORKBUN,
    PROVIDER_ROUTE53,
    PROVIDER_DIGITALOCEAN,
    PROVIDER_HETZNER,
    PROVIDER_MANUAL,
})

# ── DNS record ─────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class DnsRecord:
    """A single DNS resource record.

    Immutable by design. Any change to a record produces a new instance.
    This eliminates the "who changed what field" class of bugs entirely.
    """

    type: str  # A, AAAA, MX, TXT, CNAME, SRV, TLSA, PTR
    name: str  # Fully qualified, e.g. "mail.example.com."  (trailing dot)
    value: str
    ttl: int = 300
    priority: int | None = None  # MX/SRV preference
    purpose: str = ""  # Human-readable documentation, NOT serialised

    def key(self) -> str:
        """Unique key for this record within a zone.

        Two records with the same type+name COLLIDE. The last one wins.
        This is how DNS works — you cannot have two TXT records with
        the same name (they merge into one multi-value set in practice,
        but for our purposes we treat them as distinct by value).
        """
        return f"{self.type}:{self.name}"

    def to_dict(self) -> dict[str, Any]:
        """Serialise for JSON state files. Excludes 'purpose'."""
        d: dict[str, Any] = {
            "type": self.type,
            "name": self.name,
            "value": self.value,
            "ttl": self.ttl,
        }
        if self.priority is not None:
            d["priority"] = self.priority
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DnsRecord:
        return cls(
            type=str(data["type"]).upper(),
            name=str(data["name"]).rstrip(".") + ".",
            value=str(data["value"]),
            ttl=int(data.get("ttl", 300)),
            priority=int(data["priority"]) if data.get("priority") else None,
        )

    def __repr__(self) -> str:
        prio = f" [{self.priority}]" if self.priority is not None else ""
        return f"{self.type:5} {self.name:40} {self.value}{prio}"


# ── DNS record set ─────────────────────────────────────────────────────────


class DnsDiff:
    """The difference between two DNS record sets.

    This is what you get when you ask 'what changed?' before writing
    anything to the provider. Always compute the diff first, then
    decide whether to push it.
    """

    def __init__(
        self,
        to_create: list[DnsRecord],
        to_update: list[tuple[DnsRecord, DnsRecord]],
        to_delete: list[DnsRecord],
    ) -> None:
        self.to_create = to_create
        self.to_update = to_update  # (old, new)
        self.to_delete = to_delete

    @property
    def is_empty(self) -> bool:
        return not (self.to_create or self.to_update or self.to_delete)

    @property
    def summary(self) -> str:
        parts = []
        if self.to_create:
            parts.append(f"+{len(self.to_create)} create")
        if self.to_update:
            parts.append(f"~{len(self.to_update)} update")
        if self.to_delete:
            parts.append(f"-{len(self.to_delete)} delete")
        return ", ".join(parts) if parts else "no changes"

    def __bool__(self) -> bool:
        return not self.is_empty


class DnsRecordSet:
    """Complete DNS record set for one domain. Source of truth.

    All DNS operations flow through this type. The provider is just
    transport — it reads and writes what this object says.

    Records are indexed by type+name in a dict for O(1) lookup.
    Collisions (same type+name) are not allowed in this structure.
    """

    def __init__(self, domain: str) -> None:
        self.domain = domain.rstrip(".") + "."
        self._records: dict[str, DnsRecord] = {}

    # ── Access ─────────────────────────────────────────────────────────

    def add(self, record: DnsRecord) -> None:
        key = record.key()
        if key in self._records:
            # This is a replace, which changes the value.
            # Immutable record means we create a new key entry.
            pass
        self._records[key] = record

    def remove(self, type: str, name: str) -> None:
        key = f"{type.upper()}:{name.rstrip('.')}."
        self._records.pop(key, None)

    def find(self, type: str, name: str) -> DnsRecord | None:
        key = f"{type.upper()}:{name.rstrip('.')}."
        return self._records.get(key)

    def all(self) -> list[DnsRecord]:
        return sorted(self._records.values(), key=lambda r: (r.type, r.name))

    def __len__(self) -> int:
        return len(self._records)

    def __iter__(self):
        return iter(self.all())

    # ── Diff ──────────────────────────────────────────────────────────

    def diff(self, remote: DnsRecordSet) -> DnsDiff:
        """Compute difference between local and remote record sets.

        Never writes anything. Just computes what WOULD change.
        """
        local_keys = set(self._records.keys())
        remote_keys = set(remote._records.keys())

        to_create_keys = local_keys - remote_keys
        to_delete_keys = remote_keys - local_keys
        common_keys = local_keys & remote_keys

        to_create = [self._records[k] for k in sorted(to_create_keys)]
        to_delete = [remote._records[k] for k in sorted(to_delete_keys)]

        to_update: list[tuple[DnsRecord, DnsRecord]] = []
        for key in sorted(common_keys):
            local = self._records[key]
            remote_rec = remote._records[key]
            if local.value != remote_rec.value or local.ttl != remote_rec.ttl:
                to_update.append((remote_rec, local))

        return DnsDiff(to_create, to_update, to_delete)

    # ── Hashing / verification ────────────────────────────────────────

    def content_hash(self) -> str:
        """SHA-256 of all records, for drift detection."""
        blob = json_dumps([r.to_dict() for r in self.all()])
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def verify(self, remote: DnsRecordSet) -> list[str]:
        """Compare local to remote. Returns list of mismatch descriptions."""
        issues: list[str] = []
        found = set()
        for record in self:
            key = record.key()
            found.add(key)
            remote_rec = remote.find(record.type, record.name)
            if remote_rec is None:
                issues.append(f"missing: {record}")
            elif remote_rec.value != record.value:
                issues.append(f"mismatch: {record.type} {record.name}")
                issues.append(f"  local:  {record.value}")
                issues.append(f"  remote: {remote_rec.value}")
        for record in remote:
            key = record.key()
            if key not in found:
                issues.append(f"unexpected remote: {record}")
        return issues

    # ── Serialisation ─────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "records": [r.to_dict() for r in self.all()],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DnsRecordSet:
        rs = cls(domain=str(data["domain"]))
        for item in data.get("records", []):
            rs.add(DnsRecord.from_dict(item))
        return rs


# ── DNS transport protocol ──────────────────────────────────────────────────


@runtime_checkable
class DnsTransport(Protocol):
    """Minimal provider adapter: create, read, update, delete DNS records.

    This is intentionally narrow. A transport does one thing: sync
    records between the DnsRecordSet and the provider API. No business
    logic, no validation, no state tracking.
    """

    def list_all(self, domain: str) -> list[DnsRecord]: ...

    def create(self, record: DnsRecord) -> None: ...

    def update(self, old: DnsRecord, new: DnsRecord) -> None: ...

    def delete(self, record: DnsRecord) -> None: ...

    def supports_ptr(self) -> bool:
        """Override to True if the provider can manage PTR records."""
        return False


# ── DKIM keys ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class DkimKeyPair:
    """An RSA key pair for DKIM signing of outgoing mail.

    Generated during setup. The private key is stored with 0600
    permissions and never leaves the server. The public key goes
    into DNS as a TXT record.
    """

    selector: str  # e.g. "default" or "2026-05"
    private_key_pem: str
    public_key_dns: str  # The base64-encoded public key for DNS

    @classmethod
    def generate(cls, selector: str = "default") -> DkimKeyPair:
        """Generate a 2048-bit RSA DKIM key pair.

        Uses openssl because Python's cryptography library may not be
        available in the stdlib-only initial phase.
        """
        priv = subprocess.run(
            ["openssl", "genrsa", "2048"],
            capture_output=True,
            check=True,
        )
        priv_pem = priv.stdout.decode("utf-8")

        pub_der = subprocess.run(
            ["openssl", "rsa", "-pubout", "-outform", "DER"],
            input=priv.stdout,
            capture_output=True,
            check=True,
        )
        pub_b64 = pub_der.stdout.hex()
        # openssl base64 -A produces single-line base64
        base64_proc = subprocess.run(
            ["openssl", "base64", "-A"],
            input=pub_der.stdout,
            capture_output=True,
            check=True,
        )
        pub_dns = base64_proc.stdout.decode("utf-8").strip()

        return cls(
            selector=selector,
            private_key_pem=priv_pem,
            public_key_dns=pub_dns,
        )

    def dns_txt_record(self, domain: str) -> DnsRecord:
        """Produce the DKIM DNS TXT record."""
        name = f"{self.selector}._domainkey.{domain.rstrip('.')}."
        value = f"v=DKIM1; k=rsa; p={self.public_key_dns}"
        return DnsRecord("TXT", name, value, purpose="DKIM signing key")


# ── Security policy ────────────────────────────────────────────────────────


@dataclass
class SecurityPolicy:
    """Complete security posture for the mail server.

    Sensible defaults that work for 90% of deployments. The remaining
    10% can use Advanced Settings to change them.
    """

    # Firewall
    ports_open: frozenset[int] = frozenset({22, 25, 443, 587, 993})
    http01_mode: bool = False  # when True, adds port 80
    managesieve_enabled: bool = False  # port 4190

    # SSH
    ssh_key_only: bool = True
    ssh_password_auth: bool = False
    ssh_permit_root_login: bool = False
    ssh_password_warning_acknowledged: bool = False

    # Anti-abuse
    fail2ban_enabled: bool = True
    crowdsec_enabled: bool = True
    geoip_blocking: bool = True
    postfix_anvil_rates: bool = True
    dnsbl_checking: bool = True

    # Postfix postscreen
    postscreen_enabled: bool = True

    @property
    def actual_open_ports(self) -> list[int]:
        ports = set(self.ports_open)
        if self.http01_mode:
            ports.add(80)
        if self.managesieve_enabled:
            ports.add(4190)
        return sorted(ports)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ports_open": sorted(self.ports_open),
            "http01_mode": self.http01_mode,
            "managesieve_enabled": self.managesieve_enabled,
            "ssh_key_only": self.ssh_key_only,
            "ssh_password_auth": self.ssh_password_auth,
            "ssh_permit_root_login": self.ssh_permit_root_login,
            "fail2ban_enabled": self.fail2ban_enabled,
            "crowdsec_enabled": self.crowdsec_enabled,
            "geoip_blocking": self.geoip_blocking,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SecurityPolicy:
        return cls(
            ports_open=frozenset(data.get("ports_open", [22, 25, 443, 587, 993])),
            http01_mode=bool(data.get("http01_mode", False)),
            managesieve_enabled=bool(data.get("managesieve_enabled", False)),
            ssh_key_only=bool(data.get("ssh_key_only", True)),
            ssh_password_auth=bool(data.get("ssh_password_auth", False)),
            ssh_permit_root_login=bool(data.get("ssh_permit_root_login", False)),
            fail2ban_enabled=bool(data.get("fail2ban_enabled", True)),
            crowdsec_enabled=bool(data.get("crowdsec_enabled", True)),
            geoip_blocking=bool(data.get("geoip_blocking", True)),
        )


# ── SMTP relay ─────────────────────────────────────────────────────────────


@dataclass
class SmtpRelayConfig:
    """How outbound SMTP reaches the internet when port 25 is blocked.

    'direct'       — port 25 works, no relay needed
    'vps_relay'    — provision a $5/mo VPS with WireGuard tunnel
    'ipv6_then_relay' — try IPv6 first, fall back to VPS for IPv4-only
    'smarthost'    — use an ISP-provided or third-party relay
    """

    mode: str = "direct"  # direct | vps_relay | ipv6_then_relay | smarthost

    # VPS relay
    vps_provider: str = ""  # "hetzner" | "digitalocean" | "linode"
    vps_api_token: str = ""
    vps_region: str = ""

    # Smarthost (last resort)
    smarthost_host: str = ""
    smarthost_port: int = 587
    smarthost_user: str = ""
    smarthost_password: str = ""

    def is_needed(self) -> bool:
        return self.mode in {"vps_relay", "ipv6_then_relay", "smarthost"}

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "vps_provider": self.vps_provider,
            "vps_region": self.vps_region,
            "smarthost_host": self.smarthost_host,
            "smarthost_port": self.smarthost_port,
            "smarthost_user": self.smarthost_user,
        }


# ── Setup profile ──────────────────────────────────────────────────────────


DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def validate_domain(domain: str) -> bool:
    return bool(DOMAIN_RE.match(domain))


@dataclass
class SetupProfile:
    """Complete mail server setup profile.

    This is THE configuration. Everything the system needs to know
    about itself, the mail setup, DNS, security, and automation lives
    here.

    User provides 3 fields at minimum:
      - domain
      - dns_api_token (or indicates manual DNS)
      - admin_email

    Everything else is either auto-detected or derived.
    """

    # ── User-provided ─────────────────────────────────────────────────

    domain: str
    dns_api_token: str = ""
    admin_email: str = ""

    # ── Auto-detected during setup ────────────────────────────────────

    public_ipv4: str = ""
    public_ipv6: str = ""
    registrar: str = ""  # auto-detected from whois
    dns_provider: str = ""  # chosen provider (may differ from registrar)
    port_25_blocked: bool = False
    has_ipv6: bool = False

    # ── Generated during setup ────────────────────────────────────────

    security: SecurityPolicy = field(default_factory=SecurityPolicy)
    smtp_relay: SmtpRelayConfig = field(default_factory=SmtpRelayConfig)
    dkim: DkimKeyPair | None = None
    certificate_mode: str = "dns-01"  # dns-01 | http-01 | upload
    dns_provider_manual: bool = False  # True if user picked "manual DNS"
    manage_system_hostname: bool = True
    setup_phase: str = "BOOTSTRAP"

    # Renewal hooks config
    reload_services: tuple[str, ...] = ("postfix", "dovecot", "nginx")
    update_tlsa_on_renewal: bool = True

    # ── Derived hostnames (read-only properties) ──────────────────────

    @property
    def hostname(self) -> str:
        return f"mail.{self.domain}"

    @property
    def admin_host(self) -> str:
        return f"admin.{self.domain}"

    @property
    def webmail_host(self) -> str:
        return f"email.{self.domain}"

    @property
    def autoconfig_host(self) -> str:
        return f"autoconfig.{self.domain}"

    @property
    def autodiscover_host(self) -> str:
        return f"autodiscover.{self.domain}"

    @property
    def imap_host(self) -> str:
        return f"imap.{self.domain}"

    @property
    def smtp_host(self) -> str:
        return f"smtp.{self.domain}"

    @property
    def all_hostnames(self) -> list[str]:
        """All 7 service hostnames, no dupes, first is primary."""
        seen: set[str] = set()
        result: list[str] = []
        for name in [
            self.hostname,
            self.admin_host,
            self.webmail_host,
            self.autoconfig_host,
            self.autodiscover_host,
            self.imap_host,
            self.smtp_host,
        ]:
            if name not in seen:
                seen.add(name)
                result.append(name)
        return result

    @property
    def cert_san_names(self) -> list[str]:
        """SAN entries for the TLS certificate.

        Returns wildcard *.domain FIRST, then all explicit hostnames.
        This ordering ensures the wildcard is the primary identity.
        """
        return [f"*.{self.domain}", *self.all_hostnames]

    def cert_san_dns_args(self) -> list[str]:
        """certbot -d arguments for all SAN names."""
        args: list[str] = []
        for name in self.cert_san_names:
            args.extend(["-d", name])
        return args

    # ── DNS record generation ─────────────────────────────────────────

    def generate_dns_records(self) -> DnsRecordSet:
        """Produce the complete DNS record set from this profile.

        Calling this generates a FRESH set. It does NOT modify any
        stored state. The caller decides whether to push it.
        """
        rs = DnsRecordSet(self.domain)

        # A / AAAA — server address
        if self.public_ipv4:
            rs.add(DnsRecord("A", self.hostname, self.public_ipv4,
                             purpose="Mail server IPv4"))
        if self.public_ipv6:
            rs.add(DnsRecord("AAAA", self.hostname, self.public_ipv6,
                             purpose="Mail server IPv6"))

        # MX — inbound mail routing
        rs.add(DnsRecord("MX", self.domain, f"10 {self.hostname}.",
                         purpose="Inbound mail routing"))

        # SPF — who can send mail for this domain
        spf_parts = ["v=spf1"]
        if self.public_ipv4:
            spf_parts.append(f"ip4:{self.public_ipv4}")
        if self.public_ipv6:
            spf_parts.append(f"ip6:{self.public_ipv6}")
        spf_parts.append("mx")
        spf_parts.append("~all")  # softfail by default
        rs.add(DnsRecord("TXT", self.domain, " ".join(spf_parts),
                         purpose="SPF sender policy"))

        # DKIM — signing key
        if self.dkim is not None:
            rs.add(self.dkim.dns_txt_record(self.domain))

        # DMARC — policy + reporting (optional: start at p=none)
        dmarc = (
            f"v=DMARC1; p=none; "
            f"rua=mailto:dmarc@{self.domain}; "
            f"ruf=mailto:dmarc@{self.domain}; "
            f"fo=1"
        )
        rs.add(DnsRecord("TXT", f"_dmarc.{self.domain}", dmarc,
                         purpose="DMARC (p=none to start, promote later)"))

        # TLS-RPT — TLS reporting
        rs.add(DnsRecord(
            "TXT", f"_smtp._tls.{self.domain}",
            f"v=TLSRPTv1; rua=mailto:tls-rpt@{self.domain}",
            purpose="SMTP TLS reporting",
        ))

        # CNAME — all 7 service hostnames → mail hostname
        cname_target = f"{self.hostname}."
        cname_map = [
            (self.admin_host, "Admin GUI"),
            (self.webmail_host, "Webmail"),
            (self.autoconfig_host, "Auto-config (Thunderbird)"),
            (self.autodiscover_host, "Auto-discover (Outlook)"),
            (self.imap_host, "Explicit IMAP endpoint"),
            (self.smtp_host, "Explicit SMTP endpoint"),
        ]
        for host, purpose in cname_map:
            rs.add(DnsRecord("CNAME", host, cname_target, purpose=purpose))

        # SRV records — service discovery
        rs.add(DnsRecord(
            "SRV", f"_submission._tcp.{self.domain}",
            f"0 1 587 {self.hostname}.",
            purpose="Submission service discovery",
        ))
        rs.add(DnsRecord(
            "SRV", f"_imaps._tcp.{self.domain}",
            f"0 1 993 {self.hostname}.",
            purpose="IMAPS service discovery",
        ))

        # MTA-STS reporting (policy file served via HTTPS, not DNS TXT)
        # The _mta-sts TXT just advertises the policy location.
        rs.add(DnsRecord(
            "TXT", f"_mta-sts.{self.domain}",
            f"v=STSv1; id=1",
            purpose="MTA-STS policy advertisement",
        ))

        return rs

    def generate_dns_plan(self) -> str:
        """Human-readable DNS plan for the setup summary."""
        rs = self.generate_dns_records()
        lines = [f"DNS plan for {self.domain}:"]
        for r in rs:
            rrtype = r.type.ljust(6)
            name = r.name.removesuffix(f".{self.domain}.").ljust(24)
            lines.append(f"  {rrtype} {name} {r.value}")
        if self.dkim is None:
            lines.append("  ⚠ DKIM: not generated yet")
        return "\n".join(lines)

    # ── Serialisation ─────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "domain": self.domain,
            "admin_email": self.admin_email,
            "public_ipv4": self.public_ipv4,
            "public_ipv6": self.public_ipv6,
            "registrar": self.registrar,
            "dns_provider": self.dns_provider,
            "port_25_blocked": self.port_25_blocked,
            "has_ipv6": self.has_ipv6,
            "security": self.security.to_dict(),
            "smtp_relay": self.smtp_relay.to_dict(),
            "certificate_mode": self.certificate_mode,
            "dns_provider_manual": self.dns_provider_manual,
            "manage_system_hostname": self.manage_system_hostname,
            "setup_phase": self.setup_phase,
            "hostname": self.hostname,
            "admin_host": self.admin_host,
            "webmail_host": self.webmail_host,
            "autoconfig_host": self.autoconfig_host,
            "autodiscover_host": self.autodiscover_host,
            "imap_host": self.imap_host,
            "smtp_host": self.smtp_host,
            "reload_services": list(self.reload_services),
            "update_tlsa_on_renewal": self.update_tlsa_on_renewal,
            "open_ports": self.security.actual_open_ports,
            "cert_san_names": self.cert_san_names,
        }
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SetupProfile:
        profile = cls(
            domain=str(data["domain"]),
            dns_api_token=data.get("dns_api_token", ""),
            admin_email=str(data.get("admin_email", "")),
            public_ipv4=str(data.get("public_ipv4", "")),
            public_ipv6=str(data.get("public_ipv6", "")),
            registrar=str(data.get("registrar", "")),
            dns_provider=str(data.get("dns_provider", "")),
            port_25_blocked=bool(data.get("port_25_blocked", False)),
            has_ipv6=bool(data.get("has_ipv6", False)),
            security=SecurityPolicy.from_dict(data.get("security", {})),
            smtp_relay=SmtpRelayConfig(**data.get("smtp_relay", {})),
            certificate_mode=str(data.get("certificate_mode", "dns-01")),
            dns_provider_manual=bool(data.get("dns_provider_manual", False)),
            manage_system_hostname=bool(data.get("manage_system_hostname", True)),
            setup_phase=str(data.get("setup_phase", "BOOTSTRAP")),
            reload_services=tuple(data.get("reload_services", ["postfix", "dovecot", "nginx"])),
            update_tlsa_on_renewal=bool(data.get("update_tlsa_on_renewal", True)),
        )
        # DKIM is NOT serialised to JSON (private key stays in separate file)
        return profile


# ── Utility helpers ────────────────────────────────────────────────────────


def json_dumps(obj: Any) -> str:
    """Deterministic JSON for hashing."""
    import json
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def save_json_private(path: Path, payload: dict[str, Any]) -> None:
    """Write a JSON file with 0600 permissions, atomically.

    Uses tempfile + rename to avoid the chmod race window that
    write-then-chmod creates.
    """
    import json
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    tmp.chmod(0o600)
    tmp.rename(path)  # atomic on the same filesystem


def read_json(path: Path) -> dict[str, Any]:
    """Read and parse a JSON file."""
    import json
    return json.loads(path.read_text(encoding="utf-8"))


def detect_public_ipv4() -> str:
    """Detect public IPv4 via external API. Returns '' on failure."""
    try:
        import urllib.request
        resp = urllib.request.urlopen("https://api.ipify.org", timeout=5)
        return resp.read().decode("utf-8").strip()
    except Exception:
        return ""


def detect_public_ipv6() -> str:
    """Detect public IPv6 via external API. Returns '' on failure."""
    try:
        import urllib.request
        resp = urllib.request.urlopen("https://api6.ipify.org", timeout=5)
        return resp.read().decode("utf-8").strip()
    except Exception:
        return ""


def detect_port_25_blocked() -> bool:
    """Probe port 25 to a known SMTP server.

    Returns True if connection times out or is refused
    (likely blocked by ISP). Returns False if accepted.
    """
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex(("gmail-smtp-in.l.google.com", 25))
        sock.close()
        return result != 0
    except Exception:
        return True  # assume blocked if we can't even probe


def detect_registrar(domain: str) -> str:
    """Probe whois to detect the domain registrar.

    Returns a known provider ID or 'unknown'. This is best-effort:
    whois output format varies wildly.
    """
    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True, text=True, timeout=10,
        )
        output = (result.stdout + result.stderr).lower()
        if "namecheap" in output:
            return PROVIDER_NAMEECHEAP
        if "godaddy" in output:
            return PROVIDER_GODADDY
        if "cloudflare" in output:
            return PROVIDER_CLOUDFLARE
        if "porkbun" in output:
            return PROVIDER_PORKBUN
        if "route53" in output or "amazon" in output:
            return PROVIDER_ROUTE53
        return ""
    except Exception:
        return ""


def system_hostname() -> str:
    """Return the current system hostname, or ''."""
    try:
        result = subprocess.run(
            ["hostname", "-f"],
            capture_output=True, text=True, timeout=5,
        )
        return result.stdout.strip()
    except Exception:
        return ""
