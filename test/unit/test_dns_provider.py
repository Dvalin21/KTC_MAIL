"""Regression tests for C2: provider parsers must NOT raise KeyError on a
malformed API record. One bad row used to abort the entire `dns apply` /
`verify` sync. Each `_to_record` / `_to_dns_record` now returns None (or an
empty list for Route53) for a record missing an essential field, and the
`list_all` loop skips it.

Also covers the Porkbun apex bug: list_all previously used
`if raw.get("type") and raw.get("name")` which is falsy for root records
(name == ""), so apex MX/TXT/SPF were never synced.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from ktc_mail_admin.config import DnsRecord
from ktc_mail_admin import dns_provider as dp

HAS_BOTO3 = False
try:
    import boto3  # noqa: F401
    HAS_BOTO3 = True
except ImportError:
    pass


# ── Cloudflare ───────────────────────────────────────────────────────────────

def test_cloudflare_to_record_well_formed():
    p = dp.CloudflareProvider(token="x", zone_name="example.com")
    rec = p._to_dns_record({"type": "A", "name": "mail.example.com",
                            "content": "1.2.3.4"})
    assert isinstance(rec, DnsRecord)
    assert rec.type == "A" and rec.name == "mail.example.com."


def test_cloudflare_to_record_malformed_returns_none():
    p = dp.CloudflareProvider(token="x", zone_name="example.com")
    assert p._to_dns_record({"content": "1.2.3.4"}) is None          # no type/name
    assert p._to_dns_record({"type": "A", "name": "mail"}) is None   # no content


def test_cloudflare_list_all_skips_malformed():
    p = dp.CloudflareProvider(token="x", zone_name="example.com")

    def fake_request(method, path, payload=None):
        if path.startswith("/zones?"):
            return {"result": [{"id": "Z1"}], "success": True}
        return {
            "result": [
                {"type": "A", "name": "mail.example.com", "content": "1.2.3.4"},
                {"content": "9.9.9.9"},  # malformed: no type/name
                {"type": "MX", "name": "example.com", "content": "10 mail.example.com."},
            ],
            "result_info": {"total_pages": 1},
            "success": True,
        }

    p._request = fake_request
    recs = p.list_all("example.com")
    assert len(recs) == 2
    assert {r.type for r in recs} == {"A", "MX"}


# ── Route53 ──────────────────────────────────────────────────────────────────

def _route53_provider():
    if not HAS_BOTO3:
        pytest.skip("boto3 not installed")
    try:
        return dp.Route53Provider(token="x", zone_name="example.com")
    except Exception:  # construction resolves AWS creds; skip if absent
        pytest.skip("Route53 provider requires AWS credentials to construct")


def test_route53_to_record_well_formed():
    p = _route53_provider()
    recs = p._to_record({"Name": "example.com.", "Type": "A",
                         "ResourceRecords": [{"Value": "1.2.3.4"}]})
    assert len(recs) == 1 and recs[0].type == "A"


def test_route53_to_record_malformed_returns_empty():
    p = _route53_provider()
    assert p._to_record({"Type": "A"}) == []                       # no Name
    assert p._to_record({"Name": "example.com.",
                         "ResourceRecords": [{"foo": "x"}]}) == []  # no Value


# ── Hetzner ──────────────────────────────────────────────────────────────────

def test_hetzner_to_record_well_formed():
    p = dp.HetznerProvider(token="x", zone_name="example.com")
    rec = p._to_record({"type": "A", "name": "mail", "value": "1.2.3.4"})
    assert rec.type == "A" and rec.name == "mail.example.com."


def test_hetzner_to_record_malformed_returns_none():
    p = dp.HetznerProvider(token="x", zone_name="example.com")
    assert p._to_record({"name": "mail", "value": "1.2.3.4"}) is None  # no type
    assert p._to_record({"type": "A", "name": "mail"}) is None         # no value


# ── Porkbun ──────────────────────────────────────────────────────────────────

def test_porkbun_to_record_apex_included():
    p = dp.PorkbunProvider(token="key:secret", zone_name="example.com")
    rec = p._to_record({"type": "MX", "name": "", "content": "10 mail.example.com."})
    assert rec is not None
    assert rec.name == "."            # apex must not be skipped
    assert rec.type == "MX"


def test_porkbun_to_record_malformed_returns_none():
    p = dp.PorkbunProvider(token="key:secret", zone_name="example.com")
    assert p._to_record({"name": "mail", "content": "1.2.3.4"}) is None  # no type
    assert p._to_record({"type": "A", "name": "mail"}) is None           # no content


# ── GoDaddy ──────────────────────────────────────────────────────────────────

def test_godaddy_to_record_well_formed():
    p = dp.GoDaddyProvider(token="key:secret", zone_name="example.com")
    rec = p._to_record({"type": "A", "name": "mail", "data": "1.2.3.4"})
    assert rec.type == "A" and rec.name == "mail.example.com."


def test_godaddy_to_record_malformed_returns_none():
    p = dp.GoDaddyProvider(token="key:secret", zone_name="example.com")
    assert p._to_record({"name": "mail", "data": "1.2.3.4"}) is None  # no type


# ── DigitalOcean ─────────────────────────────────────────────────────────────

def test_digitalocean_to_record_well_formed():
    p = dp.DigitalOceanProvider(token="x", zone_name="example.com")
    rec = p._to_record({"type": "A", "name": "mail", "data": "1.2.3.4"})
    assert rec.type == "A" and rec.name == "mail.example.com."


def test_digitalocean_to_record_malformed_returns_none():
    p = dp.DigitalOceanProvider(token="x", zone_name="example.com")
    assert p._to_record({"name": "mail", "data": "1.2.3.4"}) is None  # no type
