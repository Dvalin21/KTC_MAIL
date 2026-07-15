"""Regression tests for C1: MX/SRV DNS records must NOT embed priority
in the value string. The DnsRecord carries priority in `priority`; the
value holds ONLY the target (MX) or "weight port target" (SRV). Each
provider adapter sends the correct shape for its API:

  - Cloudflare / Porkbun / DigitalOcean / GoDaddy: separate field
    (priority / prio / priority / priority)
  - Hetzner / Route53: priority embedded in the value string
    ("prio target" / "prio weight port target") -- they have NO separate
    field -- and their read parsers split it back out so diff() converges.

Before this fix, config.py built f"10 {hostname}." (double-dot, no
priority field) and every provider emitted a malformed MX -> inbound
mail bounced.
"""

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from ktc_mail_admin.config import DnsRecord, DnsRecordSet, SetupProfile
from ktc_mail_admin import dns_provider as dp


MX = DnsRecord("MX", "example.com", "mail.example.com.", priority=10)
SRV = DnsRecord("SRV", "_submission._tcp.example.com", "1 587 mail.example.com.", priority=0)


def _capture(self, *args, **kwargs):
    # Capture the full positional arg tuple; the payload is always the
    # last positional regardless of each provider's _request arity.
    self._captured = {"args": args, "kwargs": kwargs}
    return {}


def _make_provider(cls, **kw):
    p = cls(token="dummy:dummy", zone_name="example.com")
    p._zone_id = "ZONE"                       # skip the network zone-lookup
    p._request = _capture.__get__(p, cls)     # instance-bound fake
    return p


def _payload(p):
    return p._captured["args"][-1]


# ── Config generation (source of truth) ────────────────────────────────────

def test_generate_dns_records_shape():
    rs = SetupProfile(domain="example.com").generate_dns_records()
    recs = {r.type: r for r in rs if r.type in ("MX", "SRV")}
    mx = recs["MX"]
    assert mx.value == "mail.example.com.", mx.value
    assert mx.priority == 10, mx.priority
    assert not mx.value[0].isdigit(), "MX value must not embed priority"

    for r in rs:
        if r.type != "SRV":
            continue
        assert r.priority == 0, r
        parts = r.value.split()
        assert parts[0] == "1", r.value        # "weight port target"
        assert len(parts) == 3, r.value


# ── Write paths: separate-field providers ──────────────────────────────────

def test_cloudflare_write():
    p = _make_provider(dp.CloudflareProvider)
    p.create(MX)
    assert _payload(p)["content"] == "mail.example.com."
    assert _payload(p)["priority"] == 10
    p.create(SRV)
    assert _payload(p)["content"] == "1 587 mail.example.com."
    assert _payload(p)["priority"] == 0


def test_porkbun_write():
    p = _make_provider(dp.PorkbunProvider)
    p.create(MX)
    assert _payload(p)["content"] == "mail.example.com."
    assert _payload(p)["prio"] == 10
    p.create(SRV)
    assert _payload(p)["content"] == "1 587 mail.example.com."
    assert _payload(p)["prio"] == 0


def test_digitalocean_write():
    p = _make_provider(dp.DigitalOceanProvider)
    p.create(MX)
    assert _payload(p)["data"] == "mail.example.com."
    assert _payload(p)["priority"] == 10
    p.create(SRV)
    assert _payload(p)["data"] == "1 587 mail.example.com."
    assert _payload(p)["priority"] == 0


def test_godaddy_write():
    p = _make_provider(dp.GoDaddyProvider)
    p.create(MX)
    assert _payload(p)[0]["data"] == "mail.example.com."
    assert _payload(p)[0]["priority"] == 10
    p.create(SRV)
    assert _payload(p)[0]["data"] == "1 587 mail.example.com."
    assert _payload(p)[0]["priority"] == 0


# ── Write paths: embedded-value providers ──────────────────────────────────

def test_hetzner_write():
    p = _make_provider(dp.HetznerProvider)
    p.create(MX)
    assert _payload(p)["value"] == "10 mail.example.com."
    assert "priority" not in _payload(p)        # Hetzner has no such field
    p.create(SRV)
    assert _payload(p)["value"] == "0 1 587 mail.example.com."


def test_route53_write():
    p = dp.Route53Provider(token="", zone_name="example.com")
    p._zone_id = "ZONE"
    captured = {}
    p._client = SimpleNamespace(
        change_resource_record_sets=lambda **kw: captured.update(kw))
    p.create(MX)
    val = captured["ChangeBatch"]["Changes"][0]["ResourceRecordSet"]["ResourceRecords"][0]["Value"]
    assert val == "10 mail.example.com.", val
    p.create(SRV)
    val = captured["ChangeBatch"]["Changes"][0]["ResourceRecordSet"]["ResourceRecords"][0]["Value"]
    assert val == "0 1 587 mail.example.com.", val


# ── Read paths: embedded providers must split priority back out ────────────

def test_hetzner_read_splits_priority():
    p = dp.HetznerProvider(token="dummy", zone_name="example.com")
    rec = p._to_record({"name": "@", "type": "MX", "value": "10 mail.example.com.", "ttl": 300})
    assert rec.value == "mail.example.com.", rec.value
    assert rec.priority == 10, rec.priority


def test_route53_read_splits_priority():
    p = dp.Route53Provider(token="", zone_name="example.com")
    rec = p._to_record({
        "Name": "example.com.", "Type": "MX", "TTL": 300,
        "ResourceRecords": [{"Value": "10 mail.example.com."}],
    })[0]
    assert rec.value == "mail.example.com.", rec.value
    assert rec.priority == 10, rec.priority


# ── Round-trip: write embedded -> read splits -> equals local (no churn) ────

def test_hetzner_roundtrip_no_churn():
    p = _make_provider(dp.HetznerProvider)        # fake _request, skips network
    p.create(MX)                                  # captures embedded payload
    remade = p._to_record({
        "name": "@", "type": "MX", "value": _payload(p)["value"], "ttl": 300,
    })
    assert remade.value == MX.value
    assert remade.priority == MX.priority


def test_route53_roundtrip_no_churn():
    p = dp.Route53Provider(token="", zone_name="example.com")
    p._zone_id = "ZONE"
    captured = {}
    p._client = SimpleNamespace(
        change_resource_record_sets=lambda **kw: captured.update(kw))
    p.create(MX)
    val = captured["ChangeBatch"]["Changes"][0]["ResourceRecordSet"]["ResourceRecords"][0]["Value"]
    remade = p._to_record({
        "Name": "example.com.", "Type": "MX", "TTL": 300,
        "ResourceRecords": [{"Value": val}],
    })[0]
    assert remade.value == MX.value
    assert remade.priority == MX.priority


# ── H4: trailing-dot normalisation must make diff() converge ───────────────

def test_dnsrecord_name_normalized_to_trailing_dot():
    assert DnsRecord("MX", "example.com", "v").name == "example.com."
    assert DnsRecord("MX", "example.com.", "v").name == "example.com."   # idempotent
    assert DnsRecord("MX", "@", "v").name == "@"                         # apex preserved


def test_trailing_dot_no_churn_on_apply():
    local = SetupProfile(domain="example.com").generate_dns_records()
    p = dp.HetznerProvider(token="dummy", zone_name="example.com")
    remote = DnsRecordSet("example.com")
    # Provider returns dotted full names + embedded priority (Hetzner shape;
    # apex records come back with an empty name, mapped to the zone root).
    remote.add(p._to_record({"name": "", "type": "MX", "value": "10 mail.example.com.", "ttl": 300}))
    remote.add(p._to_record({"name": "_submission._tcp", "type": "SRV", "value": "0 1 587 mail.example.com.", "ttl": 300}))
    diff = local.diff(remote)
    churn = {r.key() for r in diff.to_create} | {r.key() for r in diff.to_delete}
    churn |= {u[1].key() for u in diff.to_update}
    # MX and the mirrored SRV must NOT churn every sync.
    assert "MX:example.com." not in churn
    assert "SRV:_submission._tcp.example.com." not in churn
