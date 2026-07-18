"""Domain CRUD (admin-panel only) — decision logic + auth gate.

Domains are global infra config (DNS, TLS SANs, transport maps), so they live
behind the session-authenticated panel and are deliberately NOT in the REST
API. The route handlers delegate all decisions to the pure, module-level
`edit_profile_domains`; this test covers that tree directly, plus the auth
gate on the routes (unauthenticated -> 302 to login).
"""
import json

import pytest

from ktc_mail_admin import admin_server as a
from ktc_mail_admin.config import SetupProfile


def _profile(domain="primary.example.com", domains=None):
    return SetupProfile(domain=domain, domains=list(domains or ["alias.example.com"]),
                        auth_backend="os")


# ── edit_profile_domains decision tree ──────────────────────────────────────

def test_add_appends_alias():
    p = _profile()
    a.edit_profile_domains(p, "add", new="new.example.com")
    assert p.domains == ["alias.example.com", "new.example.com"]


def test_add_rejects_invalid():
    p = _profile()
    with pytest.raises(ValueError):
        a.edit_profile_domains(p, "add", new="not a domain!")


def test_add_rejects_duplicate():
    p = _profile()
    with pytest.raises(ValueError):
        a.edit_profile_domains(p, "add", new="alias.example.com")


def test_modify_renames_alias():
    p = _profile()
    a.edit_profile_domains(p, "modify", old="alias.example.com",
                           new="renamed.example.com")
    assert p.domains == ["renamed.example.com"]


def test_modify_renames_primary():
    p = _profile()
    a.edit_profile_domains(p, "modify", old="primary.example.com",
                           new="newprimary.example.com")
    assert p.domain == "newprimary.example.com"


def test_modify_rejects_duplicate_target():
    # renaming an alias onto a *different* already-hosted domain is rejected
    p = _profile()
    with pytest.raises(ValueError):
        a.edit_profile_domains(p, "modify", old="alias.example.com",
                               new="primary.example.com")
    # renaming an alias to itself is a harmless no-op (allowed)
    p2 = _profile()
    a.edit_profile_domains(p2, "modify", old="alias.example.com",
                           new="alias.example.com")
    assert p2.domains == ["alias.example.com"]


def test_modify_rejects_invalid_new():
    p = _profile()
    with pytest.raises(ValueError):
        a.edit_profile_domains(p, "modify", old="alias.example.com",
                               new="bad name")


def test_delete_removes_alias():
    p = _profile()
    a.edit_profile_domains(p, "delete", old="alias.example.com")
    assert p.domains == []


def test_delete_blocks_primary():
    p = _profile()
    with pytest.raises(ValueError):
        a.edit_profile_domains(p, "delete", old="primary.example.com")


def test_delete_rejects_unhosted():
    p = _profile()
    with pytest.raises(ValueError):
        a.edit_profile_domains(p, "delete", old="ghost.example.com")


# ── route auth gate (unauthenticated must redirect to login) ────────────────

def test_domain_write_routes_absent_from_api_v1_boundary():
    # GET /api/v1/domains (read-only, tenant-scoped) is allowed; mutation is
    # panel-only. Assert no /api/v1/domains route accepts POST/DELETE/PUT.
    from fastapi.routing import APIRoute
    api_domains = [rt for rt in a.create_app().routes
                   if isinstance(rt, APIRoute) and rt.path == "/api/v1/domains"]
    assert api_domains, "GET /api/v1/domains should exist"
    assert api_domains[0].methods == {"GET"}, \
        f"domain API must be GET-only, got {api_domains[0].methods}"


def test_domains_add_requires_session():
    from fastapi.testclient import TestClient
    with TestClient(a.create_app()) as c:
        r = c.post("/domains/add", data={"domain": "x.example.com"},
                   follow_redirects=False)
        assert r.status_code == 302 and "/login" in r.headers.get("location", "")


def test_domains_delete_requires_session():
    from fastapi.testclient import TestClient
    with TestClient(a.create_app()) as c:
        r = c.post("/domains/delete", data={"domain": "x.example.com"},
                   follow_redirects=False)
        assert r.status_code == 302 and "/login" in r.headers.get("location", "")
