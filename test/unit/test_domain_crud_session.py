"""Session-authenticated domain CRUD path (closes the click-through gap).

The unit tests in test_domain_crud.py prove the decision logic and the
auth-gate redirect, but not the real session -> CSRF -> apply -> file
mutation path. This test seeds a real admin account, logs in through the
actual /login route (so we get a genuine signed session cookie), then drives
a real POST /domains/add via TestClient, asserting setup.json actually
changes and the apply-pipeline summary is returned.

MFA is disabled for the seeded account, so no second factor is required.
"""
import json

import pytest

from ktc_mail_admin import admin_server as a
from ktc_mail_admin import config as cfg_mod


@pytest.fixture
def authed_client(monkeypatch):
    monkeypatch.setenv("KTC_DEV", "1")  # allow insecure session cookies
    # Seed a valid setup profile so load_profile() works (use the real model
    # so from_dict round-trips; a hand-rolled dict trips required fields).
    cfg_mod.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    prof = cfg_mod.SetupProfile(
        domain="primary.example.com",
        domains=["alias.example.com"], auth_backend="os")
    (cfg_mod.CONFIG_DIR / "setup.json").write_text(
        json.dumps(prof.to_dict()), encoding="utf-8")
    # Seed a real admin account with a known password.
    pw_hash = a.hash_password("test-pass-123")
    (cfg_mod.CONFIG_DIR / "admin-hash.json").write_text(
        json.dumps({"email": "admin@example.com", "role": "admin",
                    "password_hash": pw_hash, "mfa_enabled": False,
                    "session_version": 0}),
        encoding="utf-8")

    from fastapi.testclient import TestClient
    with TestClient(a.create_app()) as c:
        # Genuine login: GET login page for CSRF token, then POST creds.
        page = c.get("/login")
        import re
        m = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
        assert m, "login page must expose a csrf_token"
        csrf = m.group(1)
        r = c.post("/login",
                   data={"email": "admin@example.com",
                         "password": "test-pass-123", "csrf_token": csrf},
                   follow_redirects=False)
        assert r.status_code in (302, 303), "login must succeed"
        yield c, csrf


def _profile():
    return json.loads((cfg_mod.CONFIG_DIR / "setup.json").read_text())


def test_authed_add_mutates_setup_json_and_returns_apply(authed_client):
    c, csrf = authed_client
    r = c.post("/domains/add",
               data={"domain": "added.example.com", "csrf_token": csrf},
               follow_redirects=False)
    assert r.status_code == 302, r.headers.get("location")
    loc = r.headers["location"]
    assert "msg=Added" in loc
    assert "apply=" in loc, "apply-pipeline summary must be returned"
    prof = _profile()
    assert prof["domains"] == ["alias.example.com", "added.example.com"]


def test_authed_add_rejects_wrong_csrf(authed_client):
    c, csrf = authed_client
    r = c.post("/domains/add",
               data={"domain": "x.example.com", "csrf_token": "wrong-token"},
               follow_redirects=False)
    assert r.status_code == 302 and "error" in r.headers["location"]
    assert _profile()["domains"] == ["alias.example.com"]


def test_authed_delete_removes_domain(authed_client):
    c, csrf = authed_client
    r = c.post("/domains/delete",
               data={"domain": "alias.example.com", "csrf_token": csrf},
               follow_redirects=False)
    assert r.status_code == 302 and "msg=" in r.headers["location"]
    assert _profile()["domains"] == []


def test_domains_page_renders_apply_banner_and_confirm_dialog(authed_client):
    c, csrf = authed_client
    r = c.get("/domains",
              params={"msg": "Added x",
                      "apply": "Profile: done — saved|TLS certificate: warn — retry"},
              follow_redirects=False)
    assert r.status_code == 200
    body = r.text
    # Apply-pipeline summary rendered as a status list.
    assert "Apply result" in body
    assert "TLS certificate: warn" in body
    # Confirm-before-delete dialog wired to the delete forms.
    assert "delete-form" in body
    assert "Delete domain" in body  # confirm() prompt text

