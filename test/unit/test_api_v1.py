"""Unit tests for the REST API v1 auth + scope enforcement.

Exercises the Bearer-token dependency and read/write scope gate without
depending on backend filesystem state (user_manager, rspamd). The scope check
fires before any backend call, so these assertions are hermetic.
"""

import hashlib
import json

import pytest

from ktc_mail_admin import admin_server as a
from ktc_mail_admin import config as cfg_mod


def _seed_keys(state_dir, read_token, write_token):
    keys = []
    for token, scope in ((read_token, "read"), (write_token, "write")):
        keys.append({
            "id": scope,
            "key_hash": hashlib.sha256(token.encode()).hexdigest(),
            "description": scope,
            "scope": scope,
            "created_at": 0,
            "last_used_at": 0,
        })
    (state_dir / "api-keys.json").write_text(
        json.dumps({"keys": keys}), encoding="utf-8")


@pytest.fixture
def client():
    # Seed into the SAME STATE_DIR the app reads (frozen at config import time
    # by conftest's env vars), so _load_api_keys finds the keys.
    state_dir = cfg_mod.STATE_DIR
    read_token = "ktc_" + "a" * 64
    write_token = "ktc_" + "b" * 64
    _seed_keys(state_dir, read_token, write_token)

    from fastapi.testclient import TestClient
    app = a.create_app()
    with TestClient(app) as c:
        c.read_token = read_token
        c.write_token = write_token
        yield c


def test_no_key_is_401(client):
    r = client.get("/api/v1/domains")
    assert r.status_code == 401


def test_read_key_gets_read_route(client):
    r = client.get("/api/v1/domains",
                   headers={"Authorization": f"Bearer {client.read_token}"})
    assert r.status_code == 200
    assert "domains" in r.json()


def test_read_key_blocked_from_write_route(client):
    r = client.post("/api/v1/users",
                    headers={"Authorization": f"Bearer {client.read_token}"},
                    json={"email": "x@y.com", "password": "pw"})
    assert r.status_code == 403


def test_read_key_blocked_from_write_quarantine(client):
    r = client.post("/api/v1/quarantine/abc/release",
                    headers={"Authorization": f"Bearer {client.read_token}"},
                    json={"user": "x@y.com"})
    assert r.status_code == 403


def test_write_key_passes_write_scope_gate(client, monkeypatch):
    # Stub the backend so the route reaches a clean 201 (the scope gate is
    # what we're testing; the dovecot call is irrelevant here).
    import ktc_mail_admin.user_manager as um
    monkeypatch.setattr(um, "user_add", lambda *a, **k: 0)
    r = client.post("/api/v1/users",
                    headers={"Authorization": f"Bearer {client.write_token}"},
                    json={"email": "x@y.com", "password": "pw"})
    assert r.status_code == 201


def test_legacy_key_without_scope_is_write(monkeypatch):
    # A key stored before scope existed (no "scope" field) must act as write.
    import ktc_mail_admin.user_manager as um
    monkeypatch.setattr(um, "user_add", lambda *a, **k: 0)
    state_dir = cfg_mod.STATE_DIR
    legacy_token = "ktc_" + "c" * 64
    (state_dir / "api-keys.json").write_text(json.dumps({"keys": [{
        "id": "legacy", "key_hash": hashlib.sha256(legacy_token.encode()).hexdigest(),
        "description": "legacy", "created_at": 0, "last_used_at": 0}]}),
        encoding="utf-8")
    from fastapi.testclient import TestClient
    app = a.create_app()
    with TestClient(app) as c:
        r = c.post(
            "/api/v1/users",
            headers={"Authorization": f"Bearer {legacy_token}"},
            json={"email": "x@y.com", "password": "pw"})
        assert r.status_code == 201


def test_write_rate_limit_returns_429(monkeypatch):
    # A leaked write key must not loop-delete every mailbox. Enforce the
    # per-token write budget and return 429 once exceeded.
    import ktc_mail_admin.user_manager as um
    monkeypatch.setattr(um, "user_add", lambda *a, **k: 0)
    # Shrink the budget so the test stays fast (default is 60/60s).
    monkeypatch.setattr(a, "_API_WRITE_RATE_LIMIT", 3)
    token = "ktc_" + "z" * 64
    state_dir = cfg_mod.STATE_DIR
    (state_dir / "api-keys.json").write_text(json.dumps({"keys": [{
        "id": "w", "key_hash": hashlib.sha256(token.encode()).hexdigest(),
        "description": "write", "scope": "write",
        "created_at": 0, "last_used_at": 0}]}), encoding="utf-8")
    from fastapi.testclient import TestClient
    app = a.create_app()
    with TestClient(app) as c:
        hdr = {"Authorization": f"Bearer {token}"}
        codes = [c.post("/api/v1/users", headers=hdr,
                        json={"email": f"u{i}@y.com", "password": "pw"}).status_code
                 for i in range(5)]
        assert 429 in codes, f"expected 429 after budget; got {codes}"


def test_revoke_by_api_requires_write_key(client):
    # read key -> 403 (revoke is a write action)
    r = client.delete("/api/keys/write",
                      headers={"Authorization": f"Bearer {client.read_token}"})
    assert r.status_code == 403


def test_revoke_by_api_with_write_key(client):
    import ktc_mail_admin.user_manager as um  # noqa: F401 (keep import path warm)
    # Authenticate with the write key, revoke the read key (id "read").
    r = client.delete("/api/keys/read",
                      headers={"Authorization": f"Bearer {client.write_token}"})
    assert r.status_code == 200
    assert r.json()["status"] == "revoked"


def test_revoke_by_api_missing_key_404(client):
    r = client.delete("/api/keys/does-not-exist",
                      headers={"Authorization": f"Bearer {client.write_token}"})
    assert r.status_code == 404


def test_usage_updates_last_used_at_in_key_file(client):
    # A read-key GET should bump last_used_at for that key (under flock, in
    # the key file itself — no sidecar log).
    client.get("/api/v1/domains",
               headers={"Authorization": f"Bearer {client.read_token}"})
    import json as _json
    data = _json.loads((cfg_mod.STATE_DIR / "api-keys.json").read_text())
    read_key = next(k for k in data["keys"] if k["id"] == "read")
    assert read_key["last_used_at"] > 0, "last_used_at should be bumped on use"


def test_expired_key_is_rejected():
    # A key past its expires_at must be treated as invalid (403).
    import ktc_mail_admin.user_manager as um
    import json as _json
    um.user_add = lambda *a, **k: 0
    state_dir = cfg_mod.STATE_DIR
    expired_token = "ktc_" + "e" * 64
    (state_dir / "api-keys.json").write_text(_json.dumps({"keys": [{
        "id": "exp", "key_hash": __import__("hashlib").sha256(expired_token.encode()).hexdigest(),
        "description": "expired", "scope": "write", "expires_at": 1,
        "created_at": 0, "last_used_at": 0}]}), encoding="utf-8")
    from fastapi.testclient import TestClient
    app = a.create_app()
    with TestClient(app) as c:
        r = c.post("/api/v1/users",
                   headers={"Authorization": f"Bearer {expired_token}"},
                   json={"email": "x@y.com", "password": "pw"})
        assert r.status_code == 403


def test_openapi_requires_admin_session():
    # The schema discloses write endpoints; it must not be anonymously
    # reachable. Unauthenticated -> redirect to login (302, not followed).
    from fastapi.testclient import TestClient
    app = a.create_app()
    with TestClient(app) as c:
        r = c.get("/openapi.json", follow_redirects=False)
        assert r.status_code == 302, r.status_code
        assert "/login" in r.headers.get("location", "")


def test_api_v1_surface_is_tenant_scoped_only():
    # Lock the boundary contract: no /api/v1 route may touch global
    # server-infrastructure settings (those stay admin-panel-only).
    forbidden = {"transports", "dns", "tls", "firewall", "backup",
                 "acme", "settings", "setup", "options", "sieve", "routing"}
    from fastapi.testclient import TestClient
    app = a.create_app()
    with TestClient(app) as c:
        pass  # app already built; inspect routes
    for r in app.routes:
        p = getattr(r, "path", "")
        if not p.startswith("/api/v1"):
            continue
        seg = p[len("/api/v1"):].strip("/").split("/")[0]
        assert seg not in forbidden, f"API exposes infra setting: {p}"

