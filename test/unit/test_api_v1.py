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

