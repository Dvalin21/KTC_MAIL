"""Unit tests for the WebAuthn / security-key second factor.

The third-party ``webauthn`` library is NOT required to run these tests: it is
mocked and injected into sys.modules. This keeps the suite hermetic and fast,
and matches how the module lazy-imports the lib at call time.
"""

import base64
import json
import sys
import types

import pytest

from ktc_mail_admin import webauthn_mgr as wa


class FakeURL:
    hostname = "admin.example.com"
    scheme = "https"
    netloc = "admin.example.com"


class FakeRequest:
    def __init__(self):
        self.session = {}
        self.url = FakeURL()


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64d(s: str) -> bytes:
    s = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


@pytest.fixture
def fake_wa(monkeypatch, tmp_path):
    """Inject a mock ``webauthn`` library and a temp credential store."""
    monkeypatch.setattr(wa, "WEBAUTHN_PATH", tmp_path / "webauthn.json")

    fake = types.ModuleType("webauthn")
    sub = types.ModuleType("webauthn.helpers.structs")

    class Descriptor:
        def __init__(self, id):
            self.id = id

    sub.PublicKeyCredentialDescriptor = Descriptor
    fake.PublicKeyCredentialDescriptor = Descriptor

    class _Opts:
        def __init__(self, challenge):
            self.challenge = challenge

    def gen_reg(**_kw):
        return _Opts(b"reg-challenge-bytes")

    def gen_auth(**_kw):
        return _Opts(b"auth-challenge-bytes")

    def to_json(o):
        return json.dumps({
            "challenge": _b64u(o.challenge),
            "rp": {"id": "admin.example.com"},
            "user": {"id": _b64u(b"admin@example.com")},
            "excludeCredentials": [],
            "allowCredentials": [],
        })

    class VReg:
        credential_id = b"cid-bytes"
        credential_public_key = b"cpk-bytes"
        sign_count = 0

    class VAuth:
        credential_id = b"cid-bytes"
        new_sign_count = 7

    def ver_reg(credential, expected_challenge, expected_rp_id,
                expected_origin, require_user_verification=False):
        return VReg()

    def ver_auth(credential, expected_challenge, expected_rp_id,
                 expected_origin, credential_public_key,
                 credential_current_sign_count, require_user_verification=False):
        return VAuth()

    fake.generate_registration_options = gen_reg
    fake.generate_authentication_options = gen_auth
    fake.options_to_json = to_json
    fake.verify_registration_response = ver_reg
    fake.verify_authentication_response = ver_auth
    fake.base64url_to_bytes = _b64d
    fake.bytes_to_base64url = _b64u

    monkeypatch.setitem(sys.modules, "webauthn", fake)
    monkeypatch.setitem(sys.modules, "webauthn.helpers", types.ModuleType("webauthn.helpers"))
    monkeypatch.setitem(sys.modules, "webauthn.helpers.structs", sub)
    return fake


# ── Persistence ─────────────────────────────────────────────────────────────

def test_credential_lifecycle(tmp_path, monkeypatch):
    monkeypatch.setattr(wa, "WEBAUTHN_PATH", tmp_path / "webauthn.json")
    assert not wa.has_credentials("a@b.com")
    wa.add_credential("a@b.com", "cid1", "cpk1", 0, "YK")
    assert wa.has_credentials("a@b.com")
    creds = wa.credentials_for("a@b.com")
    assert len(creds) == 1 and creds[0]["name"] == "YK"
    # Replace by id preserves created_at / name.
    wa.add_credential("a@b.com", "cid1", "cpk1", 3, "YK renamed")
    assert len(wa.credentials_for("a@b.com")) == 1
    assert wa.credentials_for("a@b.com")[0]["sign_count"] == 3
    assert wa.remove_credential("a@b.com", "cid1")
    assert not wa.has_credentials("a@b.com")
    assert not wa.remove_credential("a@b.com", "cid1")  # already gone


# ── Registration ceremony ────────────────────────────────────────────────────

def test_begin_registration_stores_challenge(fake_wa):
    req = FakeRequest()
    opts = wa.begin_registration(req, "admin@example.com")
    assert "challenge" in opts
    assert req.session["wa_register_challenge"]


def test_finish_registration_stores_credential(fake_wa):
    req = FakeRequest()
    req.session["wa_register_challenge"] = _b64u(b"reg-challenge-bytes")
    ok, err = wa.finish_registration(
        req, "admin@example.com",
        {"id": "x", "rawId": "x", "response": {}, "type": "public-key",
         "name": "YK"},
    )
    assert ok, err
    creds = wa.credentials_for("admin@example.com")
    assert len(creds) == 1
    assert creds[0]["name"] == "YK"
    assert creds[0]["id"] == _b64u(b"cid-bytes")


def test_finish_registration_no_challenge(fake_wa):
    req = FakeRequest()
    ok, err = wa.finish_registration(req, "admin@example.com", {"id": "x"})
    assert not ok and "No registration" in err


# ── Authentication ceremony ──────────────────────────────────────────────────

def test_begin_authentication_stores_challenge(fake_wa):
    req = FakeRequest()
    wa.add_credential("admin@example.com", _b64u(b"cid-bytes"), _b64u(b"cpk-bytes"), 0, "YK")
    opts = wa.begin_authentication(req, "admin@example.com")
    assert "challenge" in opts
    assert req.session["wa_auth_challenge"]
    assert req.session["wa_auth_email"] == "admin@example.com"


def test_verify_authentication_advances_sign_count(fake_wa):
    req = FakeRequest()
    wa.add_credential("admin@example.com", _b64u(b"cid-bytes"), _b64u(b"cpk-bytes"), 0, "YK")
    req.session["wa_auth_challenge"] = _b64u(b"auth-challenge-bytes")
    ok, err = wa.verify_authentication(
        req, "admin@example.com",
        {"id": _b64u(b"cid-bytes"), "rawId": _b64u(b"cid-bytes"),
         "response": {}, "type": "public-key"},
    )
    assert ok, err
    # Stored sign count advanced to the mock's new_sign_count (7).
    assert wa.credentials_for("admin@example.com")[0]["sign_count"] == 7


def test_verify_authentication_unknown_credential(fake_wa):
    req = FakeRequest()
    wa.add_credential("admin@example.com", _b64u(b"cid-bytes"), _b64u(b"cpk-bytes"), 0, "YK")
    req.session["wa_auth_challenge"] = _b64u(b"auth-challenge-bytes")
    ok, err = wa.verify_authentication(
        req, "admin@example.com",
        {"id": _b64u(b"other"), "response": {}, "type": "public-key"},
    )
    assert not ok and "Unknown credential" in err


def test_verify_authentication_no_challenge(fake_wa):
    req = FakeRequest()
    ok, err = wa.verify_authentication(req, "admin@example.com", {"id": "x"})
    assert not ok and "No authentication" in err


# ── rp_config derivation ─────────────────────────────────────────────────────

def test_rp_config_derivation():
    rp_id, rp_name, origin = wa.rp_config(FakeRequest())
    assert rp_id == "admin.example.com"
    assert rp_name == "KTC Mail"
    assert origin == "https://admin.example.com"
