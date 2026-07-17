"""KTC Mail — WebAuthn / FIDO2 security-key second factor (additive).

Per-admin passkeys (roaming authenticators such as YubiKeys, or platform
biometrics) are stored in ``/etc/ktc-mail/webauthn.json``. This module is an
**additive** second factor: TOTP (mfa.py) remains the primary MFA. An admin
who enrolls one or more security keys must also satisfy WebAuthn at login
when keys are present.

The third-party ``webauthn`` library (duo-labs/py_webauthn, BSD-3) is imported
**lazily** inside each ceremony function. This keeps the admin app bootable and
all other unit tests green even when the package is absent from the test env;
production installs it via ``pip install webauthn`` (see debian/postinst).

Challenges live only in the Starlette session (small, ~32 bytes) — never on
disk. Credential IDs and public keys are stored base64url-encoded.
"""

from __future__ import annotations

import base64
import glob
import json
import logging
import os
import sys
import time
from typing import Any

from .config import CONFIG_DIR, read_json, save_json_private

logger = logging.getLogger("ktc-mail.webauthn")

WEBAUTHN_PATH = CONFIG_DIR / "webauthn.json"
_RP_NAME = "KTC Mail"


def _ensure_webauthn_on_path() -> None:
    """Make the vendored WebAuthn venv importable without touching distro pkgs.

    debian/postinst installs ``webauthn`` (and its pinned cryptography chain)
    into an isolated venv at /opt/ktc-mail/webauthn-venv because webauthn 3.0.0
    requires cryptography>=49 while Debian trixie ships 43. We prepend that
    venv's site-packages to sys.path so the lazy ``from webauthn import ...``
    below resolves. No-op if already importable or venv absent.
    """
    try:
        import webauthn  # already available (venv, venv path, or dev env)
        return
    except ImportError:
        pass
    venv = "/opt/ktc-mail/webauthn-venv"
    if not os.path.isdir(venv):
        return
    sites = sorted(glob.glob(os.path.join(venv, "lib", "python3*", "site-packages")))
    for sp in sites:
        if sp not in sys.path:
            sys.path.insert(0, sp)


# ── base64url helpers ───────────────────────────────────────────────────────

def _b64url_encode(raw: bytes) -> str:
    """Encode bytes as unpadded base64url (matches the WebAuthn wire format)."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Decode an unpadded base64url string back to bytes."""
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


# ── Persistence ─────────────────────────────────────────────────────────────

def _load() -> dict[str, Any]:
    if not WEBAUTHN_PATH.exists():
        return {}
    try:
        return read_json(WEBAUTHN_PATH)
    except (OSError, ValueError):
        return {}


def _save(data: dict[str, Any]) -> None:
    WEBAUTHN_PATH.parent.mkdir(parents=True, exist_ok=True)
    save_json_private(WEBAUTHN_PATH, data)


def credentials_for(email: str) -> list[dict[str, Any]]:
    """Return the enrolled credentials list for *email* (empty if none)."""
    return _load().get(email, {}).get("credentials", [])


def has_credentials(email: str) -> bool:
    return bool(credentials_for(email))


def add_credential(
    email: str,
    cred_id_b64: str,
    public_key_b64: str,
    sign_count: int,
    name: str,
) -> None:
    """Store (or replace, by id) a credential for *email*."""
    data = _load()
    rec = data.setdefault(email, {"credentials": []})
    creds = rec.setdefault("credentials", [])
    old = next((c for c in creds if c.get("id") == cred_id_b64), None)
    entry = {
        "id": cred_id_b64,
        "public_key": public_key_b64,
        "sign_count": int(sign_count),
            "name": name or (old.get("name") if old else "Security key"),
            "created_at": (old or {}).get("created_at", int(time.time())),
    }
    creds[:] = [c for c in creds if c.get("id") != cred_id_b64]
    creds.append(entry)
    _save(data)


def remove_credential(email: str, cred_id_b64: str) -> bool:
    """Remove a credential by id. Returns True if something was removed."""
    data = _load()
    rec = data.get(email)
    if not rec:
        return False
    before = len(rec.get("credentials", []))
    rec["credentials"] = [
        c for c in rec.get("credentials", []) if c.get("id") != cred_id_b64
    ]
    if len(rec["credentials"]) == before:
        return False
    if not rec["credentials"]:
        data.pop(email, None)
    _save(data)
    return True


def rp_config(request: Any) -> tuple[str, str, str]:
    """Return (rp_id, rp_name, origin) derived from the request URL.

    rp_id is the bare host — WebAuthn requires it to be a registrable-domain
    suffix of the origin host. origin is exactly scheme://netloc as the
    browser reports it in clientDataJSON.
    """
    url = request.url
    rp_id = url.hostname or "localhost"
    origin = f"{url.scheme}://{url.netloc}"
    return rp_id, _RP_NAME, origin


# ── Registration ceremony (enrollment) ─────────────────────────────────────

def begin_registration(request: Any, email: str) -> dict[str, Any]:
    """Generate registration options (JSON-ready dict); stash challenge in session."""
    try:
        _ensure_webauthn_on_path()
        from webauthn import (
            generate_registration_options,
            options_to_json,
            bytes_to_base64url,
        )
        from webauthn.helpers.structs import PublicKeyCredentialDescriptor
    except ImportError as exc:  # pragma: no cover - prod always has the lib
        raise RuntimeError("webauthn library not installed") from exc

    rp_id, rp_name, _origin = rp_config(request)
    existing = credentials_for(email)
    exclude = [
        PublicKeyCredentialDescriptor(id=_b64url_decode(c["id"])) for c in existing
    ]
    opts = generate_registration_options(
        rp_id=rp_id,
        rp_name=rp_name,
        user_id=email.encode("utf-8"),
        user_name=email,
        user_display_name=email,
        exclude_credentials=exclude,
    )
    request.session["wa_register_challenge"] = bytes_to_base64url(opts.challenge)
    return json.loads(options_to_json(opts))


def finish_registration(
    request: Any, email: str, response: dict[str, Any]
) -> tuple[bool, str]:
    """Verify an attestation response and persist the credential.

    Returns ``(ok, error_message)``. On success the credential is stored.
    """
    try:
        _ensure_webauthn_on_path()
        from webauthn import verify_registration_response, base64url_to_bytes
    except ImportError:  # pragma: no cover
        return False, "webauthn library not installed"

    rp_id, _rp_name, origin = rp_config(request)
    challenge_b64 = request.session.get("wa_register_challenge")
    if not challenge_b64:
        return False, "No registration in progress"
    expected_challenge = base64url_to_bytes(challenge_b64)
    try:
        verification = verify_registration_response(
            credential=response,
            expected_challenge=expected_challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
            require_user_verification=False,
        )
    except Exception as exc:  # webauthn raises on any validation failure
        logger.warning("webauthn registration failed for %s: %s", email, exc)
        return False, "Registration verification failed"
    add_credential(
        email,
        _b64url_encode(verification.credential_id),
        _b64url_encode(verification.credential_public_key),
        verification.sign_count,
        str(response.get("name", "")),
    )
    request.session.pop("wa_register_challenge", None)
    return True, ""


# ── Authentication ceremony (login) ─────────────────────────────────────────

def begin_authentication(request: Any, email: str) -> dict[str, Any]:
    """Generate authentication options; stash challenge+email in session."""
    try:
        _ensure_webauthn_on_path()
        from webauthn import (
            generate_authentication_options,
            options_to_json,
            bytes_to_base64url,
        )
        from webauthn.helpers.structs import PublicKeyCredentialDescriptor
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("webauthn library not installed") from exc

    rp_id, _rp_name, _origin = rp_config(request)
    allow = [
        PublicKeyCredentialDescriptor(id=_b64url_decode(c["id"]))
        for c in credentials_for(email)
    ]
    opts = generate_authentication_options(rp_id=rp_id, allow_credentials=allow)
    request.session["wa_auth_challenge"] = bytes_to_base64url(opts.challenge)
    request.session["wa_auth_email"] = email
    return json.loads(options_to_json(opts))


def verify_authentication(
    request: Any, email: str, response: dict[str, Any]
) -> tuple[bool, str]:
    """Verify an assertion and advance the stored sign count.

    Returns ``(ok, error_message)``.
    """
    try:
        _ensure_webauthn_on_path()
        from webauthn import verify_authentication_response, base64url_to_bytes
    except ImportError:  # pragma: no cover
        return False, "webauthn library not installed"

    rp_id, _rp_name, origin = rp_config(request)
    challenge_b64 = request.session.get("wa_auth_challenge")
    if not challenge_b64:
        return False, "No authentication in progress"
    expected_challenge = base64url_to_bytes(challenge_b64)

    cred_id = response.get("id") or response.get("rawId") or ""
    match = next(
        (c for c in credentials_for(email) if c.get("id") == cred_id), None
    )
    if match is None:
        return False, "Unknown credential"

    try:
        verification = verify_authentication_response(
            credential=response,
            expected_challenge=expected_challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=_b64url_decode(match["public_key"]),
            credential_current_sign_count=int(match["sign_count"]),
            require_user_verification=False,
        )
    except Exception as exc:  # webauthn raises on any validation failure
        logger.warning("webauthn authentication failed for %s: %s", email, exc)
        return False, "Authentication verification failed"

    # Persist the new sign count (replay protection).
    add_credential(
        email,
        match["id"],
        match["public_key"],
        verification.new_sign_count,
        match.get("name", "Security key"),
    )
    request.session.pop("wa_auth_challenge", None)
    request.session.pop("wa_auth_email", None)
    return True, ""
