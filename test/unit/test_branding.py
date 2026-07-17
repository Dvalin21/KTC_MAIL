"""Branding model + persistence — config boundary for the web UI."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from ktc_mail_admin.config import (
    Branding,
    SetupProfile,
    load_profile,
    save_branding,
    save_profile,
)


def test_validate_accepts_empty_and_valid_hex():
    Branding().validate()                              # all blank is fine
    Branding(accent="#5b67f1").validate()             # 6-digit hex
    Branding(accent="#fff").validate()                # 3-digit hex


def test_validate_rejects_unsafe_accent(tmp_path):
    import pytest
    for bad in ("red", "#zzz", "red;background:url(x)", "#12345"):
        with pytest.raises(ValueError):
            Branding(accent=bad).validate()


def test_validate_rejects_overlong_fields(tmp_path):
    import pytest
    with pytest.raises(ValueError):
        Branding(org_name="x" * 41).validate()
    with pytest.raises(ValueError):
        Branding(logo_url="https://x.com/" + "a" * 300).validate()


def test_save_branding_roundtrip(tmp_path):
    setup = tmp_path / "setup.json"
    save_profile(SetupProfile(admin_email="a@b.com", domain="b.com"), setup)
    b = Branding(org_name="Acme", accent="#8b5cf6", logo_url="https://x/y.png")
    save_branding(b, setup)
    reloaded = load_profile(setup)
    assert reloaded.branding.org_name == "Acme"
    assert reloaded.branding.accent == "#8b5cf6"
    assert reloaded.branding.effective_accent() == "#8b5cf6"


def test_effective_accent_falls_back_on_bad_value(tmp_path):
    b = Branding(accent="not-a-colour")
    assert b.effective_accent() == "#5b67f1"
