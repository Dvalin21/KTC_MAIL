#!/usr/bin/env python3
"""Create a synthetic test profile for container validation."""
import sys
sys.path.insert(0, "/opt/ktc-mail/src")

from ktc_mail_admin.config import SetupProfile, save_json_private

p = SetupProfile(
    domain="test.example.com",
    admin_email="admin@test.example.com",
    public_ipv4="203.0.113.10",
    public_ipv6="2001:db8::1",
    has_ipv6=True,
)
save_json_private("/etc/ktc-mail/setup.json", p.to_dict())
print(f"test profile created: {p.domain}")
