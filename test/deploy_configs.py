#!/usr/bin/env python3
"""Render and deploy all mail configs from the test profile."""
import sys
sys.path.insert(0, "/opt/ktc-mail/src")

from ktc_mail_admin.config import read_json, SetupProfile
from ktc_mail_admin.config_renderer import render_all, write_all

data = read_json("/etc/ktc-mail/setup.json")
p = SetupProfile.from_dict(data)

# Write all configs
written = write_all(p, dest="/etc", dry_run=False)
print(f"deployed {len(written)} config files under /")

# Write MTA-STS
from ktc_mail_admin.config_renderer import render_mta_sts_policy
mta_sts = render_mta_sts_policy(p)
Path = __import__("pathlib").Path
sts_path = Path("/etc/nginx/mta-sts.txt")
sts_path.parent.mkdir(parents=True, exist_ok=True)
sts_path.write_text(mta_sts, encoding="utf-8")
written["nginx/mta-sts.txt"] = sts_path

for path in sorted(written.values()):
    print(f"  {path}")
