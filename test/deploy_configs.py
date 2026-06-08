#!/usr/bin/env python3
"""Render and deploy all mail configs from the test profile."""
import os

import sys
sys.path.insert(0, "/opt/ktc-mail/src")

from pathlib import Path
from ktc_mail_admin.config import read_json, SetupProfile
from ktc_mail_admin.config_renderer import render_all, write_all

data = read_json("/etc/ktc-mail/setup.json")
p = SetupProfile.from_dict(data)

# Write all configs
written = write_all(p, dest="/etc", dry_run=False)
print(f"deployed {len(written)} config files under /")

# Write MTA-STS
from ktc_mail_admin.config_renderer import render_mta_sts_policy
mta_sts_path = Path("/etc/nginx/mta-sts.txt")
mta_sts_path.parent.mkdir(parents=True, exist_ok=True)
fd = os.open(mta_sts_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
try:
    os.write(fd, render_mta_sts_policy(p).encode("utf-8"))
    os.fsync(fd)
finally:
    os.close(fd)
written["nginx/mta-sts.txt"] = mta_sts_path

for path in sorted(written.values()):
    print(f"  {path}")
