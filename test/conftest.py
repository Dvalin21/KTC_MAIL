"""Test session setup.

Point KTC_MAIL_CONFIG_DIR / KTC_MAIL_STATE_DIR at a temp location BEFORE the
first import of ktc_mail_admin.config, so create_app() (used by API tests)
does not try to mkdir /etc/ktc-mail. Loaded by pytest ahead of any test module.
"""

import tempfile
from pathlib import Path

_TMP = Path(tempfile.mkdtemp(prefix="ktc-test-"))
CFG = _TMP / "cfg"
STATE = _TMP / "state"
CFG.mkdir(parents=True, exist_ok=True)
STATE.mkdir(parents=True, exist_ok=True)

import os

os.environ["KTC_MAIL_CONFIG_DIR"] = str(CFG)
os.environ["KTC_MAIL_STATE_DIR"] = str(STATE)
os.environ["KTC_DEV"] = "1"
