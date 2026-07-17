"""P1-Slice-C: end-user self-service logic.

Covers the two reusable primitives: `build_spam_policy_ucl` (the rspamd
setting:user: override string, shared with the admin spam-policy route) and
`mailbox_auth` (Dovecot-backed login). Route wiring reuses the established
admin auth/CSRF patterns and is covered by import + the VM deploy.
"""
import subprocess
from unittest import mock

import ktc_mail_admin.admin_server as adm


def test_build_spam_policy_ucl_basic():
    assert adm.build_spam_policy_ucl(15.0, 6.0) == '{actions{reject=15.0;"add header"=6.0;}}'


def test_build_spam_policy_ucl_with_greylist():
    assert adm.build_spam_policy_ucl(15.0, 6.0, 4.0) == \
        '{actions{reject=15.0;"add header"=6.0;greylist=4.0;}}'


def test_build_spam_policy_ucl_omits_greylist_when_none():
    assert "greylist" not in adm.build_spam_policy_ucl(15.0, 6.0, None)


def test_mailbox_auth_success():
    with mock.patch.object(adm.shutil, "which", return_value="/usr/bin/doveadm"), \
         mock.patch.object(adm.subprocess, "run") as run:
        run.return_value = subprocess.CompletedProcess([], 0, "pass", "")
        assert adm.mailbox_auth("alice@example.com", "pw") is True


def test_mailbox_auth_failure():
    with mock.patch.object(adm.shutil, "which", return_value="/usr/bin/doveadm"), \
         mock.patch.object(adm.subprocess, "run") as run:
        run.return_value = subprocess.CompletedProcess([], 1, "fail", "")
        assert adm.mailbox_auth("alice@example.com", "bad") is False


def test_mailbox_auth_no_doveadm():
    with mock.patch.object(adm.shutil, "which", return_value=None):
        assert adm.mailbox_auth("alice@example.com", "pw") is False
