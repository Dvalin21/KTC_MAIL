"""P1-Slice-B: quarantine history parsing + release/confirm action logic.

These exercise the module-level helpers in admin_server.py. `parse_rspamc_history`
is the defensive JSON parser (rspamd history schema varies); the release/confirm
helpers are tested with monkeypatched subprocess so no real dovecot/rspamd is
needed.
"""
import subprocess
from unittest import mock

import ktc_mail_admin.admin_server as adm


SAMPLE_HISTORY = """
{
  "rows": [
    {
      "unix_time": 1700000000,
      "message-id": "<abc@mail>",
      "sender_smtp": "spammer@bad.example",
      "rcpt_smtp": ["alice@example.com"],
      "subject": "buy now",
      "score": 12.5,
      "action": "add header"
    },
    {
      "unix_time": 1700000001,
      "message-id": "<ham@mail>",
      "sender_smtp": "bob@good.example",
      "rcpt_smtp": ["alice@example.com"],
      "subject": "hello",
      "score": 1.0,
      "action": "no action"
    },
    {
      "unix_time": 1700000002,
      "message-id": "<rej@mail>",
      "sender_smtp": "x@bad.example",
      "rcpt_smtp": ["alice@example.com"],
      "subject": "phish",
      "score": 20.0,
      "action": "reject"
    }
  ]
}
"""


def test_parse_rspamc_history_filters_spam_only():
    rows = adm.parse_rspamc_history(SAMPLE_HISTORY)
    # only the "add header" row survives; no-action + reject are excluded
    assert len(rows) == 1
    r = rows[0]
    assert r["message_id"] == "<abc@mail>"
    assert r["from"] == "spammer@bad.example"
    assert r["to"] == "alice@example.com"
    assert r["subject"] == "buy now"
    assert r["score"] == 12.5
    assert r["action"] == "add header"


def test_parse_rspamc_history_empty_and_malformed():
    assert adm.parse_rspamc_history("") == []
    assert adm.parse_rspamc_history("not json") == []


def test_parse_rspamc_history_bare_list_shape():
    # older/alt rspamc may return a bare JSON array
    body = '[{"message-id":"<z@m>","sender_smtp":"s@e","rcpt_smtp":["u@e"],'
    body += '"subject":"x","score":9,"action":"rewrite subject","unix_time":1}]'
    rows = adm.parse_rspamc_history(body)
    assert len(rows) == 1
    assert rows[0]["action"] == "rewrite subject"


def test_parse_rspamc_history_alt_field_names():
    # tolerate message_id / from / rcpt variants
    body = '{"rows":[{"message_id":"<y@m>","from":"f@e","rcpt":["v@e"],'
    body += '"subject":"s","score":8,"action":"add header","time":7}]}'
    rows = adm.parse_rspamc_history(body)
    assert len(rows) == 1
    assert rows[0]["message_id"] == "<y@m>"
    assert rows[0]["from"] == "f@e"
    assert rows[0]["to"] == "v@e"


def test_rspamc_history_rows_unavailable_without_binary():
    # no rspamc on PATH in tests -> graceful empty list
    with mock.patch.object(adm.shutil, "which", return_value=None):
        assert adm.rspamc_history_rows() == []


def test_quarantine_release_moves_when_doveadm_present():
    with mock.patch.object(adm.shutil, "which", return_value="/usr/bin/doveadm"), \
         mock.patch.object(adm.subprocess, "run") as run:
        # first call (search) returns a uid line; second call (move) succeeds.
        run.side_effect = [
            subprocess.CompletedProcess([], 0, "1001 1\n", ""),
            subprocess.CompletedProcess([], 0, "", ""),
        ]
        res = adm.quarantine_release("<abc@mail>", "alice@example.com")
        assert res == {"moved": True}
        # move invoked with user + INBOX target
        move_cmd = run.call_args_list[1].args[0]
        assert move_cmd[:4] == ["/usr/bin/doveadm", "move", "-u", "alice@example.com"]
        assert "INBOX" in move_cmd


def test_quarantine_release_unavailable_without_doveadm():
    with mock.patch.object(adm.shutil, "which", return_value=None):
        assert adm.quarantine_release("<abc@mail>", "alice@example.com") == {"moved": False}


def test_quarantine_confirm_learns_when_present():
    with mock.patch.object(adm.shutil, "which", side_effect=lambda x: "/usr/bin/" + x), \
         mock.patch.object(adm.subprocess, "run") as run:
        run.side_effect = [
            subprocess.CompletedProcess([], 0, "full message bytes", ""),
            subprocess.CompletedProcess([], 0, "", ""),
        ]
        res = adm.quarantine_confirm("<abc@mail>", "alice@example.com")
        assert res == {"learned": True}
        learn_cmd = run.call_args_list[1].args[0]
        assert learn_cmd == ["/usr/bin/rspamc", "learn_spam"]
