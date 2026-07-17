"""P2-Slice-1: dependency-free IMAP migration (imaplib).

Tests the pure parsing + orchestration logic with a mocked IMAP4 connection
so no real mail server is needed.
"""
import json
from unittest import mock

import ktc_mail_admin.imap_migrate as mig
import imaplib


def _conn() -> mock.MagicMock:
    return mock.MagicMock(spec=imaplib.IMAP4)


def test_list_mailboxes_skips_noselect():
    c = _conn()
    c.list.return_value = ("OK", [
        b'(\\HasNoChildren) "/" "INBOX"',
        b'(\\Noselect \\HasChildren) "/" "Trash"',
        b'(\\HasNoChildren) "/" "Sent"',
    ])
    assert mig._list_mailboxes(c) == ["INBOX", "Sent"]


def test_uids_parses():
    c = _conn()
    c.select.return_value = ("OK", [])
    c.uid.return_value = ("OK", [b"1 2 3"])
    assert mig._uids(c, "INBOX") == [1, 2, 3]


def test_uids_empty_on_missing():
    c = _conn()
    c.select.return_value = ("NO", [])
    assert mig._uids(c, "NOPE") == []


def test_migrate_mailbox_copies_missing():
    src = _conn()
    dst = _conn()
    src.select.return_value = ("OK", [])
    src.uid.side_effect = [
        ("OK", [b"1 2"]),
        ("OK", [(b"1 (FLAGS (\\Seen) INTERNALDATE \"16-Jul-2026 10:00:00 +0000\")",
                 b"MSG1")]),
        ("OK", [(b"2 (FLAGS () INTERNALDATE \"16-Jul-2026 11:00:00 +0000\")",
                 b"MSG2")]),
    ]
    dst.select.return_value = ("OK", [])
    copied: set[int] = set()
    n, _ = mig.migrate_mailbox(src, dst, "INBOX", copied)
    assert n == 2
    assert copied == {1, 2}
    assert dst.append.call_count == 2


def test_migrate_mailbox_creates_missing_dst():
    src = _conn()
    dst = _conn()
    src.select.return_value = ("OK", [])
    src.uid.side_effect = [
        ("OK", [b"1"]),
        ("OK", [(b"1 (FLAGS () INTERNALDATE \"16-Jul-2026 10:00:00 +0000\")",
                 b"MSG1")]),
    ]
    dst.select.return_value = ("NO", [])  # mailbox absent on dst
    copied: set[int] = set()
    n, _ = mig.migrate_mailbox(src, dst, "Archive", copied)
    assert n == 1
    dst.create.assert_called_once_with("Archive")
    dst.append.assert_called_once()


def test_run_migration_dry_run():
    args = mock.MagicMock()
    args.dry_run = True
    args.src_user = "a@x"
    args.src_host = "h"
    args.dst_user = "a@y"
    args.dst_host = "127.0.0.1"
    args.state = None
    assert mig.run_migration(args) == 0


def test_run_migration_copies_and_writes_state(tmp_path):
    args = mock.MagicMock()
    args.dry_run = False
    args.src_user = "a@x"
    args.src_host = "h"
    args.src_password = "p"
    args.src_port = None
    args.src_ssl = True
    args.src_starttls = False
    args.dst_user = "a@y"
    args.dst_host = "127.0.0.1"
    args.dst_password = "q"
    args.dst_port = None
    args.dst_ssl = True
    args.dst_starttls = False
    args.state = str(tmp_path / "state.json")

    src = _conn()
    dst = _conn()
    src.list.return_value = ("OK", [b'(\\HasNoChildren) "/" "INBOX"'])
    src.select.return_value = ("OK", [])
    src.uid.side_effect = [
        ("OK", [b"1"]),
        ("OK", [(b"1 (FLAGS (\\Seen) INTERNALDATE \"16-Jul-2026 10:00:00 +0000\")",
                 b"MSG1")]),
    ]
    dst.select.return_value = ("OK", [])

    with mock.patch.object(mig, "_open", side_effect=[src, dst]):
        rc = mig.run_migration(args)
    assert rc == 0
    assert dst.append.called
    assert (tmp_path / "state.json").exists()
    st = json.loads((tmp_path / "state.json").read_text())
    assert st.get("INBOX") == [1]
