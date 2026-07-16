#!/usr/bin/env python3
"""Unit tests for the multi-domain SQL mailbox store (C)."""

from __future__ import annotations

import pytest

from ktc_mail_admin import config, config_renderer, user_manager
from ktc_mail_admin.config import SetupProfile


# ── Renderer: dovecot-sql.conf.ext ───────────────────────────────────────

@pytest.fixture
def sql_profile():
    return SetupProfile(domain="example.com", mailbox_store="sql")


def test_render_dovecot_sql_conf(sql_profile, monkeypatch):
    monkeypatch.setattr(config_renderer, "get_mailbox_db_password", lambda: "testpw")
    out = config_renderer.render_dovecot_sql_conf(sql_profile)
    assert "driver = sql" in out
    assert "dbname=ktc_mail user=ktc_mail password=testpw" in out
    assert "SELECT email AS user, password_hash AS password" in out
    assert "SELECT maildir AS mail" in out
    assert "'*:storage=' || quota" in out


def test_passdb_sql_branch(sql_profile):
    out = config_renderer._dovecot_passdb(sql_profile)
    assert "driver = sql" in out
    assert "dovecot-sql.conf.ext" in out


def test_userdb_sql_branch(sql_profile):
    out = config_renderer._dovecot_userdb(sql_profile)
    assert "driver = sql" in out


def test_dovecot_conf_sql_no_warning(sql_profile):
    out = config_renderer.render_dovecot_conf(sql_profile)
    assert "dovecot-sql.conf.ext" in out
    assert "mail_location = maildir:/var/mail/%d/%n" in out
    # The old "fail-honest" warning must be gone.
    assert "NOT auto-configured" not in out
    assert "Falling back to maildir" not in out


def test_dovecot_conf_maildir_static():
    p = SetupProfile(domain="example.com", mailbox_store="maildir")
    out = config_renderer.render_dovecot_conf(p)
    assert "driver = sql" not in out
    assert "driver = passwd-file" in out
    assert "driver = static" in out
    assert "home=/var/mail/%d/%n" in out


def test_render_all_includes_sql_conf(sql_profile):
    rendered = config_renderer.render_all(sql_profile)
    assert "dovecot/dovecot-sql.conf.ext" in rendered
    assert "driver = sql" in rendered["dovecot/dovecot-sql.conf.ext"]


def test_render_all_excludes_sql_conf_for_maildir():
    p = SetupProfile(domain="example.com", mailbox_store="maildir")
    rendered = config_renderer.render_all(p)
    assert "dovecot/dovecot-sql.conf.ext" not in rendered


def test_schema_has_tables():
    sql = config_renderer.MAILBOX_SCHEMA_SQL
    assert "CREATE TABLE IF NOT EXISTS mailboxes" in sql
    assert "CREATE TABLE IF NOT EXISTS domains" in sql
    assert "password_hash" in sql
    assert "maildir" in sql


# ── Config validation ────────────────────────────────────────────────────

def test_from_dict_rejects_bad_mailbox_store():
    with pytest.raises(config.ValidationError):
        SetupProfile.from_dict({"domain": "example.com", "mailbox_store": "bogus"})


def test_from_dict_accepts_sql():
    p = SetupProfile.from_dict({"domain": "example.com", "mailbox_store": "sql"})
    assert p.mailbox_store == "sql"


# ── user_manager SQL path (no live DB; FakeConn captures queries) ────────

class _FakeCursor:
    def __init__(self):
        self.executed = []
        self._rows = []

    def execute(self, query, params=()):
        self.executed.append((query, params))

    def fetchall(self):
        return self._rows

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _FakeConn:
    def __init__(self):
        self._cur = _FakeCursor()

    def cursor(self):
        return self._cur

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def close(self):
        pass


@pytest.fixture
def fake_conn(monkeypatch):
    fc = _FakeConn()
    monkeypatch.setattr(user_manager, "_mailbox_db_conn", lambda: fc)
    return fc


def test_sql_user_add_query(fake_conn):
    rc = user_manager._sql_user_add("alice@example.com", "HASH", "2G")
    assert rc == 0
    q, params = fake_conn._cur.executed[0]
    assert "INSERT INTO mailboxes" in q
    assert params == ("alice@example.com", "example.com", "HASH",
                      "/var/mail/example.com/alice", "2G")


def test_sql_user_delete_query(fake_conn):
    user_manager._sql_user_delete("bob@example.com")
    q, params = fake_conn._cur.executed[0]
    assert "DELETE FROM mailboxes" in q
    assert params == ("bob@example.com",)


def test_sql_user_passwd_query(fake_conn):
    user_manager._sql_user_passwd("bob@example.com", "NEWHASH")
    q, params = fake_conn._cur.executed[0]
    assert "UPDATE mailboxes SET password_hash" in q
    assert params == ("NEWHASH", "bob@example.com")


def test_sql_user_list_query(fake_conn):
    fake_conn._cur._rows = [("a@example.com", "1G")]
    assert user_manager._sql_user_list() == [("a@example.com", "1G")]


def test_sql_exists_true(monkeypatch):
    fc = _FakeConn()
    fc._cur._rows = [(1,)]
    monkeypatch.setattr(user_manager, "_mailbox_db_conn", lambda: fc)
    assert user_manager._sql_exists("a@example.com") is True


def test_sql_exists_false(monkeypatch):
    fc = _FakeConn()
    fc._cur._rows = []
    monkeypatch.setattr(user_manager, "_mailbox_db_conn", lambda: fc)
    assert user_manager._sql_exists("a@example.com") is False
