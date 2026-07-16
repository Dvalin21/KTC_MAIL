"""Contract tests for the Phase3 config renderers.

These prove the renderers emit well-formed, internally-consistent
config without a real mail server (Phase3 exit criteria demand
integration tests; these are the headless half — the part that
can run in CI without a VM). Each renderer output is asserted
for the invariants the consuming daemon actually parses.

Run: pytest from repo root (pyproject.toml sets pythonpath=src).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ktc_mail_admin.config import SetupProfile, SecurityPolicy
from ktc_mail_admin import config_renderer as cr


def _profile() -> SetupProfile:
    return SetupProfile(
        domain="example.com",
        dns_api_token="",
        admin_email="admin@example.com",
        public_ipv4="203.0.113.10",
        public_ipv6="2001:db8::10",
        dns_provider="cloudflare",
        has_ipv6=True,
        certificate_mode="dns-01",
        security=SecurityPolicy(),
    )


def test_postfix_main_cf_invariants():
    out = cr.render_postfix_main_cf(_profile())
    assert "smtpd_tls_security_level = may" in out
    assert "smtpd_sasl_type = dovecot" in out
    assert "smtpd_milters = inet:localhost:11332" in out  # rspamd inline
    # relay control must be present or Postfix 3.7+ refuses to start
    assert "smtpd_relay_restrictions" in out
    assert "reject_unauth_destination" in out
    # no leftover placeholder / unbalanced braces
    assert "{CERT_NAME}" not in out


def test_postfix_master_cf_services():
    out = cr.render_postfix_master_cf(_profile())
    for svc in ("smtp", "submission", "smtps", "postscreen", "dovecot"):
        assert svc in out
    assert "smtpd_tls_wrappermode=yes" in out  # 465 implicit TLS


def test_dovecot_conf_invariants():
    out = cr.render_dovecot_conf(_profile())
    assert "ssl = required" in out
    assert "protocols = imap lmtp sieve" in out
    assert "ssl_cert = </etc/letsencrypt/live/ktc-mail/fullchain.pem" in out
    assert "mail_location = maildir:/var/mail/%d/%" in out


def test_rspamd_local_dkim():
    out = cr.render_rspamd_local_conf(_profile())
    assert "dkim" in out
    assert "sign_alg = rsa-sha256" in out
    assert "selector = \"default\"" in out


def test_sogo_conf_wires_db_password():
    out = cr.render_sogo_conf(_profile())
    assert "SOGoMailDomain = \"example.com\"" in out
    assert "SOGoEnableWebAccess = YES" in out
    # must pull the secret from secrets.json, never inline a literal
    assert "sogo:" in out and "localhost:5432" in out


def test_nginx_webmail_vhost():
    out = cr.render_nginx_webmail_vhost(_profile())
    # properties: hostname=mail, webmail_host=email, admin_host=admin
    assert "server_name mail.example.com email.example.com admin.example.com" in out
    assert "proxy_pass" in out  # SOGo FastCGI upstream
    assert "listen 443 ssl" in out


def test_all_renderers_run_without_exception():
    p = _profile()
    for fn in (
        cr.render_postfix_main_cf,
        cr.render_postfix_master_cf,
        cr.render_dovecot_conf,
        cr.render_rspamd_worker_conf,
        cr.render_rspamd_controller_conf,
        cr.render_rspamd_local_conf,
        cr.render_rspamd_dkim_signing_conf,
        cr.render_sogo_conf,
        cr.render_nginx_webmail_vhost,
    ):
        assert isinstance(fn(p), str)


def _multi_profile() -> SetupProfile:
    p = _profile()
    p.domains = ["alias1.example.com", "alias2.example.com"]
    return p


def test_multi_domain_virtual_mailbox_domains():
    out = cr.render_postfix_main_cf(_multi_profile())
    assert (
        "virtual_mailbox_domains = example.com, alias1.example.com, alias2.example.com"
        in out
    )


def test_multi_domain_back_compat_single():
    out = cr.render_postfix_main_cf(_profile())
    assert "virtual_mailbox_domains = example.com" in out


def test_multi_domain_nginx_alias_comments():
    out = cr.render_nginx_webmail_vhost(_multi_profile())
    assert "alias: alias1.example.com" in out
    assert "alias: alias2.example.com" in out


def test_mailbox_store_sql_is_wired():
    p = _profile()
    p.mailbox_store = "sql"
    out = cr.render_dovecot_conf(p)
    # SQL store is now actually wired (no fail-honest warning)
    assert "driver = sql" in out
    assert "dovecot-sql.conf.ext" in out
    assert "mail_location = maildir:/var/mail/%d/%n" in out


def test_all_domains_dedupes():
    p = SetupProfile(domain="example.com", domains=["example.com", "b.com"])
    assert p.all_domains == ["example.com", "b.com"]

