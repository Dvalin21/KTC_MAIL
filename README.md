# KTC Mail

KTC Mail is a bare-metal Debian/Ubuntu mail server suite scaffold. The goal is a Mailcow-style operational structure without Docker: mature open-source mail components, a friendly web GUI, guided DNS/TLS setup, and strict firewall/security defaults.

## Current scope

This repository now contains the first implementation slice:

- A standard-library Python first-run web GUI that launches on the server IP and collects domain, hostname, public IPs, DNS provider, administrator email, and certificate mode.
- DNS plan generation and first-pass automation for A, AAAA, MX, SPF, DKIM, DMARC, TLS-RPT, optional DANE TLSA, split admin/SOGo hostnames, and autodiscovery SRV records.
- A conservative iptables/ip6tables firewall monitor that reads the setup profile so DNS-01 keeps port 80 closed unless HTTP-01 is selected.
- Debian packaging metadata that installs the GUI, firewall monitor, helper scripts, examples, documentation, and systemd units.
- ACME issue/renew tooling with DNS-01 hooks, HTTP-01 fallback, TLSA regeneration, and service reload hooks.
- A bootstrap script that installs the proven open-source stack: Postfix, Dovecot, Rspamd, Redis, Fail2ban, Nginx, certbot, iptables, and supporting tools.

## Target production stack

| Layer | Tooling |
| --- | --- |
| SMTP | Postfix with postscreen, Rspamd milter, strict TLS, submission on 587 |
| IMAP and delivery | Dovecot IMAPS, LMTP, Sieve, ManageSieve as optional |
| Spam/security policy | Rspamd, Redis, Fail2ban, optional CrowdSec |
| Admin GUI | KTC Mail Python service, later hardened behind HTTPS and MFA |
| TLS | ACME DNS-01 provider APIs, service reload hooks, optional DANE TLSA updates |
| Firewall | iptables/ip6tables monitor now; nftables should be evaluated as the future primary backend |
| Packaging | `.deb` for Debian/Ubuntu bare-metal installation |

## Quick developer checks

```bash
python3 -m py_compile src/ktc_mail_admin/app.py src/ktc_mail_admin/firewall_monitor.py src/ktc_mail_admin/dns_provider.py src/ktc_mail_admin/acme_manager.py
bash -n scripts/bootstrap-mail-stack.sh scripts/ktc-mail-open-ports.sh packaging/debian/postinst packaging/debian/prerm
```

## Prototype run

```bash
KTC_MAIL_CONFIG_DIR=/tmp/ktc-mail/etc KTC_MAIL_STATE_DIR=/tmp/ktc-mail/state \
  python3 src/ktc_mail_admin/app.py --host 127.0.0.1 --port 8080
```

Then open `http://127.0.0.1:8080` and submit the initial domain setup form.

## What you are missing before production

- DNS provider adapter implementation and token scope requirements.
- A final decision on nftables versus iptables as the primary firewall backend.
- Admin identity design: local accounts, OIDC, LDAP, MFA, RBAC, and break-glass access.
- Backup design: destination, retention, restore testing, mailbox encryption, and secret custody.
- Observability design: logs, metrics, alert destinations, queue monitoring, DNS drift, and certificate expiry.
- Webmail decision: none, Roundcube, SnappyMail, or another maintained client.
- Compliance requirements that affect logging, retention, encryption, and access controls.

See `docs/architecture.md`, `docs/security.md`, and `docs/implementation-plan.md` for the detailed plan.
