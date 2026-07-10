# KTC Mail

KTC Mail is a bare-metal Debian/Ubuntu mail server suite scaffold. The goal is a Mailcow-style operational structure without Docker: mature open-source mail components, a friendly web GUI, guided DNS/TLS setup, and strict firewall/security defaults.

## Current scope

This repository now contains the first implementation slice:

- A standard-library Python first-run web GUI that launches on the server IP and collects domain, hostname, public IPs, DNS provider, administrator email, and certificate mode.
- DNS plan generation and first-pass automation for A, AAAA, MX, SPF, DKIM, DMARC, TLS-RPT, optional DANE TLSA, split admin/SOGo hostnames, and autodiscovery SRV records.
- An nftables firewall monitor that reads the setup profile so DNS-01 keeps port 80 closed unless HTTP-01 is selected.
- Debian packaging metadata that installs the GUI, firewall monitor, helper scripts, examples, documentation, and systemd units.
- ACME issue/renew tooling with DNS-01 hooks, HTTP-01 fallback, TLSA regeneration, and service reload hooks.
- A bootstrap script that installs the proven open-source stack: Postfix, Dovecot, Rspamd, Redis, Fail2ban, Nginx, certbot, nftables, and supporting tools.

## Target production stack

| Layer | Tooling |
| --- | --- |
| SMTP | Postfix with postscreen, Rspamd milter, strict TLS, submission on 587 |
| IMAP and delivery | Dovecot IMAPS, LMTP, Sieve, ManageSieve as optional |
| Spam/security policy | Rspamd, Redis, Fail2ban, optional CrowdSec |
| Admin GUI | KTC Mail Python service, later hardened behind HTTPS and MFA |
| TLS | ACME DNS-01 provider APIs, service reload hooks, optional DANE TLSA updates |
| Firewall | nftables (inet family, IPv4+IPv6 single ruleset) |
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

- DNS provider adapters: Cloudflare, Route53 (AWS, needs boto3), Hetzner,
  Porkbun, GoDaddy, and DigitalOcean are implemented (plus a DryRun provider
  for `--dry-run`). Namecheap is NOT implemented (its API is XML-based and
  needs reverse-engineering — `ktc-mail dns apply` raises a clear error if
  selected). Run `ktc-mail dns providers` for the full list and token scopes.
- ✅ Admin identity: local accounts, MFA (TOTP), RBAC (admin/operator/readonly), CSRF, secure cookies, recovery codes, and break-glass operator access are implemented. OIDC/LDAP remain optional future auth backends.
- ✅ Backup: restic-based (init/run/restore/check/forget/snapshots) with configurable retention. Restore drill + destination selection still need your operational decision.
- ✅ Observability: append-only audit log, Prometheus exporter (queue/DNS drift/cert expiry), and remote audit export (syslog/SIEM) are implemented. Alert destinations need wiring to your SIEM.
- Webmail: SOGo is wired by default (config renderer + nginx vhost). Switch to Roundcube/SnappyMail if preferred.
- Compliance requirements that affect logging, retention, encryption, and access controls — your call (jurisdiction/regime).

See `docs/architecture.md`, `docs/security.md`, and `docs/implementation-plan.md` for the detailed plan.
