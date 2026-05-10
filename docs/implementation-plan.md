# KTC Mail implementation plan

This is the build order. Each phase must leave the product safer and more testable than the phase before it.

## Phase 0: Threat model and hard rules

**Goal:** Lock the security baseline before adding moving parts.

**Deliverables:**

- Mailcow feature inventory mapped to Debian/Ubuntu packages and systemd units.
- Threat model for SMTP abuse, mailbox takeover, DNS API compromise, cert/key theft, web admin compromise, and backup leakage.
- Root-only secret storage rules, token scope rules, and audit log requirements.
- Supported OS matrix for Debian stable and Ubuntu LTS.

**Exit criteria:** Written decisions exist for DNS providers, firewall backend, identity/MFA, webmail, backups, and observability.

## Phase 1: First-run installer and setup profile

**Goal:** Make the `.deb` install predictable and capture all information needed to build the host.

**Deliverables:**

- `.deb` package installs setup GUI, systemd units, examples, helpers, and docs.
- First-run GUI collects domain, mail hostname, admin hostname, SOGo hostname, admin email, DNS provider, DNS API token, certificate mode, and hostname-management consent.
- Setup profile records open ports, DNS records, renewal hooks, and security defaults.
- Secrets are stored separately with `0600` permissions.

**Exit criteria:** A fresh VM can install the package, submit setup, and produce valid config without starting mail services publicly.

## Phase 2: DNS and certificate automation

**Goal:** Automate DNS and TLS safely without over-broad API credentials.

**Deliverables:**

- DNS provider adapter interface and first production adapter.
- ACME DNS-01 issuance path, HTTP-01 fallback, renewal timer, and renewal hook runner.
- Automatic A, AAAA, MX, SPF, DKIM, DMARC, TLS-RPT, MTA-STS, SRV, CNAME, and optional TLSA management.
- TLSA regeneration after every successful cert renewal when DANE is enabled.

**Exit criteria:** Cert renewal updates service certs, reloads Postfix/Dovecot/Nginx, and updates TLSA without exposing port 80 for DNS-01 installs.

## Phase 3: Mail stack configuration

**Goal:** Generate hardened Postfix, Dovecot, Rspamd, Redis, and Nginx configs from the setup profile.

**Deliverables:**

- Postfix SMTP, submission, postscreen, milter, TLS, rate-limit, and relay-deny templates.
- Dovecot IMAPS, LMTP, mailbox, Sieve, password-hash, and auth templates.
- Rspamd DKIM, ARC, DMARC, SPF, greylisting, reputation, and Redis templates.
- Nginx vhosts for separate admin and SOGo hostnames.
- SOGo packaging/configuration or a documented replacement if SOGo is rejected.

**Exit criteria:** Local integration tests prove inbound SMTP, outbound submission, IMAPS login, DKIM signing, and web routes work on a clean VM.

## Phase 4: Firewall and abuse controls

**Goal:** Close everything not required and make drift visible.

**Deliverables:**

- nftables-first firewall backend with iptables compatibility if required.
- Config-driven open-port policy: SSH, SMTP, HTTPS, submission, IMAPS, optional ManageSieve, and port 80 only for HTTP-01.
- Fail2ban baseline plus decision on CrowdSec or equivalent reputation layer.
- Per-mailbox outbound rate limits, compromised-account quarantine, and queue abuse checks.

**Exit criteria:** Re-running enforcement is idempotent, lockout-safe, and covered by tests using generated setup profiles.

## Phase 5: Admin GUI and identity

**Goal:** Build a usable admin GUI without creating a soft target.

**Deliverables:**

- HTTPS-only admin GUI on the dedicated admin hostname.
- Local admin bootstrap, WebAuthn/MFA, recovery codes, session timeout, CSRF protection, and secure cookies.
- RBAC for global admin, domain admin, mailbox admin, read-only auditor, and break-glass operator.
- Mailbox/domain CRUD, DNS/cert status, queue view, logs, and health checks.

**Exit criteria:** Admin operations are audited, role-gated, and covered by browser/API tests.

## Phase 6: Backup, restore, and observability

**Goal:** Make recovery and detection first-class features.

**Deliverables:**

- Encrypted restic backups for mailboxes, configs, secrets, DKIM keys, and database/state.
- Restore workflow tested into a clean VM.
- Metrics and alerts for queue depth, disk pressure, auth failures, cert expiry, DNS drift, blacklist status, and service health.
- Remote audit log/syslog/SIEM support.

**Exit criteria:** A documented disaster-recovery drill restores mail service from backup and proves alert delivery.

## Phase 7: Release hardening

**Goal:** Ship something that can survive real internet traffic.

**Deliverables:**

- AppArmor profiles for custom services and helpers.
- Debian package upgrade/rollback tests.
- Unattended security update policy and reboot coordination.
- Full integration test matrix for Debian stable and Ubuntu LTS.
- External security review checklist.

**Exit criteria:** Install, upgrade, renewal, backup, restore, and abuse-control flows pass in repeatable CI/VM testing.
