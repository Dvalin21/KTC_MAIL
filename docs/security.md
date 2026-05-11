# Security plan and missing decisions

## Baseline controls implemented in this scaffold

- The first-run GUI is a small Python standard-library service, reducing bootstrap dependency risk.
- The systemd unit uses `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem`, `ProtectHome`, and explicit writable paths.
- The firewall monitor checks both `iptables` and `ip6tables` for the KTC chain, required ports, and chain ordering.
- The default port model keeps port 80 closed for DNS-01 and allows it only for HTTP-01.
- DNS setup includes SPF, DKIM, DMARC, TLS-RPT, optional DANE TLSA, and client autodiscovery records.
- Cloudflare DNS automation uses the stored API token only from the root-readable secrets file.
- ACME renewal hooks regenerate TLSA records and reload Postfix, Dovecot, and Nginx after successful certificate renewal.
- Phase 3 renders mail service configs into a staging directory for review instead of overwriting `/etc` directly.
- Phase 4 uses nftables as the primary firewall backend while retaining generated iptables compatibility output.
- Fail2ban jails, Postfix rate-limit snippets, queue checks, and quarantine policy artifacts are generated from the setup profile.
- Phase 5 admin portal stores PBKDF2 password hashes, role assignments, sessions, recovery codes, and audit logs in root-readable files.
- Phase 6 renders restic backup, restore-drill, health-check, DNS drift, and ops policy artifacts without enabling external alert delivery by default.

## Recommended enterprise additions

- Admin authentication with phishing-resistant MFA, recovery codes, session timeout, and WebAuthn support.
- Role-based access control for domain admins, mailbox admins, read-only auditors, and break-glass operators.
- Root-owned API credential storage with separate provider scopes for DNS challenge records and TLSA updates.
- ACME DNS-01 renewal hooks that reload Postfix, Dovecot, and Nginx only after certificate validation succeeds.
- MTA-STS and TLS-RPT hosting to improve SMTP transport security visibility.
- DKIM key rotation workflows with staged DNS publication before signing cutover.
- DMARC policy ramp from `none` to `quarantine` to `reject` with report review.
- Encrypted mailbox and configuration backups with tested restore procedures.
- Immutable audit logging to a remote syslog or SIEM target.
- Unattended security updates with reboot orchestration and service health checks.
- AppArmor profiles for the admin GUI and custom helper scripts.
- Optional CrowdSec integration in addition to Fail2ban for shared reputation signals.
- Outbound abuse controls: per-mailbox send limits, suspicious login detection, and compromised account quarantine.
- Queue health monitoring, disk pressure alerts, certificate-expiry alerts, DNS drift alerts, and blacklist monitoring.

## Decisions still needed from you

- Which DNS providers must be supported first: Cloudflare, Route 53, DigitalOcean, Hetzner, Porkbun, Namecheap, or another hoster.
- Whether the product should use nftables as the primary firewall backend while keeping iptables compatibility.
- Whether mailboxes are local-only, LDAP-backed, OIDC-backed, or integrated with an existing identity provider.
- Whether the web GUI should manage multiple domains and organizations from day one.
- Backup target choices, retention rules, and encryption key custody.
- Required compliance posture, such as SOC 2, HIPAA, CJIS, PCI DSS, or internal enterprise hardening benchmarks.
- Whether to expose webmail, and if so whether to package Roundcube, SnappyMail, or a separate supported client.
