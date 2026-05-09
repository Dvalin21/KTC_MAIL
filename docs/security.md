# Security plan and missing decisions

## Baseline controls implemented in this scaffold

- The first-run GUI is a small Python standard-library service, reducing bootstrap dependency risk.
- The systemd unit uses `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem`, `ProtectHome`, and explicit writable paths.
- The firewall monitor checks both `iptables` and `ip6tables` for the KTC chain, required ports, and chain ordering.
- The default port model allows only `22/tcp`, `25/tcp`, `80/tcp`, `443/tcp`, `587/tcp`, `993/tcp`, and optional `4190/tcp`.
- DNS setup includes SPF, DKIM, DMARC, optional DANE TLSA, and client autodiscovery records.

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
