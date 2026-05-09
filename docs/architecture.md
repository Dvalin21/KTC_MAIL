# KTC Mail bare-metal architecture

KTC Mail follows the Mailcow-style separation of responsibilities while using Debian/Ubuntu packages and systemd services instead of Docker containers.

## Service map

| Capability | Component | Notes |
| --- | --- | --- |
| SMTP ingress/egress | Postfix | Chrooted where practical, strict TLS policy, postscreen, rate limits, sender restrictions, Rspamd milter integration. |
| Mailbox access | Dovecot | IMAPS, LMTP delivery, Sieve, per-domain mailbox configuration, strong password hashing, optional external identity provider later. |
| Spam and policy | Rspamd + Redis | DKIM signing, ARC, DMARC, SPF, greylisting, neural and reputation modules. |
| Abuse response | Fail2ban | Watches Postfix, Dovecot, Nginx, and admin UI logs; feeds temporary blocks into the KTC firewall chain. |
| Web administration | KTC Mail setup GUI | Starts on the server IP after package installation and guides domain, DNS, TLS, and policy setup. |
| TLS automation | ACME DNS-01 provider adapters | Provider APIs create challenge records, renew certificates, reload services, and update TLSA/DANE records when enabled. |
| Firewall integrity | KTC firewall monitor | Verifies iptables/ip6tables chain order and required ports so mail rules are not shadowed by accidental drops. |

## Installation flow

1. Install the `.deb` on a fresh Debian or Ubuntu host.
2. The package enables `ktc-mail-setup.service`, which listens on `http://SERVER_IP:8080` for first-run setup.
3. The admin enters the mail domain, mail hostname, DNS provider, admin address, and certificate mode.
4. KTC Mail generates the required DNS plan: A, AAAA, MX, SPF, DKIM, DMARC, optional TLSA, and autodiscovery SRV records.
5. Provider adapters will apply DNS through API tokens stored with root-only permissions.
6. ACME DNS-01 certificates will be issued and installed for Postfix, Dovecot, and Nginx.
7. The firewall policy opens only SSH, SMTP, HTTP bootstrap, HTTPS, submission, IMAPS, and optional ManageSieve.

## What is intentionally not reinvented

KTC Mail should orchestrate proven components instead of reimplementing the mail server itself. Postfix, Dovecot, Rspamd, Redis, Fail2ban, Nginx, systemd, ACME clients, and Debian package management remain the core building blocks.
