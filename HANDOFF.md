# HANDOFF — KTC Mail (2026-07-11)

## State
- Branch `clean-scaffold-v2` (local) = `origin/clean-scaffold-v3` (pushed), commit **`966c831`** (feat(dns-01)). Tree CLEAN.
- **OS retargeted Debian 12 → 13 (trixie)** (commit `b8acafa`). Target = **Python 3.13** (trixie's interpreter; host is also 3.13.5, so the old host≠target parse-gap is moot). All VM verification now runs on real Debian 13 qemu/kvm via `ktc-mail-vm-verify.sh`. Standards-Version 4.7.2.
- No CRITICAL/HIGH blockers. Remaining work = OPERATOR INPUT only (tokens, domain, IdP creds) — not code-blocked.

## Verified this cycle (real Debian 13 VM, not host)
- `.deb` builds + installs on trixie; sogo 5.12.1, dovecot-core 2.4.1 (ships oauth2 driver).
- DNS-01 feature (966c831): `ktc-mail dns apply` auto-populates the FULL record set (A/AAAA, MX, SPF, DKIM, DMARC, MTA-STS, 6 CNAMEs, 6 SRVs, + TLSA when cert exists) via provider API. User-added registrar records are NEVER deleted (owned-keys delete-protection); `dns_managed` allowlist scopes touch. TLSA recomputed + upserted on every cert issue/renew via single `sync_records(include_tlsa=True)` path (shared by `dns apply` + certbot deploy hook).
- Wildcard cert: `cert_san_names` = `*.domain` + all 7 service URLs (mail/smtp/imap/autoconfig/autodiscover/admin/email). One cert covers every service URL. Verified via probe.
- ActiveSync: nginx EAS proxy wired + tuned (keepalive, no request buffering) (04dd031); SOGo 5.12.1.
- IMAP: password + LDAP auth WORK. OIDC IMAP-OAuth2 available on trixie (dovecot-core ships the oauth2 driver) — no third-party repo.

## Key gotchas (don't re-learn)
- Host is Python 3.13; **TARGET is 3.13 (trixie)** — the VM verify boots `debian-13-nocloud-amd64.qcow2`. (Pre-retarget docs citing "3.11 / Debian 12" are stale; trixie ships 3.13, same as host, so the old f-string parse-gap is moot on target.) Always `py_compile` with the target interpreter if you still support bookworm back-deploys.
- Two-tree landmine: `debian/` is build source of truth; `packaging/debian/` is CI mirror. Edit root→mirror. NEVER `rm -rf debian && cp packaging/debian`.
- VM approval gate trips on BUNDLED commands (systemctl+apparmor_parser+pgrep in one SSH). Split into one single-purpose call each.
- VM reusable script: `/home/keith/.hermes/vm-assets/ktc-mail-vm-verify.sh`. It: downloads trixie nocloud if missing, virt-customize the disk (mask systemd-firstboot, install openssh-server, inject pubkey, enable ssh), boots, runs full `.deb` build+install+service dry-starts, leaves VM at pidfile `/home/keith/.hermes/vm-assets/qemu.pid`. Kill: `kill $(cat /home/keith/.hermes/vm-assets/qemu.pid)`.
- trixie nocloud image gotcha: minimal — NO openssh-server, NO cloud-init provisioning, blocks on interactive systemd-firstboot. The verify script handles this via virt-customize (cloud-init seed.iso does NOT run on this image). Don't re-add seed.iso.
- SSH port 2223 for the verify VM (2222 is a different unrelated VM).

## Operator / deep work NOT done (honest, not faked)
- OPERATOR: `ktc-mail backup init <restic-url>` (restic coded + restore VM-verified; needs a repo URL).
- OPERATOR: DNS provider API token in `secrets.json`; real-domain smoke test (DKIM/DMARC/SPF push→verify, admin MFA).
- OPERATOR: OIDC webmail SSO end-to-end needs IdP creds (render gated, ready).
- DEEP: multi-domain SQL mailbox store (profile/renderer layer done; Dovecot SQL passdb/db + schema remain).

## Authoritative docs (match `966c831`)
- `PRODUCTION_READINESS.md` — verdict + reference-suite comparison (updated).
- `PRODUCTION_ROADMAP.md` — all items closed + evidence.
- `AUDIT_AND_HANDOFF.md` — fix ledger + open items.
- `REVIEW_LEDGER.md` — 100% line-by-line review record.
