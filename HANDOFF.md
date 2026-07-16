# HANDOFF — KTC Mail (2026-07-12)

## State
- Branch **`clean-scaffold-v2`**, HEAD **`a848615`**, in sync with `origin/clean-scaffold-v2` (tree clean). NOTE: `origin/clean-scaffold-v3` (`9f905b6`) is a SEPARATE branch — do not merge; histories are unrelated (empty merge-base).
- **OS retargeted Debian 12 → 13 (trixie)** (commit `b8acafa`). Target = **Python 3.13** (trixie's interpreter; host is also 3.13.5). All VM verification runs on real Debian 13 qemu/kvm via `ktc-mail-vm-verify.sh`. Standards-Version 4.7.2.
- No CRITICAL/HIGH blockers. Remaining work = OPERATOR INPUT only (tokens, domain, IdP creds) — not code-blocked.

## Recent (2026-07) — DNS criticals + security features
- DNS **CRITICAL C1** (`97586b6`): MX/SRV records shipped without a priority field (priority double-encoded into the value) → malformed MX at every provider, inbound mail bounced. Fixed: `DnsRecord.priority` carries priority; adapters send per-provider contract. Regression: `test/unit/test_dns_mx_srv.py`.
- DNS **HIGH H4** (`83d7429`): `DnsRecord` names not FQDN-dotted; provider parsers return dotted names → `diff()` key mismatch → every `dns apply` deleted+recreated all non-TXT records (mail-flap window). Fixed: normalize name in `DnsRecord.__post_init__`. Regression: H4 coverage.
- DNS **CRITICAL C2** (`a848615`): provider parsers used direct dict indexing → malformed/apex records raised `KeyError` and aborted `dns apply`/`verify`; Porkbun dropped apex records. Fixed: `.get()` hardening + skip; Porkbun apex check. Regression: C2 coverage across 6 providers.
- **ClamAV + greylisting** (`507f355`): ClamAV antivirus wired via rspamd; greylisting parity confirmed. Present on branch.
- **Multi-domain SQL mailbox store** (working tree, this session): `profile.mailbox_store='sql'` now fully wired — Dovecot SQL passdb/userdb, `MAILBOX_SCHEMA_SQL`, `user_manager.py` SQL path (psycopg2), deploy provisioning of `ktc_mail` PG role/db. opt-in; maildir remains default. VM-verified pending.

## Verified this cycle (real Debian 13 VM, not host)
- `.deb` builds (`dpkg-buildpackage` → `ktc-mail_1.0.0_all.deb`) + installs on trixie via `apt` (Depends resolve from Debian repos). sogo 5.12.1, dovecot-core 2.4.1 (ships oauth2 driver).
- DNS-01 feature (`966c831`): `ktc-mail dns apply` auto-populates the FULL record set (A/AAAA, MX, SPF, DKIM, DMARC, MTA-STS, 6 CNAMEs, 6 SRVs, + TLSA when cert exists) via provider API. User-added registrar records are NEVER deleted (owned-keys delete-protection); `dns_managed` allowlist scopes touch. TLSA recomputed + upserted on every cert issue/renew via single `sync_records(include_tlsa=True)` path.
- Wildcard cert: `cert_san_names` = `*.domain` + all 7 service URLs. One cert covers every service URL.
- ActiveSync: nginx EAS proxy wired + tuned (04dd031); SOGo 5.12.1.
- IMAP: password + LDAP auth WORK. OIDC IMAP-OAuth2 available on trixie (dovecot-core ships the oauth2 driver).

## Full line-by-line security review (Linus + Ponytail, 2026-07-12)
Re-audited the security-critical surface in full (mfa.py, breakglass.py, admin_server.py auth/RBAC/CSRF + 20+ POST routes, user_manager.py, config.py secret storage, app.py setup wizard). Found and FIXED:
- **HIGH: `/logout` route was never registered.** Handler existed but lacked `@app.get("/logout")` — dead orphan function. base.html linked to it → 404 on every logout; sessions never cleared via UI. Doc/code broken window. FIXED (registered route).
- **MEDIUM: break-glass login unthrottled.** `/login/break-glass` had no rate limiting (unlike `/login` + `/login/mfa`). Token ~25 bits → online-guessable unthrottled. FIXED (`_login_rate_check` on entry + `_login_rate_record` on failure).
- **MINOR: `settings_mfa_disable` left stale `mfa_recovery_codes` hashes.** Purged on disable.
- **MINOR: `_verify_api_key` rewrote the whole key file on every authenticated request** (concurrency race on `last_used_at`). Dropped the mutate-and-save; `last_used_at` stays at creation time.

Verified SOUND (no change): scrypt password hashing (per-hash salt, const-time compare), TOTP RFC-6238 + recovery codes, RBAC + per-session CSRF on all POST routes, api-key SHA-256 + show-once, app.py wizard (no `shell=True`, `html.escape` everywhere, self-disables after run), atomic_write helpers (open at final mode, no TOCTOU).

## VM re-verify (2026-07-12, post-bugfix) — ALL GREEN
`ktc-mail-vm-verify.sh` result (0 FAIL):
- OK: `/usr/bin/ktc-mail` resolves; `ktc-mail` user exists; `metrics collect` runs as ktc-mail.
- OK: no `--expose` in setup/admin; `app.py` + `admin_server.py` bind loopback (C-0.2 regression).
- OK: `ssh_policy.py` 0755/executable (postinst path); setup GUI bound; rate-limiter running; firewall --enforce ran (no ImportError).
- `.deb` = `ktc-mail_1.0.0_all.deb` (120 KB), Depends resolve via apt.

NOTE: the verify script previously self-killed at `pkill -9 -f ktc-verify` (matched its own bash argv). Fixed to `pkill -f 'qemu-system-x86_64.*ktc-verify'` + pidfile cleanup. Re-run passed.

## Key gotchas (don't re-learn)
- Host is Python 3.13; **TARGET is 3.13 (trixie)** — VM verify boots `debian-13-nocloud-amd64.qcow2`.
- Two-tree landmine: `debian/` is build source of truth; `packaging/debian/` is CI mirror. Edit root→mirror. NEVER `rm -rf debian && cp packaging/debian`.
- VM approval gate trips on BUNDLED commands (systemctl+apparmor_parser+pgrep in one SSH). Split into one single-purpose call each.
- VM reusable script: `/home/keith/.hermes/vm-assets/ktc-mail-vm-verify.sh`. Boots trixie, virt-customize (mask firstboot, install openssh-server, inject pubkey, enable ssh), builds+installs `.deb`, runs assertions, leaves VM at pidfile `/home/keith/.hermes/vm-assets/qemu.pid`. Kill: `kill $(cat /home/keith/.hermes/vm-assets/qemu.pid)`. Disk is freshly created from the nocloud base each run (never reuse stale).
- trixie nocloud image gotcha: minimal — NO openssh-server, NO cloud-init, blocks on interactive systemd-firstboot. Script handles via virt-customize. Don't re-add seed.iso.
- SSH port 2223 for the verify VM (2222 is a different unrelated VM).

## Operator / deep work NOT done (honest, not faked)
- OPERATOR: `ktc-mail backup init <restic-url>` (restic coded + restore VM-verified; needs a repo URL).
- OPERATOR: DNS provider API token in `secrets.json`; real-domain smoke test (DKIM/DMARC/SPF push→verify, admin MFA).
- OPERATOR: OIDC webmail SSO end-to-end needs IdP creds (render gated, ready).
- DEEP: multi-domain SQL mailbox store — **DONE** (this session, working tree): Dovecot SQL passdb/userdb + `MAILBOX_SCHEMA_SQL` + `user_manager.py` SQL path + deploy provisioning. opt-in via `profile.mailbox_store='sql'`; maildir is default.

## Authoritative docs (match `a848615`; reconciled 2026-07-16)
- `PRODUCTION_READINESS.md` — verdict + reference-suite comparison.
- `PRODUCTION_ROADMAP.md` — all items closed + evidence.
- `AUDIT_AND_HANDOFF.md` — fix ledger + open items.
- `REVIEW_LEDGER.md` — 100% line-by-line review record.
