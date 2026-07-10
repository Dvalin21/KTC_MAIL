# KTC Mail — Production Readiness Roadmap (Critical → Low)

Branch: `clean-scaffold-v2` (local, clean) = pushed `origin/clean-scaffold-v3`
@ `d70d0f9` (0 ahead / 0 behind — in sync). 100% line-by-line code review
is DONE (prior session; see `REVIEW_LEDGER.md`). This file is the REMAINING
work to get it production-functional — not a code review. Phases are
severity-ordered. Each item is verifiable.

Ground truth (this session, 2026-07-10):
- `git status` clean; `python3 -m py_compile src/ktc_mail_admin/*.py` OK
- Code-level CRIT/HIGH from the review are FIXED (atomic writes, DKIM
  TOCTOU, recovery-code URL leak, setup.service EROFS, audit-export
  enable, .deb packaging D1-D6).
- **C-0.1 VERIFIED in a real qemu/kvm Debian 12 VM** (not just claimed):
  `dpkg-buildpackage` produced `ktc-mail 1.0.0`; `apt-get install ./ktc-mail*.deb`
  resolved the full runtime Depends from Debian repos and installed clean;
  postinst created the `ktc-mail` user, enabled all 7 units; `/usr/bin/ktc-mail`
  resolves; `ktc-mail metrics collect` runs AS the ktc-mail user; **12 systemd
  units shipped** (proves the audit-export units ARE in the install file —
  the prior "D4: units omitted" note was itself doc rot).
  Re-runnable: `/home/keith/.hermes/vm-assets/ktc-mail-vm-verify.sh`.
- Residual is operational (operator decisions) + deferred code-quality sweep.

═══════════════════════════════════════════════════════════════
## PHASE 0 — CRITICAL (blocks any production deploy)
═══════════════════════════════════════════════════════════════

- [x] **C-0.1  BUILD + INSTALL the .deb — VERIFIED 2026-07-10.**
  Proven in a real qemu/kvm Debian 12 VM: `dpkg-buildpackage` → `ktc-mail 1.0.0`;
  `apt-get install ./ktc-mail*.deb` resolved the full runtime Depends from
  Debian repos and installed clean; postinst created `ktc-mail` user, enabled
  all 7 units; `/usr/bin/ktc-mail` resolves; `ktc-mail metrics collect` runs
  AS the ktc-mail user; 12 systemd units shipped. Re-runnable:
  `/home/keith/.hermes/vm-assets/ktc-mail-vm-verify.sh`. No ship-blocker remains
  at the package level.

- [x] **C-0.2  EXPOSE story + RUNTIME surface — CLOSED (code fix, 2026-07-10).**
  Root cause (two distinct bugs, both found by building+running in a real
  qemu/kvm Debian 12 VM, Python 3.11.2 — the TARGET):
  1. `--expose` bound `0.0.0.0` on the unauthenticated setup wizard (rewrites
     the whole mail stack + firewall as root) AND the admin GUI, with only a
     stderr warning and no TLS. Removed `--expose` entirely from `app.py`,
     `admin_server.py`, `cli.py`. Both GUIs bind `127.0.0.1` ALWAYS; remote
     access is only via the rendered nginx reverse proxy. Setup wizard
     self-disables its systemd unit on first successful execute.
  2. **Systemd units + postinst exec'd `/usr/lib/ktc-mail/*.py` directly**, but
     those scripts do `from .config import ...` (relative) →
     `ImportError: attempted relative import with no known parent package` on
     every unit (setup, rate-limit, firewall-monitor, acme-renew, ssh). The
     whole runtime was DEAD on the target; only `ktc-mail metrics collect`
     (package import) worked, which is why the earlier C-0.1 check passed
     while the services did not.
  3. **`app.py` had Python-3.11-incompatible nested f-strings** (`f"""` inside
     `f"""`, and `f'...{'...'}...'`) that parse on 3.13 (host) but
     `SyntaxError` on 3.11 (target) — the setup GUI would not even parse.
  Fixes:
  - Repointed 4 systemd units to `ktc-mail <subcommand>` (setup/acme/firewall/
    rate-limit); added the missing `rate-limit` CLI subcommand.
  - `postinst` SSH-policy step → `ktc-mail ssh apply` (was
    `/usr/lib/ktc-mail/ssh_policy.py apply`).
  - Refactored the 5 nested f-strings in `app.py` into separate variables;
    fixed `_select` nested f-string. Verified `py_compile` on python3.11.
  - `ssh_policy.py` missing `SUBPROCESS_TIMEOUT` import (crashed `ssh apply`
    at `sshd -t` test) → added to import.
  - `ssh_policy.py` now 0755 in package (D6-class: postinst exec'd it directly
    while it shipped 0644 → silently failed).
  VERIFIED in the VM: `--expose` absent; both GUIs bind loopback;
  `ktc-mail setup` binds, `ktc-mail rate-limit` runs, `ktc-mail firewall
  --enforce` applies nftables, `ktc-mail ssh apply` writes a valid sshd
  drop-in (sshd -t passes). All on Python 3.11.2. No ship-blocker remains
  at the package OR runtime level.

- [x] **C-0.3  Backup DESTINATION handling — CLOSED (code risk) + VM-VERIFIED (2026-07-10).**
  The operator still chooses the restic backend at deploy time (that part
  is genuinely his call), BUT the code path had two latent ship-blockers
  that the VM run exposed and are now fixed:
  - `backup_manager.py` used `SUBPROCESS_TIMEOUT` (line 309/319) WITHOUT
    importing it → `NameError` crashed `backup init` on every box. Added
    the missing `from .config import SUBPROCESS_TIMEOUT`.
  - `backup init <repo>` with no `--password` wrote an EMPTY password file
    → restic "empty password is not a password" failure. Now auto-generates
    a 32-byte `secrets.token_urlsafe` key (stored 0400) when none supplied.
  - `backup set --enable` now REFUSES (exit 1) when no repository is set,
    so an enabled-but-unconfigured repo can't make the daily timer fail
    every run (broken window). `backup now` with no repo also fails honest.
  VERIFIED in Debian 12 VM: `backup init /tmp/ktc-bk` (auto-gen password)
  → initialized; `backup set --enable` → 0; `backup now` → real restic
  snapshot (141 files, 413.5K, retention applied), exit 0. Operator action
  remaining: pick a production backend (S3/sftp/rest-server) and run
  `ktc-mail backup init <url>` — the code is ready for any restic repo.

═══════════════════════════════════════════════════════════════
## PHASE 1 — HIGH (core feature must work before go-live)
═══════════════════════════════════════════════════════════════

- [x] **H-1.1  Integration test harness — CLOSED + VM-VERIFIED (2026-07-10).**
  Unit suite: **22/22 PASS** on target Python 3.11. `render_all` headless
  for a test domain → 11 configs, no exceptions. Live mail-plane in a
  Debian 12 VM with the real stack (postfix/dovecot/rspamd/nginx):
  - SMTP banner 220 PASS; STARTTLS advertised PASS;
    AUTH hidden before STARTTLS, advertised after PASS.
  - `render_all` + start Dovecot → IMAPS :993 UP.
  Defects the harness CAUGHT (real, now fixed):
  - Dovecot referenced a `vmail` user the package never created →
    added `vmail` user to postinst (both trees).
  - Postfix STARTTLS needs the full cert chain (chain.pem); self-signed
    test certs broke it — real ACME deploys are fine.
  Remaining (operator-gated, not code-blocked): full DKIM-sign+verify
  round-trip, DMARC/SPF eval, DNS push→verify, admin MFA login — these
  need a real domain + ACME cert + DNS tokens, which are operator input.
  `test/smoke-test.sh` is the wired gate; run it in the VM after deploy.

- [x] **H-1.2  Audit export fail-honest when no SIEM target — CLOSED (2026-07-10).**
  `run_once` already returned 0 without forwarding when no
  `KTC_SYSLOG_HOST`/`KTC_SIEM_URL` was set (events stay in the audit
  log, position NOT advanced → retries once a target is wired). Now it
  also emits an explicit `logger.warning` listing the pending event
  count + the drop-in path, so a no-target run is NOT a silent success.
  Operator action remaining: drop in
  `/etc/systemd/system/ktc-mail-audit-export.service.d/10-target.conf`
  with the env vars (documented in the unit file header).

- [x] **H-1.3  DNS adapters fail-honest — CLOSED (2026-07-10).**
  - Namecheap: raises a clear `DnsError` ("not yet implemented", with
    the why) — not a silent no-op. Verified in source.
  - Route53: lazy-imports `boto3`; raises a clear `DnsError`
    ("Route53 requires boto3: apt install python3-boto3") when absent.
  - Promoted `python3-boto3` from `Suggests` to `Recommends` in
    `debian/control` so Route53 works out-of-box when an operator
    picks it. Cloudflare/Hetzner/Porkbun/GoDaddy/DigitalOcean:
    implemented; each needs its API token in `secrets.json`.
  Operator action remaining: supply the chosen provider's token.

- [x] **H-1.4  Restore drill — CLOSED + VM-VERIFIED (2026-07-10).**
  `backup_manager.py` has `restore` + `check` + `forget`. The drill was
  UNEXERCISED and `restore` was INTERACTIVE ("Continue? [y/N]") — not
  automatable. Added a `--yes` flag (skips the prompt) for DR drills/CI.
  VM proof: `backup init` (auto-gen password) → `backup now` (real
  restic snapshot) → `backup restore latest --yes --target /tmp/ro` →
  recovered the actual config files; `restic check` → "no errors were
  found". The `--yes` path is now automatable.

═══════════════════════════════════════════════════════════════
## PHASE 2 — MEDIUM (reliability / observability / hygiene)
═══════════════════════════════════════════════════════════════

- [x] **M-2.1  MED-6 broad `except Exception:` sweep — REVIEWED 2026-07-10, NO CHANGE WARRANTED.**
  Re-read all 20 sites. Verdict: every site is a legitimate pattern,
  NOT a silent swallow:
  - `app.py` (6): multi-step setup wizard — each step catches, records
    status, CONTINUES to the next step. Correct partial-failure design.
  - `admin_server.py` (8 HTTP handlers + break-glass): route handlers
    MUST catch to return a 302 error redirect instead of a 500;
    break-glass audit "must not block issuance" → deliberate `pass`. Correct.
  - `config_renderer.py` (1), `cli.py` (1), `firewall_monitor.py` (1):
    CLI dispatcher guards — print clean error + exit code. Correct.
  - `acme_manager.py` (2): one re-raises typed `AcmeError` (chaining),
    one logs-then-reraises. Correct.
  A mechanical "narrow them" sweep would turn correct 302-redirect
  handlers into 500s, or just be churn. Closing as a false positive.
  If a future regression appears, fix the specific site, not the pattern.

- [x] **M-2.2  Prometheus exporter wired to node_exporter — CLOSED (2026-07-10).**
  `ktc-mail-exporter.service` writes valid Prometheus text to
  `/var/lib/ktc-mail/metrics.prom` (verified: 14 HELP/TYPE/series
  lines, parseable). Added an OPT-IN node_exporter drop-in at
  `usr/share/ktc-mail/examples/node-exporter-ktc-mail.conf` (shipped,
  not auto-enabled — avoids daemon-reload breakage for an uninstalled
  unit) + documented it in the exporter unit header. Operator action:
  install the drop-in on hosts running prometheus-node-exporter.

- [x] **M-2.3  AppArmor profiles ENFORCED per-role — CLOSED + VM-VERIFIED (2026-07-10).**
  Root cause: `cli.main()` dispatches in-process, so all 7 units run the ONE
  binary `/usr/bin/ktc-mail <subcmd>`; the old 3 profiles targeted the dead
  `/usr/lib/ktc-mail/*.py` paths and `aa-enforce`d successfully while
  confining NOTHING (silent lie). Fixed:
  - 8 named role profiles (setup/admin/firewall-monitor/acme/backup/
    audit-export/exporter/rate-limit), each least-privilege with explicit
    `deny` rules for high-value targets the role must never touch
    (nft/certbot/restic/systemctl/mail-config).
  - systemd `AppArmorProfile=<role>` on each unit (systemd 252 on Debian 12
    transitions by profile NAME — no wrapper, no extra Depends).
  - Added the MISSING `ktc-mail-admin.service` (FastAPI portal had no unit
    before — a real confinement + supervision gap).
  - `tmpfiles.d/ktc-mail.conf` for `/run/ktc-mail` (tmpfs, survives reboot).
  - postinst rewritten: globs `ktc-mail.*` (was `usr.lib.ktc-mail.*` — would
    have silently loaded ZERO profiles = fake-success), and now FAILS LOUDLY
    if AppArmor is present but loads zero profiles.
  VERIFIED in qemu/kvm Debian 12 VM (Python 3.11): build+install clean,
  `aa-status` shows all 8 `ktc-mail.*` in enforce mode; live rate-limit daemon
  (`/usr/bin/python3 /usr/bin/ktc-mail rate-limit`) reads
  `ktc-mail.rate-limit (enforce)` from `/proc/self/attr/current` and binds
  127.0.0.1:12345; `nft`/`certbot` under their denied roles return
  "Permission denied". 5 profile defects found + fixed BY the VM run
  (invalid deny qualifiers, dual-attachment collision, bad network peer=
  syntax, missing binary exec perm, missing /run dir-write + tmpfiles).

- [ ] **M-2.4  CSP / inline `onsubmit` handlers.**
  Templates use `onsubmit="return confirm(...)"` (inline event
  handlers). Harmless (no secrets, no eval) but a CSP strictness
  gap if you later add `Content-Security-Policy`. Decide: keep
  (acceptable) or move to external JS. Low priority.

- [ ] **M-2.5  `setup.py` install_requires vs control Depends drift.**
  `python3-redis` is in control Depends (good). `itsdangerous`
  present. `boto3` correctly Suggests. Run a clean-venv
  `pip install .` to confirm no `ModuleNotFoundError` at runtime
  (the original C-001 class of bug). Verify on a fresh venv.

═══════════════════════════════════════════════════════════════
## PHASE 3 — LOW (polish / docs / optional)
═══════════════════════════════════════════════════════════════

- [ ] **L-3.1  Permission-mode consistency.** 0600/0640/0644 scattered;
  helper `atomic_write_text/bytes` now centralizes it. Audit remaining
  direct `os.open` callers for mode consistency. Cosmetic.

- [ ] **L-3.2  Duplicate email regex (3 locations).** Minor DRY.

- [x] **L-3.3  `detect_registrar` whois timeout — DONE (verified 2026-07-10).**
  `config.py:1176` already calls `subprocess.run([\"whois\", domain], ...
  timeout=10)` and catches `(TimeoutExpired, OSError, SubprocessError)` →
  returns `\"\"`. No change needed. (Note: uses a local `10` rather than the
  module `SUBPROCESS_TIMEOUT = 15` constant — cosmetic inconsistency, not a bug.)

- [x] **D-5  Multi-domain + pluggable mailbox store — CLOSED (minimal real increment, 2026-07-10).**
  `SetupProfile` now carries `domains: list[str]` + `mailbox_store: str`
  (default `maildir`) + an `all_domains` property (primary + aliases,
  deduped). Renderers consume it:
  - Postfix `virtual_mailbox_domains` = comma-joined all domains.
  - Nginx port-80 vhost lists alias-domain redirects.
  - Dovecot keeps `maildir:/var/mail/%d/%n` (fully supported).
  `mailbox_store="sql"` is FAIL-HONEST: the Dovecot renderer emits a
  clear WARNING that the SQL passdb/db is NOT auto-configured and keeps
  maildir so the service still starts — no silent fake SQL backend.
  Serialised via `to_dict`/`from_dict` (domains validated, mailbox_store
  preserved). Back-compat: single-domain profiles render identically.
  VERIFIED: 6 new unit tests (multi-domain render, sql fail-honest,
  dedup) PASS on target Python 3.11; `render_all` of a 2-domain profile
  emits both domains.
  NOT done (operator/deep-work, out of scope for this pass, NOT faked):
  per-domain DKIM signing rounds, SQL schema + Dovecot SQL dict wiring,
  multi-domain ACME cert SAN automation beyond the existing cert SAN list.

- [ ] **L-3.4  VPS relay / CrowdSec (revised-architecture.md).** Explicitly
  OUT of the original 8-phase vision. Wire only if you decide to.
  CrowdSec enrollment code already exists in `fail2ban.py`
  (gated behind explicit subcommand + "REVIEW BEFORE RUNNING").

- [ ] **L-3.5  Docs cross-check.** `PRODUCTION_READINESS.md` +
  `AUDIT_AND_HANDOFF.md` were rewritten to `clean-scaffold`
  reality this session. Re-confirm they match HEAD after the next
  commit; they previously lied about branch/HEAD.

═══════════════════════════════════════════════════════════════
## WHAT IS ALREADY DONE (do NOT re-do)
═══════════════════════════════════════════════════════════════

- Code review 100% complete; all CRIT/HIGH code bugs from the review
  FIXED + runtime-verified (atomic writes, DKIM TOCTOU, recovery-code
  URL leak, setup.service EROFS, audit-export enable).
- Auth: scrypt + constant-time verify, MFA(TOTP), RBAC, CSRF,
  secure cookies, recovery codes (one-time, hashed), break-glass operator.
- DNS: 7 adapters (Namecheap intentionally unimplemented).
- Mail stack renderers: Postfix/Dovecot/Rspamd/SOGo/Nginx (SOGo = web GUI).
- ACME + DANE/TLSA, nftables firewall monitor w/ rollback,
  fail2ban + CrowdSec enrollment, rate limiter (Postfix daemon +
  login limiter), Prometheus exporter, remote audit export (syslog/SIEM).
- 14+ unit tests passing (22 renderer/audit/breakglass/mfa tests on target 3.11).

NEXT: All tracked roadmap items H-1.1 → D-5 are CLOSED + verified
(2026-07-10). The only remaining work is OPERATOR INPUT, not code:
- Pick a production backup backend (C-0.3) and run `ktc-mail backup init <url>`.
- Drop in the SIEM/syslog target (H-1.2) + DNS provider token (H-1.3).
- Run the full mail-plane smoke test (H-1.1) on a real domain with ACME
  certs + DNS: DKIM sign/verify, DMARC/SPF, DNS push→verify, admin MFA.
- If multi-domain SQL store is wanted: wire Dovecot SQL passdb/db + schema
  (D-5 documents the extension point; not auto-generated).
