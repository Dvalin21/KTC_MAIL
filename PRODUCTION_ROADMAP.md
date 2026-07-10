# KTC Mail — Production Readiness Roadmap (Critical → Low)

Branch: `clean-scaffold` @ `237debd` (clean tree, 14/14 unit tests pass,
full tree compiles). 100% line-by-line code review is DONE
(prior session; see `REVIEW_LEDGER.md` + `references/ktc-mail-review-pitfalls.md`).
This file is the REMAINING work to get it production-functional — not a
code review. Phases are severity-ordered. Each item is verifiable.

Ground truth (this session):
- `git status` clean; `python3 -m py_compile src/ktc_mail_admin/*.py` OK
- `pytest test/` → 14 passed
- Code-level CRIT/HIGH from the review are FIXED (atomic writes, DKIM
  TOCTOU, recovery-code URL leak, setup.service EROFS, audit-export
  enable). Residual is operational + one deferred code-quality sweep.

═══════════════════════════════════════════════════════════════
## PHASE 0 — CRITICAL (blocks any production deploy)
═══════════════════════════════════════════════════════════════

- [ ] **C-0.1  Actually BUILD + INSTALL the .deb.** Never exercised.
  `systemd-analyze verify` reported `/usr/bin/ktc-mail` and
  `/usr/lib/ktc-mail/*.py` "not executable" — because the package
  was never built/installed. Until `dpkg -i` is run on a clean
  Debian/Ubuntu, NONE of the systemd units, postinst AppArmor
  load, or ktc-mail CLI exist. This is the #1 ship-blocker:
  the code is proven but the PACKAGE is unproven.
  Verify: `dpkg-buildpackage` (or `dpkg -b` from a staged tree) →
  `dpkg -i` in a throwaway VM → all 7 units `systemctl status`
  show `active`/`enabled`, `which ktc-mail` resolves.

- [ ] **C-0.2  Decide + set the admin-server EXPOSE story.**
  `admin_server.py cmd_admin_start` defaults `host=127.0.0.1`;
  `--expose` binds `0.0.0.0` with only a stderr WARNING.
  The setup GUI (`ktc-mail-setup.service`) listens on `:8080`.
  There is NO TLS terminator wired for either. You MUST run both
  behind nginx (which IS rendered) with a real cert, NOT bind
  0.0.0.0 raw. Verify: `nginx -t` passes; `curl -k https://host:8081`
  (admin) returns 200; `0.0.0.0` bind is rejected by policy.

- [ ] **C-0.3  Backup DESTINATION is unset (data-loss risk).**
  `backup_manager.py` is restic-based but the repo/init path needs a
  real `RESTIC_REPOSITORY` + credentials. README explicitly lists
  "Restore drill + destination selection" as YOUR operational decision.
  Until set, backup `run` has nowhere to push. Verify:
  `ktc-mail backup run` → non-zero / clear error if repo unset; a real
  `restic init` against your chosen backend succeeds.

═══════════════════════════════════════════════════════════════
## PHASE 1 — HIGH (core feature must work before go-live)
═══════════════════════════════════════════════════════════════

- [ ] **H-1.1  Integration test harness (Phase 7 exit criteria).**
  Unit tests pass but there is NO VM-level integration proof:
  SMTP AUTH before/after STARTTLS, IMAPS login, DKIM sign+verify,
  DMARC/SPF eval, DNS push→verify round-trip, admin GUI login+MFA.
  README "before production" + docs/implementation-plan.md require it.
  Verify: a scripted throwaway VM (or podman) runs the smoke
  path end-to-end and asserts each. `test/smoke-test.sh` exists
  but is NOT wired into CI/Phase-7 gate.

- [ ] **H-1.2  Operator decisions: SIEM target + compliance retention.**
  `ktc-mail-audit-export.service` ships with NO targets (safe no-op
  until you drop in `/etc/systemd/system/ktc-mail-audit-export.service.d/10-target.conf`
  with `KTC_SYSLOG_HOST` / `KTC_SIEM_URL`). README lists
  "Alert destinations need wiring to your SIEM" as open. Verify:
  drop-in present; timer fires every 10m; synthetic audit line appears
  in your SIEM/syslog within 1 cycle.

- [ ] **H-1.3  DNS adapter readiness.**
  - Namecheap: NOT implemented (raises clear error — acceptable, but
    README must not list it as usable).
  - Route53: lazy-imports `boto3` (Suggested but not Depends).
    On a box without `python3-boto3` it errors at use. Verify:
    install `python3-boto3` on target OR document Route53 unsupported
    without it.
  - Cloudflare/Hetzner/Porkbun/GoDaddy/DigitalOcean: implemented;
    each needs its API token in `secrets.json`. Verify each provider's
    `apply`→`verify` round-trip against a real (test) zone.

- [ ] **H-1.4  Restore drill (Phase 6 deliverable, unexercised).**
  `backup_manager.py` has `restore` + `check` + `forget` but no
  documented DR drill was run. Verify: `ktc-mail backup restore`
  into a scratch dir recovers a known file; `restic check` passes.

═══════════════════════════════════════════════════════════════
## PHASE 2 — MEDIUM (reliability / observability / hygiene)
═══════════════════════════════════════════════════════════════

- [ ] **M-2.1  MED-6 broad `except Exception:` sweep (DEFERRED).**
  19 sites across admin_server/app/backup_manager/firewall_monitor/cli
  swallow broadly. Not a runtime blocker (review confirmed no active
  bug), but a broken window — masks future regressions. Verify
  per-file: replace with specific `except (OSError, ValueError, ...)`
  + `logger.exception` where the failure is real.

- [ ] **M-2.2  Prometheus exporter is opt-in, not wired to node_exporter.**
  `ktc-mail-exporter.service` runs `ktc-mail metrics collect` to
  `/var/lib/ktc-mail/metrics.prom`, but node_exporter textfile
  collector must be pointed at that path. Verify:
  `node_exporter --collector.textfile.directory=/var/lib/ktc-mail`
  and `/metrics` exposes `ktc_mail_*` series.

- [ ] **M-2.3  AppArmor profiles actually ENFORCED on target.**
  postinst loads them (now logs failures instead of `|| true`). But
  the 3 profiles (`rate_limiter`, `admin_server`, `firewall_monitor`)
  must be `aa-enforce`d and survive `apparmor_parser -p`. Verify
  on the install VM: `aa-status` shows them in enforce mode; a
  denied syscall is logged, not silently breaking the daemon.

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

- [ ] **L-3.3  `detect_registrar` uses `whois` with no timeout.** Add
  `subprocess` timeout (project standard is `SUBPROCESS_TIMEOUT`).

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
- 14 unit tests passing.

NEXT: start at C-0.1 (build + install the .deb in a throwaway VM).
That is the only thing standing between "code works" and "server ships".
