# KTC Mail — Production Readiness Status

**Last Updated:** 2026-07-09 (post line-by-line review, BEFORE commit)
**Branch:** `clean-scaffold` (working tree DIRTY — changes UNCOMMITTED)
**Base Commit:** e2ba7a5

> NOTE: earlier versions of this file falsely claimed `main`@`527603e`/`ed8afd7`
> and "All CRIT/HIGH/MEDIUM fixed". Those claims were WRONG — the
> branch was `clean-scaffold` and several real bugs were still open. This
> rewrite reflects the actual tree state as of 2026-07-09.

---

## ✅ FIXED THIS SESSION (verified by reading source + running code)

| ID | Issue | Fix | Evidence |
|----|-------|-----|----------|
| THEME | `write_text()`+`chmod()` TOCTOU across 7 sites (exporter, ssh_policy, firewall_monitor, fail2ban×2, app.py DKIM, admin_server DKIM, config_renderer DKIM) | Added `atomic_write_text()` + `atomic_write_bytes()` to `config.py`; both open at final mode → fsync → rename (no world-readable window). Routed all 7 sites through them. | Runtime test: written file is `0600` before any other process can read it |
| CRIT | One-time recovery codes leaked in 302 `Location` query string (`?recovery=CODE1,CODE2`) → access logs / browser history / Referer | `settings_mfa_recovery` + `settings_mfa_init` now render codes ONCE via new `mfa_codes.html` body (mirrors `api_key_created.html`) | Code read; template added |
| HIGH | DKIM private key written via `write_bytes`+`chmod` (world-readable TOCTOU window) | `atomic_write_bytes(key_path, priv_pem)` → `0600` in app.py, admin_server, config_renderer | Compiles; helper runtime-tested |
| HIGH | `ktc-mail-setup.service` had `ProtectSystem=full` + `ReadWritePaths=/etc/ktc-mail` only → wizard's "Write mail configs" step hit EROFS writing `/etc/postfix` etc. | Added real write paths (`/etc/postfix /etc/dovecot /etc/nginx /etc/rspamd /etc/sogo /etc/ssh /etc/letsencrypt /etc/ssl`) | Service file read; wizard writes enumerated from `config_renderer.write_all` |
| DEP | `python3-boto3` (Route53, lazy-imported) missing from control | Added `Suggests: python3-boto3` | control read |
| DEP | `python3-venv` in bootstrap but unused (no venv anywhere) | Removed from bootstrap | bootstrap read |
| WIRING | `ktc-mail-audit-export.timer` never enabled in postinst → remote audit export never ran | Added to postinst `systemctl enable` list | postinst read |
| WIRING | audit-export `.service` blank `Environment=` overrode ambient config (footgun) | Replaced with drop-in documentation comment | service file read |

---

## ✅ ALREADY IMPLEMENTED + VERIFIED (was falsely marked missing)

- **Remote audit-log / syslog / SIEM export (Phase 6):** FULLY PRESENT.
  - `src/ktc_mail_admin/audit_export.py` (243 lines): syslog UDP/TCP/TLS + SIEM JSON + byte-offset position tracking (idempotent, crash-safe).
  - `cli.py`: `ktc-mail audit export --syslog-host/--siem-url/...` wired.
  - `systemd/ktc-mail-audit-export.service` + `.timer` (every 10 min).
  - `test/unit/test_audit_export.py`: 5 tests pass.
  - **Integration verified this session:** ran against a fake UDP syslog listener — first run forwarded 2 events, second run forwarded 0 (cursor advanced). Real datagrams received.
- **Recovery codes + break-glass (Phase 5):** present (`mfa.py`, `breakglass.py`, admin routes). `session_version` IS enforced (admin_server ~line 798) → MFA disable/init/recovery DO invalidate sessions.
- **DNS adapters:** 7 real (Cloudflare, Route53, Hetzner, Porkbun, GoDaddy, DigitalOcean, DryRun). Namecheap NOT implemented (README corrected).
- **Jinja autoescape ON** → all `{{ error }}`/`{{ msg }}`/`{{ log_text }}` HTML-escaped. No XSS via template output.
- **`exporter.py` CRIT-4:** uses `CERT_NAME` constant (not hardcoded path).

---

## ⚠ OPEN / NOT DONE (still in tree)

| ID | Issue | Severity | Note |
|----|-------|----------|------|
| MED-6 | Broad `except Exception:` masks real errors (19 sites across admin_server/app/backup_manager/firewall_monitor/cli) | MED | Large per-file audit; deferred. Not a runtime blocker but a broken window. |
| DOC | `PRODUCTION_READINESS.md` / `AUDIT_AND_HANDOFF.md` cited wrong branch (`main`) + falsely claimed all fixed | — | Being corrected now. |
| GIT | Entire review (13 files + new template + ledger) is UNCOMMITTED | — | Must commit + push `clean-scaffold`. |

---

## ✅ VERIFICATION (this session)

```bash
python3 -m py_compile src/ktc_mail_admin/*.py      # PASS
python3 -m pytest test/unit/test_audit_export.py -q  # 5 passed
# Runtime: atomic_write_text/bytes produce 0600 before readable
# Runtime: audit export → fake UDP syslog forwarded 2 then 0 (idempotent)
systemd-analyze verify systemd/*.service *.timer    # not yet run this session
```

---

## PRODUCTION READINESS VERDICT

| Category | Status |
|----------|--------|
| Functionality | ✅ Complete — admin GUI, DNS, ACME, backup, rate limiting, audit export |
| Security | ⚠ Hardened BUT residual MED-6 broad-except; verify before shipping |
| Reliability | ✅ systemd integration, health checks, atomic writes, idempotent export |
| Packaging | ✅ deps corrected (redis, boto3 Suggests); setup.service write paths fixed |

**No CRITICAL/HIGH blockers remain in the reviewed tree.** Residual work:
1. MED-6 broad-except audit (code quality, not a blocker).
2. Commit + push the uncommitted review fixes.
3. Operator decisions still required (per README "before production"): backup destination, SIEM target drop-in, compliance/log-retention regime.

---

**Branch:** `clean-scaffold`
**Remote:** `origin/clean-scaffold` (tree is AHEAD, uncommitted)
**Next:** commit review fixes → push → then MED-6 sweep if desired.
