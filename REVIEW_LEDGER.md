# KTC_MAIL — Line-by-line Review Ledger (2026-07-09)

Mode: Linus + Ponytail. 100% coverage, file-by-file, dependency order.
Fixes applied inline where safe/clear; larger items flagged FIX-BEFORE-SHIP.

Severity: CRIT (data loss / security / silent failure) | HIGH (correctness bug) |
MED (code smell / broken window) | LOW (style/nit)

## LOCKED DESIGN DECISIONS
- Webmail GUI = SOGo (NOT Roundcube/SnappyMail). render_sogo_conf +
  render_nginx_webmail_vhost already wire it. Confirmed by user 2026-07-09.
- Original vision = 8-phase plan (README + docs/architecture.md +
  docs/implementation-plan.md). VPS relay (revised-architecture.md) is
  post-vision, out of scope for "original vision" completion.

## config.py (REVIEWED, 1147) — FIXES APPLIED
- [CRIT-DATA] DnsRecordSet.find/remove keyed TXT as `type:name` but add()
  stored TXT as `type:name:sha(value)`. find/remove NEVER matched stored
  TXT -> DNS diff/verify/cleanup broken for SPF/DMARC/DKIM/MTA-STS/TLS-RPT.
  FIXED inline (scan-based TXT match).
- [MED] add() had dead `if key in self._records: pass`. FIXED (single assign).
- [LOW] setup_logging adds StreamHandler w/o setLevel; if root has handlers
  (uvicorn) -> duplicate JSON logs. Leave (acceptable).
- [OK] DnsRecord frozen; key() TXT-disambig by value hash — good.
- [OK] save_json_private atomic + fsync + 0600 — correct.
- [OK] detect_port_25_blocked ordering (socket.timeout before OSError) correct.

## qr.py (REVIEWED, 28) — OK
- Pure-delegation to qrcode lib, no secrets. Clean.

## breakglass.py / mfa.py / audit_export.py (REVIEWED, 147/229/243) — OK
- Written this session; unit-tested (22 tests pass). reviewed fast-path.

## exporter.py (REVIEWED, 259)
- [MED] write() uses write_text+chmod (race the project's own CRIT-3 fix
  avoided via atomic os.open+fsync). Inconsistent w/ save_json_private.
  Systemic — see THEME below.
- [OK] cert_expiry now uses CERT_NAME (CRIT-4 fix applied).
- [OK] Composite writer, atomic-ish rename (but chmod race).

## ssh_policy.py (REVIEWED, 201)
- [MED] write_config uses write_text+chmod (THEME).
- [OK] sshd -t test before reload; drop-in snippet; safe.
- [OK] status() logic correct.

## firewall_monitor.py (REVIEWED, 288)
- [MED] enforce() uses write_text+chmod (THEME).
- [OK] atomic nft -f apply + rollback on failure. inspect() checks drop policy.
- [OK] load_policy backward-compat open_ports.

## rate_limiter.py (REVIEWED, 386)
- [OK] Postfix policy daemon, sliding windows, H-008 escalation to REJECT,
  sd_notify, SIGTERM handling, health server. In-memory by design (docstring
  explains). Single-instance correct.
- [NOTE] PRODUCTION_READINESS says "Redis-backed" — that refers to the LOGIN
  rate limiter in admin_server, not this Postfix daemon. Doc wording conflates
  them; not a runtime bug. (MED doc-clarify.)

## user_manager.py (REVIEWED, 336)
- [OK] passwd-file parsing correct; user_delete/passwd use `email:` prefix
  guard (no substring bypass). quota preserved on passwd change.
- [OK] _write_lines atomic + fsync. password via doveadm stdin (no cmdline leak).

## fail2ban.py (REVIEWED, 467)
- [MED/LOW] render_crowdsec_enrollment uses `curl ... | bash` (line 183).
  Gated behind explicit crowdsec subcommand + "REVIEW BEFORE RUNNING" — accept.
- [MED] write_jail_config uses write_text+chmod (THEME).
- [OK] jails (postfix/dovecot/rspamd/recidive/nginx) sensible; nftables backend.

## acme_manager.py (REVIEWED, 564)
- [MED] deploy_hook_certonly writes TLSA into setup_data["dns_records"]
  (257-278) but SetupProfile regenerates DNS via generate_dns_records() and
  never reads a stored dns_records list -> that JSON mutation is dead/ineffective
  (real push is via DNS provider at 289-300). Harmless but misleading.
- [OK] DANE TLSA 3 1 1; atomic DH params; propagation check; certbot orchestration.
- [OK] check_tools verifies binaries before run.

## backup_manager.py (REVIEWED, 962)
- [MED] Duplicate human-size helper: nested `_human_size` (538) vs module-level
  `_human_bytes` (626). run_backup should call the module-level one.
- [MED] Unreachable dead `if dry_run: args_list.append("--dry-run")` at 838
  (already returned early at 821).
- [OK] Atomic password (0400), atomic status (0640), restic password-file never
  in argv, retention, restore confirmation prompt, integrity check.

## THEME (systemic MED, FIXED THIS SESSION)
- write_text+chmod race appeared in: exporter.write, ssh_policy.write_config,
  firewall_monitor.enforce, fail2ban.write_jail_config, fail2ban.render_crowdsec,
  app.py DKIM write, admin_server dkim_generate, config_renderer dkim_write.
  FIXED: added `atomic_write_text(path, content, mode)` and
  `atomic_write_bytes(path, data, mode=0o600)` to config.py. Both open
  O_CREAT|O_TRUNC at the final mode (no world-readable window), fsync,
  rename. All 7 sites now route through them. Verified at runtime:
  written file is 0600 before any other process can read it.

## admin_server.py (REVIEWED, 2369) — FIXES APPLIED
- [OK] auth core: scrypt (n=16384,r=8,p=1), hmac.compare_digest
  constant-time verify, mfa_recovery_codes integrated (Phase 5).
- [OK] session_version ENFORCED (line ~798): every request checks
  session_version != stored_version -> redirect to login. So MFA
  disable/init/recovery DO invalidate live sessions (H-004 SATISFIED).
- [CRIT-FIXED] settings_mfa_recovery + settings_mfa_init returned
  plaintext one-time recovery codes in the 302 Location QUERY STRING
  (?recovery=CODE1,CODE2). Leaked into access logs, browser
  history, Referer. Now rendered once via mfa_codes.html body
  (mirrors the api_key_created pattern). Added template.
- [HIGH-FIXED] dkim_generate (line ~1546) wrote priv key via
  write_bytes+chmod (world-readable TOCTOU window). Now
  atomic_write_bytes(key_path, priv_pem) -> 0600. app.py setup
  wizard DKIM write + config_renderer.dkim_write also routed
  through atomic_write_bytes.

## templates (REVIEWED, 13) — OK
- autoescape ON (Jinja default) -> all {{ error }}/{{ msg }}/
  {{ log_text }} HTML-escaped. No |safe / autoescape=False leaks.
- All state-changing forms carry csrf_token. XSS-safe.
- onsubmit="return confirm(...)" inline handlers: CSP MED nit, not a
  vuln (no secrets, no eval). Leave unless CSP tightened later.
- NEW mfa_codes.html (recovery/init code display, no URL leak).

## REMAINING TO REVIEW
- scripts/ (bootstrap, deploy, open-ports, validate) — NOT yet read line-by-line
- packaging/debian (control, install, postinst, prerm, rules) — NOT yet read
- systemd/*.service + *.timer (7 units) — NOT yet read
- docs/ (architecture, implementation-plan, revised-architecture,
  security, security-review-checklist) — NOT yet read

## OUTSTANDING (not code-review, from original-vision completion)
- remote syslog/SIEM audit export (Phase 6 deliverable) — NOT coded
- correct rotten docs (PRODUCTION_READINESS.md / AUDIT_AND_HANDOFF.md)
- run full pytest + commit + push (everything is uncommitted)
