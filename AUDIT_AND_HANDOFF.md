# KTC Mail — Audit & Handoff
# Single source of truth for production-readiness state.

# ── Current repo state ─────────────────────────────────────────────
Tree:      DIRTY (review fixes UNCOMMITTED)
Branch:    clean-scaffold
HEAD:      e2ba7a5 (base; working tree has 13 modified + 2 new files AHEAD)
Remote:    origin/clean-scaffold (base only; nothing pushed this session)

> NOTE: an earlier version of this file cited `main`@`527603e` and
> claimed "original 8-phase vision complete, all CRIT/HIGH/MEDIUM fixed".
> That was WRONG. The branch is `clean-scaffold`, and the line-by-line
> review on 2026-07-09 found REAL unfixed bugs. This rewrite is
> accurate as of 2026-07-09 (before the pending commit).

# ── Verified fixes this session (2026-07-09) ───────────────────
Commit scope below is NOT yet committed — these are working-tree edits.

THEME  config.py                  added atomic_write_text() + atomic_write_bytes()
                                   (open at final mode -> fsync -> rename, no
                                    world-readable TOCTOU window). Routed 7
                                    write_text+chmod sites through them.
CRIT    admin_server.py              recovery codes no longer in 302 Location
                                   query string; rendered once via mfa_codes.html.
HIGH    admin_server/app.py/         DKIM private key written atomic 0600
        config_renderer.py          (was write_bytes+chmod race).
HIGH    systemd/ktc-mail-setup.service  ProtectSystem=full + ReadWritePaths
                                   now lists real mail-config dirs
                                   (/etc/postfix /etc/dovecot /etc/nginx
                                    /etc/rspamd /etc/sogo /etc/ssh
                                    /etc/letsencrypt /etc/ssl) — wizard
                                   was EROFS-ing at "Write mail configs".
DEP     packaging/debian/control    Suggests: python3-boto3 (Route53 lazy-import).
DEP     scripts/bootstrap-mail-stack.sh  dropped unused python3-venv.
WIRING  packaging/debian/postinst   ktc-mail-audit-export.timer now enabled.
WIRING  systemd/ktc-mail-audit-export.service  removed footgun blank
                                   Environment= line; documents drop-in.

# ── Already implemented + verified (was falsely marked missing) ──
- Remote audit export (syslog UDP/TCP/TLS + SIEM JSON): audit_export.py
  + cli `ktc-mail audit export` + systemd service/timer. Integration
  verified this session (fake UDP listener: 2 forwarded, 2nd run 0).
- Recovery codes + break-glass (Phase 5): mfa.py / breakglass.py / admin routes.
- session_version enforced -> MFA change invalidates sessions.
- 7 DNS adapters real; Namecheap not implemented (README corrected).
- Jinja autoescape ON -> template output HTML-escaped.

# ── Open / remaining ──────────────────────────────────────────────
1. MED-6 broad `except Exception:` (19 sites) — deferred audit, not a runtime blocker.
2. Working tree UNCOMMITTED — must commit + push clean-scaffold.
3. Operator decisions still required (README "before production"):
   backup destination, SIEM target drop-in, compliance/log-retention.

# ── Next actions (in priority order) ──────────────────────────────
1. Commit review fixes on clean-scaffold:
       git add -A && git commit -m "review: atomic writes, DKIM/setup hardening, docs"
       git push origin clean-scaffold
2. (optional) MED-6 broad-except sweep.
3. Verify systemd units parse: systemd-analyze verify systemd/*.service *.timer

# ── Philosophy notes ────────────────────────────────────────────
- "Talk is cheap. Show me the code." This file lists only what was
  verified by reading the actual file + running the code this session.
- "Surface problems first." The prior green claims were a broken window;
  this rewrite removes the fake-green.
- Atomic-write fix applied once at the source (config.py helpers) and
  consumed by every caller — deletion over addition.
