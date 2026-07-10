# KTC Mail — Audit & Handoff
# Single source of truth for production-readiness state.

# ── Current repo state ─────────────────────────────────────────────
Tree:      CLEAN (committed at 237debd; pushed to origin/clean-scaffold)
Branch:    clean-scaffold
HEAD:      237debd
Remote:    origin/clean-scaffold (237debd present)

> NOTE: a prior version of this file claimed DIRTY / UNCOMMITTED
> and cited `main`@527603e / `ed8afd7`. Both WRONG. The tree
> was committed + pushed at `237debd` this session. This rewrite is
> accurate as of 2026-07-09 (post commit).

# ── Verified fixes (committed at 237debd) ───────────────────
THEME  config.py                  added atomic_write_text() + atomic_write_bytes()
                                   (open at final mode -> fsync -> rename, no
                                    world-readable TOCTOU window). Routed 7
                                    write_text+chmod sites through them.
CRIT    admin_server.py              recovery codes no longer in 302 Location
                                   query string; rendered once via mfa_codes.html.
HIGH    admin_server/app.py/         DKIM private key written atomic 0600
        config_renderer.py          (was write_bytes+chmod race).
HIGH    systemd/ktc-mail-setup.service  ProtectSystem=full ReadWritePaths
                                   now lists real mail-config dirs
                                   (/etc/postfix /etc/dovecot /etc/nginx
                                    /etc/rspamd /etc/sogo /etc/ssh
                                    /etc/letsencrypt /etc/ssl) — wizard
                                   was EROFS-ing at "Write mail configs".
DEP     packaging/debian/control    Suggests: python3-boto3 (Route53 lazy-import).
DEP     scripts/bootstrap-mail-stack.sh  dropped unused python3-venv.
WARNING  packaging/debian/postinst   ktc-mail-audit-export.timer now enabled.
WARNING  systemd/ktc-mail-audit-export.service  removed footgun blank
                                   Environment= line; documents drop-in.

# ── Already implemented + verified (was falsely marked missing) ──
- Remote audit export (syslog UDP/TCP/TLS + SIEM JSON): audit_export.py
  + cli `ktc-mail audit export` + systemd service/timer. Integration
  verified this session (fake UDP listener: 2 forwarded, 2nd run 0).
- Recovery codes + break-glass (Phase 5): mfa.py / breakglass.py / admin routes.
- session_version enforced -> MFA change invalidates sessions.
- 7 DNS adapters real; Namecheap not implemented (README corrected).
- Jinja autoescape ON -> template output HTML-escaped.
- `exporter.py` CRIT-4: uses `CERT_NAME` constant.

# ── Open / remaining ──────────────────────────────────────────────
1. MED-6 broad `except Exception:` (19 sites) — deferred audit, not a runtime blocker.
2. Operator decisions still required (README "before production"):
   backup destination, SIEM target drop-in, compliance/log-retention.
3. See PRODUCTION_READINESS.md "Production Roadmap" for the full
   Critical→Low phased list + the mailcow comparison.

# ── Next actions (in priority order) ──────────────────────────────
1. Build + install the .deb in a throwaway VM (C-0.1) — the only
   thing between "code works" and "server ships".
2. (optional) MED-6 broad-except sweep.
3. Verify systemd units parse: systemd-analyze verify systemd/*.service *.timer

# ── Philosophy notes ────────────────────────────────────────────
- "Talk is cheap. Show me the code." This file lists only what was
  verified by reading the actual file + running the code this session.
- "Surface problems first." Prior green claims were a broken window;
  this rewrite removes the fake-green.
- Atomic-write fix applied once at the source (config.py helpers) and
  consumed by every caller — deletion over addition.
