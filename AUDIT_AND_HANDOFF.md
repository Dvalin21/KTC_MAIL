# KTC Mail — Audit & Handoff
# Single source of truth for production-readiness state.

# ── Current repo state ─────────────────────────────────────────────
Tree:      CLEAN (all review + parity work committed + pushed)
Branch:    clean-scaffold-v2   (mailcow-free history; see NOTE)
HEAD:      ab1de47
Remote:    origin/clean-scaffold-v2 (ab1de47 present)

> NOTE: the word "mailcow" is banned from this project (code, docs,
> commits, GitHub) per owner directive. All docs use the neutral
> descriptor "the reference Docker Compose mail suite". The original
> `clean-scaffold` branch still contains a historical commit whose
> message has the banned word; it could not be force-pushed (GitHub
> branch protection blocked it). `clean-scaffold-v2` is the clean
> replacement. Delete `clean-scaffold` + rename `v2` when convenient.

# ── Verified fixes (this review cycle) ─────────────────────────────
THEME   config.py                 atomic_write_text/bytes() (open final mode
                                 -> fsync -> rename, no TOCTOU window).
                                 urs: 7 write_text+chmod sites routed through.
CRIT    admin_server.py           recovery codes no longer in 302 Location;
                                 rendered once via mfa_codes.html.
HIGH    admin_server/app.py/       DKIM key written atomic 0600.
        config_renderer.py
HIGH    systemd/ktc-mail-setup.service  ProtectSystem=full ReadWritePaths
                                 lists real mail-config dirs (was EROFS).
PKG     debian/* (7 fixes)        .deb now builds + installs + units run:
                                 - install -> ktc-mail.install (debhelper
                                   ignored the bare name)
                                 - added debian/changelog
                                 - control: python3-setuptools Build-Depends
                                 - rules: --buildsystem=pybuild +
                                   exec-bit override for service .py scripts
                                 - ktc-mail.install: ship audit-export
                                   units (postinst enables the timer)
                                 - postinst: /var/lib/ktc-mail 0770
                                 - setup.py: console_scripts -> /usr/bin/ktc-mail
                                 VERIFIED by build+install in qemu/kvm
                                 Debian 12 VM (systemd-analyze verify clean,
                                 metrics/audit subcommands run as ktc-mail).

# ── Feature parity work (bare-metal vs reference Docker suite) ──────
A-1  ClamAV        config_renderer: rspamd antivirus module -> clamd socket.
                  control: +clamav-daemon. Reuses existing milter, no amavis.
                  VERIFIED in VM (renders CLAMAV_VIRUS; clamav Depends install).
A-2  Greylisting   already wired (rspamd milter { greylisting=true } + redis).
B-3  FTS           config_renderer: dovecot fts + fts_xapian plugins;
                  control: +dovecot-fts-xapian. VERIFIED in VM.

# ── Already implemented + verified (was falsely marked missing) ──
- Remote audit export: audit_export.py + cli + systemd + 5 unit tests.
  Integration verified (fake UDP: 2 forwarded, 2nd run 0).
- Recovery codes + break-glass; session_version enforced.
- 7 DNS adapters real; Namecheap stub by design.
- Jinja autoescape ON.

# ── Open / remaining ──────────────────────────────────────────────
1. MED-6 broad `except Exception:` (19 sites) — deferred, not a blocker.
2. Operator decisions (README "before production"): backup destination,
   SIEM target drop-in, compliance/log-retention.
3. C-4 OIDC/LDAP auth backend — NOT done.
4. D-5 Multi-domain + SQL mailbox store — structural epic, needs green-light.
5. BX Prometheus alert rules + Grafana dashboard + OpenAPI — NOT done.
6. See PRODUCTION_ROADMAP.md for the full Critical→Low phased list +
   the reference Docker Compose suite comparison.

# ── Next actions (priority order) ─────────────────────────────────
1. C-4 OIDC/LDAP (or D-5 multi-domain/SQL — owner's call).
2. (optional) MED-6 broad-except sweep.
3. Resolve clean-scaffold vs clean-scaffold-v2 branch naming on GitHub.

# ── Philosophy notes ────────────────────────────────────────────
- "Talk is cheap. Show me the code." Only what was read + run is listed.
- "Surface problems first." Fake-green claims are a broken window.
- Atomic-write fix applied once at source, consumed by every caller.
- Verification lives in a real qemu/kvm Debian 12 VM, not the host.
