# KTC Mail — Audit & Handoff
# Single source of truth for production-readiness state.

# ── Current repo state ─────────────────────────────────────────────
Tree:      CLEAN (LDAP + ClamAV + fts-xapian + .deb packaging fixes committed)
Branch:    clean-scaffold-v2   (local, clean, @ d70d0f9)
Remote:    origin/clean-scaffold-v3  (d70d0f9 — 0 ahead / 0 behind, in sync)
Note:      local `clean-scaffold-v2` IS the pushed `origin/clean-scaffold-v3`.
          They are the same commit under two names; no divergence. The two
          stale `clean-scaffold` + `clean-scaffold-v2` refs retain a historical
          commit whose message has the banned word; force-push is blocked by
          GitHub branch protection. Clean history is already on v3. Delete the
          two stale refs + rename v3 -> v2 when convenient (owner call).

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
PKG2  systemd units + postinst exec'd /usr/lib/ktc-mail/*.py directly, but
      those scripts use relative imports -> ImportError on the target
      (Python 3.11.2). Entire runtime (setup/rate-limit/firewall/acme/ssh)
      was DEAD. ALSO app.py had 3.11-incompatible nested f-strings
      (SyntaxError on target). FIXED (2026-07-10): units now exec
      `ktc-mail <subcommand>` (setup/acme/firewall/rate-limit; added the
      missing rate-limit subcommand); postinst -> `ktc-mail ssh apply`;
      app.py nested f-strings refactored (py_compile clean on 3.11);
      ssh_policy.py SUBPROCESS_TIMEOUT import added + 0755 in package.
      VERIFIED in VM: setup binds, rate-limit runs, firewall --enforce
      applies nftables, ssh apply writes valid sshd drop-in (sshd -t OK).

# ── Feature parity work (bare-metal vs reference Docker suite) ──────
A-1  ClamAV        config_renderer: rspamd antivirus module -> clamd socket.
                  control: +clamav-daemon. Reuses existing milter, no amavis.
                  VERIFIED in VM (renders CLAMAV_VIRUS; clamav Depends install).
A-2  Greylisting   already wired (rspamd milter { greylisting=true } + redis).
B-3  FTS           config_renderer: dovecot fts + fts_xapian plugins;
                  control: +dovecot-fts-xapian. VERIFIED in VM.
C-4  LDAP          config.py: SetupProfile.auth_backend toggle ('passwd_file'|
                  'ldap') + LDAP fields + load_profile(); config_renderer:
                  _dovecot_passdb() selects passdb driver + emits
                  dovecot-ldap.conf.ext (LDAP mode only); user_manager skips
                  passwd-file write under LDAP; control: +dovecot-ldap.
                  VERIFIED in VM (LDAP passdb + conf emitted; build+install OK).
                  OIDC: DEFERRED — Dovecot has no native OIDC; needs external
                  IdP (Keycloak) + OAuth2 proxy. Documented, not stubbed.

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
3. C-4 OIDC — deferred (external IdP required; not Dovecot-native).
4. D-5 Multi-domain + SQL mailbox store — structural epic, needs green-light.
5. BX Prometheus alert rules + Grafana dashboard + OpenAPI — NOT done.
6. See PRODUCTION_ROADMAP.md for the full Critical→Low phased list +
   the reference Docker Compose suite comparison.

# ── Next actions (priority order) ─────────────────────────────────
1. D-5 multi-domain/SQL (or BX observability/API docs — owner's call).
2. (optional) MED-6 broad-except sweep.
3. Resolve GitHub branch naming: delete clean-scaffold + v2, rename v3 -> v2.

# ── Philosophy notes ────────────────────────────────────────────
- "Talk is cheap. Show me the code." Only what was read + run is listed.
- "Surface problems first." Fake-green claims are a broken window.
- Atomic-write fix applied once at source, consumed by every caller.
- Verification lives in a real qemu/kvm Debian 12 VM, not the host.
