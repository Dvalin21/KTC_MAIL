# KTC Mail — Audit & Handoff
# Single source of truth for production-readiness state.

# ── Current repo state ─────────────────────────────────────────────
Tree:      CLEAN (all roadmap items H-1.1 → D-5 committed)
Branch:    clean-scaffold-v2   (local, clean, @ 97d8a42)
Remote:    origin/clean-scaffold-v3  (97d8a42 — 0 ahead / 0 behind, in sync)
Note:      local `clean-scaffold-v2` IS the pushed `origin/clean-scaffold-v3`.
          They are the same commit under two names; no divergence. The two
          stale `clean-scaffold` + `clean-scaffold-v2` refs retain a historical
          commit whose message has the banned word; force-push is blocked by
          GitHub branch protection. Clean history is already on v3. Delete the
          two stale refs + rename v3 -> v2 when convenient (owner call).

# ── Verified fixes (this review cycle, real Debian 12 qemu/kvm VM) ──
THEME   config.py                 atomic_write_text/bytes() (open final mode
                                 -> fsync -> rename, no TOCTOU). 7 sites routed.
CRIT    admin_server.py           recovery codes no longer in 302 Location;
                                 rendered once via mfa_codes.html.
HIGH    admin_server/app.py/       DKIM key written atomic 0600.
        config_renderer.py
HIGH    systemd/ktc-mail-setup.service  ProtectSystem=full ReadWritePaths
                                 lists real mail-config dirs (was EROFS).
PKG     debian/* (7 fixes)        .deb builds + installs + units run. VERIFIED
                                 by build+install in qemu/kvm Debian 12 VM.
PKG2  systemd units + postinst exec'd /usr/lib/ktc-mail/*.py (relative
      imports -> ImportError on 3.11.2, entire runtime DEAD). app.py had
      3.11-incompatible nested f-strings. FIXED: units exec `ktc-mail
      <subcommand>`; app.py refactored; ssh_policy SUBPROCESS_TIMEOUT import
      + 0755. VERIFIED in VM.
M-2.3 AppArmor                  8 named role profiles + systemd AppArmorProfile=;
                                 added ktc-mail-admin.service; tmpfiles.d;
                                 postinst FAILS LOUDLY if zero profiles load.
                                 VERIFIED: 8 ktc-mail.* enforced; live daemon
                                 reads ktc-mail.rate-limit (enforce); nft/certbot
                                 denied under their roles.
C-0.3 backup                    SUBPROCESS_TIMEOUT import added; empty-password
                                 crash fixed (auto-gen 32-byte pw); `backup
                                 set --enable` refuses with no repo. VERIFIED.
H-1.1 integration               Unit 22/22 on 3.11; render_all 11 cfgs; live
                                 SMTP banner/STARTTLS/AUTH-gating PASS; Dovecot
                                 IMAPS :993 UP. Caught+fixed: vmail user missing
                                 in postinst (added, both trees).
H-1.4 restore drill             `backup restore` was interactive; added --yes.
                                 VERIFIED: restore recovered files; restic check
                                 clean.
H-1.2 audit export              no-target run now logs explicit warning (not
                                 silent no-op).
H-1.3 DNS                       Namecheap/Route53 raise clear DnsError;
                                 python3-boto3 Suggests->Recommends.
M-2.2 exporter                  opt-in node_exporter textfile drop-in shipped
                                 (not auto-enabled); metrics format verified
                                 parseable.
D-5 multi-domain                SetupProfile.domains + mailbox_store +
                                 all_domains; renderers emit multi-domain
                                 virtual_mailbox_domains + nginx alias
                                 redirects; sql store fail-honest (keeps
                                 maildir, warns). 6 new unit tests.

# ── Feature parity work (bare-metal vs reference Docker suite) ──────
A-1  ClamAV        rspamd antivirus -> clamd socket; control +clamav-daemon.
A-2  Greylisting   rspamd milter { greylisting=true } + redis.
B-3  FTS           dovecot fts + fts_xapian; control +dovecot-fts-xapian.
C-4  LDAP          SetupProfile.auth_backend toggle + LDAP fields +
                  _dovecot_passdb() selects driver + emits dovecot-ldap.conf.ext
                  (LDAP mode only); user_manager skips passwd write under LDAP;
                  control +dovecot-ldap. OIDC: DEFERRED (external IdP + OAuth2
                  proxy). Documented, not stubbed.
D-5  Multi-domain  profile + renderers done. SQL passdb/db + schema + Dovecot
                  SQL dict wiring remain a deep epic (documented extension
                  point, not faked). maildir fully supported.

# ── Already implemented + verified (was falsely marked missing) ──
- Remote audit export: audit_export.py + cli + systemd + 5 unit tests.
  Integration verified (fake UDP: 2 forwarded, 2nd run 0).
- Recovery codes + break-glass; session_version enforced.
- 7 DNS adapters real; Namecheap stub raises clear error.
- Jinja autoescape ON; exporter uses CERT_NAME constant.
- AppArmor: 8 named role profiles ENFORCED.

# ── Open / remaining (honest) ─────────────────────────────────────
1. OPERATOR: backup backend (C-0.3) — run `ktc-mail backup init <url>`.
2. OPERATOR: SIEM/syslog target drop-in (H-1.2).
3. OPERATOR: DNS provider API token (H-1.3).
4. OPERATOR: full real-domain smoke test (H-1.1) — DKIM/DMARC/SPF, DNS
   push->verify, admin MFA login. Needs domain + ACME cert + DNS.
5. DEEP: multi-domain SQL mailbox store (D-5 extension point).
6. DEEP: OIDC auth (C-4 deferred — external IdP required).
7. DEEP: ActiveSync / mobile (SOGo EAS not wired).
8. MED-6 broad `except Exception:` — reviewed (M-2.1), judged legitimate
   per-site patterns, NOT silent swallows. Closed as no-change.
9. See PRODUCTION_ROADMAP.md (all items H-1.1→D-5 CLOSED) + the reference
   Docker Compose suite comparison in PRODUCTION_READINESS.md.

# ── Next actions (priority order) ─────────────────────────────────
1. OPERATOR INPUT only: backup backend, SIEM target, DNS token, real-domain
   smoke test.
2. (optional, deep) SQL mailbox store / OIDC / ActiveSync.
3. Resolve GitHub branch naming: delete clean-scaffold + v2, rename v3 -> v2.

# ── Philosophy notes ────────────────────────────────────────────
- "Talk is cheap. Show me the code." Only what was read + run is listed.
- "Surface problems first." Fake-green claims are a broken window.
- Verification lives in a real qemu/kvm Debian 12 VM on Python 3.11.2, not
  the host (host is 3.13; target parse-gap is real — py_compile on 3.11).
- No silent lies: sql mailbox store warns + keeps maildir; audit export
  warns on no target; backup refuses enable-without-repo.
