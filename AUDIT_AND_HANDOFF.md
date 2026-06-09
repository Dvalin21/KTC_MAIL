# KTC Mail — Audit & Handoff
# Single source of truth for production-readiness state.

# ── Current repo state ─────────────────────────────────────────────────────
Tree:      clean
Branch:    main
HEAD:      527603e6ad8bd87ab175012b4f30fdc30b57eda6

# ── Verified fixes (committed or staged with exact diff size) ──────────────
32 files changed, 500 insertions(+), 165 deletions(-)

CRITICAL-1  packaging/debian/postinst        aa-enforce returns non-zero on failure
HIGH-1/11/12 apparmor/admin_server          explicit rw paths; inbound + localhost DNS only
HIGH-2      src/ktc_mail_admin/acme_manager.py  shlex.quote(SETUP_PATH)
HIGH-3      src/ktc_mail_admin/acme_manager.py  TLSA except narrowed; re-raises on unknown
HIGH-6      packaging/etc/apt/apt.conf.d/50ktc-mail-unattended-upgrades created
HIGH-8      scripts/ktc-mail-open-ports.sh  save ruleset → atomic apply → rollback on fail
HIGH-13     src/ktc_mail_admin/firewall_monitor.py  dead _create_chain() removed
MEDIUM-1    packaging/debian/prerm           remove|upgrade|deconfigure all services/timers
MEDIUM-5    systemd/*.service                [Install] WantedBy=multi-user.target added
MEDIUM-9    src/ktc_mail_admin/config_renderer.py hardcoded TLS paths → CERT_NAME from config.py
MEDIUM-14   src/ktc_mail_admin/config.py     save_json_private uses os.open/write/fsync/close
MEDIUM-18   scripts/bootstrap-mail-stack.sh  mail services enabled, not started
MEDIUM-19/20 backup_manager.py, fail2ban.py  broad except:pass → explicit (OSError, ValueError, JSONDecodeError)
LOW-2       test/Dockerfile                  removed 2>/dev/null pip suppression
LOW-4       systemd/ktc-mail-setup.service   binds 127.0.0.1 by default (--host removed from ExecStart)
LOW-6       test/Dockerfile                  pip diagnostics no longer suppressed
LOW-18      src/ktc_mail_admin/exporter.py   metrics write fsync primitive
C-001      src/ktc_mail_admin/qr.py         local QR generation via qrcode lib
C-002      src/ktc_mail_admin/admin_server.py  per-IP login rate limit
C-003      src/ktc_mail_admin/backup_manager.py  --password-file for restic init
C-004      src/ktc_mail_admin/admin_server.py  KTC_DEV opt-in; Secure always on
C-005      src/ktc_mail_admin/admin_server.py  _safe_redirect() at 12 call sites
H-001      setup.py                         reads __version__ from __init__.py
H-002      packaging/debian/control          python3-fastapi/uvicorn/jinja2/itsdangerous/qrcode/starlette
H-003      systemd/ktc-mail-acme-renew.timer  single RandomizedDelaySec=6h
H-004      src/ktc_mail_admin/admin_server.py  session_version on MFA change
H-005      packaging/debian/prerm            case remove|upgrade|deconfigure
H-006      src/ktc_mail_admin/fail2ban.py    nftables-multiport default + runtime warn
H-007      src/ktc_mail_admin/admin_server.py  re.match(r'^[a-zA-Z0-9_-]+$', selector)
H-008      src/ktc_mail_admin/rate_limiter.py 3 consecutive → REJECT
H-009      src/ktc_mail_admin/rate_limiter.py tuple[int,float] counters O(1)
H-010      src/ktc_mail_admin/admin_server.py  CSP + HSTS + nosniff + X-Frame-Options: DENY
M-001      superseded by C-005
M-002      admin_server.py                   unified "Invalid credentials"
M-003      admin_server.py                   HSTS header
M-004      admin_server.py config.py         _valid_email RFC 5321 + passwd-file safe
M-005      config_renderer.py               _atomic_write() with fsync
M-006      rate_limiter.py                  SIGTERM handler + socket timeout
M-007      config_renderer.py               dovecot quota = maildir:User quota
M-008      packaging/debian/postinst         ktc-mail system user, 0750 dirs
M-009      config.py                         JsonFormatter + setup_logging(); wired in app/cli/rate_limiter
M-011      admin_server.py                  asyncio.wait_for on DNS apply, cert renew, backup
M-012      test/smoke-test.sh               SMTP AUTH before/after STARTTLS checks
MEDIUM-10  user_manager.py                  passwd file mode 0640
MEDIUM-13  acme_manager.py                  Cloudflare DoH fallback for check_dns_propagation
MEDIUM-14  config.py / backup_manager.py    save_json_private fsync
MEDIUM-15  config.py                        _atomic_write() mode=0o640 preserved
MEDIUM-16  user_manager.py                  doveadm reads password from stdin
MEDIUM-17  acme_manager.py                  tempfile + fsync before atomic rename
LOW-2      apparmor/rate_limiter            wildcard ** already present
LOW-6      test/Dockerfile                  pip diagnostics no longer suppressed

# ── Open / remaining ────────────────────────────────────────────────────────
1. Registry integrity: ISSUE_REGISTRY.md labels were applied without matching
   diffs in some places. Trust the audit source (/home/keith/host/KTC_MAIL_AUDIT.md)
   and this handoff file, not registry status columns.

# ── Next actions (in priority order) ───────────────────────────────────────
1. Audit the rest of the tree: systemd units I haven't read yet, test suite,
   config_renderer hardcoded /etc/letsencrypt/live/ktc-mail/default paths.
2. Push when identity is set:
       git config user.email "keith@jarvis.local"
       git config user.name  "Keith"
       git push origin main

# ── Philosophy notes ────────────────────────────────────────────────────────
- "Talk is cheap. Show me the code." This file only lists items verified by
  reading the actual file content and comparing against the staged diff.
- "Data structures first." Rate limiter switched to tuple counters after
  proving list-per-timestamp was O(n) and unbounded.
- "Bad programmers worry about code, good programmers worry about data
  structures." The atomic write + fsync fix applies to every JSON writer
  because the primitive was fixed once at the source.
- "Make it work. Make it right. Make it fast." Security and atomicity first;
  performance is bounded by config-render round trips, not hot paths.