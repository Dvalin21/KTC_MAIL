# KTC Mail — Production Readiness Issue Registry

**Purpose**: Living document tracking every bug, design issue, security concern,
and missing feature between current state (0.2.0) and production readiness.

**How to use**: Each issue has a unique ID, severity rating, and fix direction.
Status starts as `🔴 open`. As items are addressed, update status to `🟡 in_progress`,
`🟢 fixed`, or `⚪ deferred`. New issues found during implementation should be
appended — the registry is the single source of truth, not a closed list.

**Last updated**: 2026-05-30

---

## Severity Key

| Mark | Meaning | Expected timeline |
|------|---------|-------------------|
| **C** | **CRITICAL** — Security vulnerability or data-loss risk | Before any production deployment |
| **H** | **HIGH** — Breaks functionality, violates principle, or causes incorrect behavior | Before 1.0.0 |
| **M** | **MEDIUM** — Degrades reliability, observability, or maintainability | Before 1.0.0 or shortly after |
| **L** | **LOW** — Polish, documentation, or minor technical debt | Post-1.0 or as time permits |
| **O** | **OBSERVATION** — Not a bug but worth noting for architectural awareness | No action required |

---

## Registry

---

### C-001: TOTP QR code leaks secret to third-party API

| Field | Value |
|-------|-------|
| **Area** | Security — Admin Web GUI |
| **File** | `src/ktc_mail_admin/templates/settings.html` |
| **Line** | 67 |
| **Severity** | **C — CRITICAL** |
| **Status** | 🟢 fixed |
| **Discovered** | Code review 2026-05-29 |
| **Root cause** | QR code image is fetched from `https://api.qrserver.com/v1/create-qr-code/…` with the `otpauth_uri` (which contains the raw TOTP secret) encoded in the URL query parameter |

```html
<img src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&data={{ mfa.otpauth_uri | urlencode }}"
     alt="QR Code" style="width:180px;height:180px;border-radius:0.5rem">
```

**Impact**: Every time the admin configures MFA, the TOTP shared secret is
transmitted to a third-party CDN (`api.qrserver.com`). This completely defeats
the purpose of MFA — an attacker who monitors that service's logs obtains
the raw secret and can generate valid TOTP codes.

**Fix**: Generate QR codes locally. Options:
1. Add `qrcode` Python library and render the QR as a PNG data URI
2. Call `qrencode` CLI and serve the image locally
3. Use a JavaScript QR library like `qrcodejs` bundled with the app

**Do NOT** use any external QR generation API.

---

### C-002: Login endpoint has no rate limiting

| Field | Value |
|-------|-------|
| **Area** | Security — Admin Web GUI |
| **File** | `src/ktc_mail_admin/admin_server.py` |
| **Lines** | 730–774 |
| **Severity** | **C — CRITICAL** |
| **Status** | 🟢 fixed |
| **Discovered** | Code review 2026-05-29 |
| **Root cause** | `POST /login` validates credentials without any per-IP rate limiting. An attacker can brute-force the admin password over the network with no slowdown. |

**Impact**: Unauthenticated remote attacker can brute-force admin credentials.
Rate of attack is limited only by network latency and server response time.

**Fix**:
1. Add in-memory per-IP rate limiting: 5 failed attempts → 60-second lockout
2. Log all failed attempts with IP, timestamp, and username tried
3. Optionally trigger Fail2ban integration for repeated brute-force across hours

---

### C-003: Restic backup password leaked via process environment

| Field | Value |
|-------|-------|
| **Area** | Security — Backup |
| **File** | `src/ktc_mail_admin/backup_manager.py` |
| **Lines** | 328–335 |
| **Severity** | **C — CRITICAL** |
| **Status** | 🟢 fixed |
| **Discovered** | Code review 2026-05-29 |
| **Root cause** | `init_repository()` called `restic init` with the password piped via stdin (`input=password + "\n"`) instead of using the already-available `--password-file` path. While `_restic()` and `_restic_nonjson()` correctly use `--password-file`, the init path still passed the secret through the child process input stream. |

**Impact**: The password was present in the `restic` child process's stdin buffer,
observable via `/proc/PID/fd/0` or by tracing syscalls.

**Fix**: Switch `init_repository()` to use `--password-file` with the
`RESTIC_PASSWORD_PATH` file that `write_password()` already creates (mode `0400`).
No environment variable was ever used — `_restic()` and `_restic_nonjson()`
already use `--password-file` correctly.

---

### C-004: Session cookie Secure flag can be disabled via env var

| Field | Value |
|-------|-------|
| **Area** | Security — Admin Web GUI |
| **File** | `src/ktc_mail_admin/admin_server.py` |
| **Lines** | 597–604 |
| **Severity** | **C — CRITICAL** |
| **Status** | 🟢 fixed |
| **Discovered** | Code review 2026-05-29 |
| **Root cause** | `SessionMiddleware` used `KTC_SESSION_HTTPS` env var to toggle `https_only`. If set to `0`, the session cookie's `Secure` flag was removed. Starlette **does** hardcode `HttpOnly` and `SameSite=lax` in all cases — the `HttpOnly` concern was a false alarm. |

**Impact**: In a mixed HTTP/HTTPS deployment (e.g., TLS-terminating proxy
forwarding HTTP to the app), setting `KTC_SESSION_HTTPS=0` removes `Secure`,
allowing the session cookie to be sent over unencrypted connections.

**Fix**: 
1. Replaced `KTC_SESSION_HTTPS` env toggle with `KTC_DEV=1` flag (opt-in for local HTTP testing)
2. `Secure` flag is now **always on** by default — fail-closed
3. `HttpOnly` and `SameSite=lax` were already correct in Starlette's middleware implementation
4. No change needed to `samesite` or `httponly` — both are hardcoded in Starlette's security flags string

---

### C-005: Redirect URLs contain user-controlled data unescaped

| Field | Value |
|-------|-------|
| **Area** | Security — Admin Web GUI |
| **File** | `src/ktc_mail_admin/admin_server.py` |
| **Lines** | 949, 955, 983, 989, 1018, 1274, 1381, 1390, 1446, 1506, 1551, 1625 |
| **Severity** | **C — CRITICAL** |
| **Status** | 🟢 fixed |
| **Discovered** | Code review 2026-05-29 |
| **Root cause** | Redirect URLs are built with f-strings embedding user-controlled values (email addresses, exception messages) without URL-encoding: `url=f"/users?msg=Added+{email}"`. |

**Impact**: An attacker who controls a value that gets embedded in a redirect
URL (e.g., an email address like `attacker@example&status=compromised`) can
inject arbitrary query parameters, enabling response splitting or phishing via
redirect manipulation.

**Fix**: Added `_safe_redirect()` helper that uses `urllib.parse.urlencode()`
and replaced all 12 f-string redirect sites. The helper properly percent-encodes
every query parameter value, preventing parameter injection and response splitting.

---

### H-001: Version drift between setup.py and __init__.py

| Field | Value |
|-------|-------|
| **Area** | Build / Packaging |
| **Files** | `setup.py` (line 5), `src/ktc_mail_admin/__init__.py` (line 3) |
| **Severity** | **H — HIGH** |
| **Status** | 🟢 fixed |
| **Discovered** | Code review 2026-05-29 |
| **Root cause** | `setup.py` says `version="0.3.0"`, `__init__.py` says `__version__ = "0.2.0"`. One of these is wrong. |

**Impact**: Package metadata and runtime version disagree. Monitoring systems
and upgrade tools cannot reliably determine the installed version.

**Fix**: `setup.py` now reads `__version__` from `__init__.py` via `_get_version()`. Single source of truth — no more drift.

---

### H-002: Python dependencies not listed in Debian control file

| Field | Value |
|-------|-------|
| **Area** | Packaging |
| **Files** | `packaging/debian/control`, `setup.py` |
| **Severity** | **H — HIGH** |
| **Status** | 🟢 fixed |
| **Discovered** | Code review 2026-05-29 |
| **Root cause** | `setup.py` requires `fastapi`, `uvicorn`, `jinja2`, `itsdangerous` via pip. The `.deb` control file does NOT list these as dependencies. After `.deb` install, the admin server will fail to start with `ModuleNotFoundError`. |

**Impact**: `.deb` install completes but admin GUI is non-functional.

**Fix**: Added `python3-fastapi`, `python3-uvicorn`, `python3-jinja2`, `python3-itsdangerous`, `python3-qrcode`, `python3-starlette` to the Debian control file's `Depends` list.

---

### H-003: ACME timer has duplicate RandomizedDelaySec

| Field | Value |
|-------|-------|
| **Area** | Operations — Systemd |
| **File** | `systemd/ktc-mail-acme-renew.timer` |
| **Lines** | 7–8 |
| **Severity** | **H — HIGH** |
| **Status** | 🟢 fixed |
| **Discovered** | Code review 2026-05-29 |
| **Root cause** | Two `RandomizedDelaySec` directives: `6h` then `45m`. The second overrides the first, so effective delay is 45 minutes, not 6 hours. |

```ini
[Timer]
OnCalendar=daily
RandomizedDelaySec=6h
RandomizedDelaySec=45m    # ← overrides the line above
Persistent=true
```

**Impact**: Cert renewal runs with a 45-minute random delay instead of the
intended 6-hour spread. On large deployments, this causes a thundering-herd
against Let's Encrypt at approximately 00:45 every morning.

**Fix**: Removed duplicate `RandomizedDelaySec=45m`. Kept `RandomizedDelaySec=6h` as intended.

---

### H-004: MFA disable does not invalidate existing sessions

| Field | Value |
|-------|-------|
| **Area** | Security — Admin Web GUI |
| **File** | `src/ktc_mail_admin/admin_server.py` |
| **Line** | 1164–1167 |
| **Severity** | **H — HIGH** |
| **Status** | 🟢 fixed |
| **Discovered** | Code review 2026-05-29 |
| **Root cause** | When MFA is disabled, the admin account's `mfa_enabled` is set to `False`, but existing authenticated sessions are not invalidated. A session that was created when MFA was active remains valid. |

**Impact**: If an admin disables MFA (e.g., "I'll set it up again later"), any
attacker who has stolen the session cookie retains access even after the
security policy is downgraded.

**Fix**: Added `session_version` counter to admin account. Incremented on MFA enable/disable/init. `is_authenticated()` checks that the session's `session_version` matches the stored account version. On mismatch, the session is cleared — forcing re-login.

---

### H-005: Pre-removal script does not handle upgrades

| Field | Value |
|-------|-------|
| **Area** | Packaging |
| **File** | `packaging/debian/prerm` |
| **Lines** | 1–6 |
| **Severity** | **H — HIGH** |
| **Status** | 🟢 fixed |
| **Discovered** | Code review 2026-05-29 |
| **Root cause** | `prerm` only handles `remove` action. When the package is upgraded, `prerm` is called with `upgrade` but the script does nothing, leaving old services running during the install of the new package. |

```bash
if [[ "${1:-}" = remove ]]; then
  systemctl disable --now ... 2>/dev/null || true
fi
```

**Impact**: On upgrade, old systemd unit files remain active until the
postinst runs. If the new package renames or removes a service, the old
service continues running.

**Fix**: Changed from `if [[ "${1:-}" = remove ]]` to `case "${1:-}" in remove|upgrade|deconfigure)`. Now services are stopped before upgrade and re-enabled by postinst.

---

### H-006: Fail2ban jail action uses iptables-multiport instead of nftables

| Field | Value |
|-------|-------|
| **Area** | Configuration — Fail2ban |
| **File** | `src/ktc_mail_admin/fail2ban.py` |
| **Lines** | 83, 89 |
| **Severity** | **H — HIGH** |
| **Status** | 🟢 fixed |
| **Discovered** | Code review 2026-05-29 |
| **Root cause** | The fail2ban jail template defaults to `action = nftables-multiport` (line 89), but the generated jails may use iptables if fail2ban is configured that way system-wide. There is no explicit verification that fail2ban is using the nftables backend. |

**Impact**: On systems where iptables is not present (clean Debian 12+ with
nftables only), fail2ban bans silently fail because the iptables commands
don't work. The ban is recorded in fail2ban's counters but no actual firewall
rule is added.

**Fix**: Template already defaults to `action = nftables-multiport`. Added a runtime
check in `cmd_check()` that warns if fail2ban is using an iptables-based action.
Config generation always emits `nftables-multiport` explicitly.

---

### H-007: DKIM selector injection in file path

| Field | Value |
|-------|-------|
| **Area** | Security — Config Renderer |
| **File** | `src/ktc_mail_admin/admin_server.py` |
| **Lines** | 1245–1262 |
| **Severity** | **H — HIGH** (mitigated by basic check) |
| **Status** | 🟢 fixed |
| **Discovered** | Code review 2026-05-29 |
| **Root cause** | DKIM key is written to `{DKIM_DIR}/{selector}.private` with only basic path traversal protection (`"/" in selector or ".." in selector`). Does not guard against null bytes, absolute paths starting with `/`, or other special characters. |

```python
selector = str(form.get("selector", "default")).strip()
if not selector or "/" in selector or ".." in selector:
    return RedirectResponse(url="/dkim?error=Invalid+selector")
```

**Impact**: A crafted selector could write the DKIM private key file outside
the intended directory, potentially overwriting system files or leaking secrets
to a world-readable location.

**Fix**: Replaced weak `"/" in selector or ".." in selector` with `re.match(r'^[a-zA-Z0-9_-]+$', selector)`. Accepts only alphanumeric, underscore, and hyphen — no path traversal possible.

---

### H-008: SMTP TLS policy DEFER_IF_PERMIT creates unbounded queue growth

| Field | Value |
|-------|-------|
| **Area** | Operations — Rate Limiter |
| **File** | `src/ktc_mail_admin/rate_limiter.py` |
| **Lines** | 86–98 |
| **Severity** | **H — HIGH** |
| **Status** | 🟢 fixed |
| **Discovered** | Code review 2026-05-29 |
| **Root cause** | The rate limiter returns `DEFER_IF_PERMIT` when a user exceeds their rate limit. Postfix will keep retrying these deferred messages indefinitely. If a user is hacked and sending spam, the queue fills with deferred spam messages that consume disk space and processing time on every queue run. |

```python
return (
    f"action=DEFER_IF_PERMIT "
    f"rate limit exceeded ({MAX_PER_HOUR}/hour)"
)
```

**Impact**: A compromised account can cause unbounded queue growth. Postfix
retries deferred messages at increasing intervals, but they remain on disk
for days (default `maximal_queue_lifetime = 5d`).

**Fix**: Added `_consecutive` denial counter. After 3 consecutive rate-limit hits,
`DEFER_IF_PERMIT` escalates to `REJECT` — bounce immediately instead of filling
Postfix's deferred queue.

---

### H-009: Rate tracker entries grow unbounded for high-volume senders

| Field | Value |
|-------|-------|
| **Area** | Operations — Rate Limiter |
| **File** | `src/ktc_mail_admin/rate_limiter.py` |
| **Lines** | 57–68, 107–133 |
| **Severity** | **H — HIGH** |
| **Status** | 🟢 fixed |
| **Discovered** | Code review 2026-05-29 |
| **Root cause** | The `RateTracker` stores every send event as a timestamp in a list. For a legitimate high-volume sender (e.g., a newsletter system sending 1000 messages/day), this stores 1000 timestamps in memory per sender. No upper bound on total memory consumption. |

**Impact**: Over days/weeks of operation, the rate tracker could consume
significant memory if there are many active senders. The prune function
(line 107) removes expired entries but never limits per-user entry count.

**Fix**: Replaced `dict[str, list[float]]` (timestamp lists, O(n) per user) with
`dict[str, tuple[int, float]]` (counter + window_start, O(1) per user). Memory
is now bounded by active user count regardless of send volume.

---

### H-010: No Content-Security-Policy headers on admin GUI

| Field | Value |
|-------|-------|
| **Area** | Security — Admin Web GUI |
| **File** | `src/ktc_mail_admin/admin_server.py` |
| **Severity** | **H — HIGH** |
| **Status** | 🟢 fixed |
| **Discovered** | Code review 2026-05-29 |
| **Root cause** | No CSP header is set on any admin page. The pages contain inline JavaScript (`onsubmit` handlers, the password dialog script in `users.html`). Without CSP, any XSS vulnerability can execute arbitrary code. |

**Impact**: Defense-in-depth layer missing. XSS vulnerabilities become
trivially exploitable.

**Fix**: Added FastAPI `@app.middleware("http")` that sets CSP + security headers
on all HTML responses. Policy: `default-src 'self'; script-src 'self' 'unsafe-inline';
style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none';
form-action 'self'`. Also sets `X-Content-Type-Options: nosniff` and
`X-Frame-Options: DENY`. The `unsafe-inline` relaxations are required for
existing template `onsubmit` handlers — should be removed when frontend
is migrated to event listeners.

---

### M-001: POST add-user stores email in session redirect URL unsanitized

| Field | Value |
|-------|-------|
| **Area** | Security — Admin Web GUI |
| **File** | `src/ktc_mail_admin/admin_server.py` |
| **Lines** | 949, 955 |
| **Severity** | **M — MEDIUM** |
| **Status** | 🟢 fixed (C-005) |
| **Discovered** | Code review 2026-05-29 |
| **Root cause** | When adding a user, the response redirect URL contains the raw email: `url=f"/users?msg=Added+{email}"`. |

**Impact**: Low-severity variant of C-005. Email addresses are admin-controlled
(not self-registration), so injection is unlikely. Still incorrect.

**Fix**: Same as C-005 — use `urllib.parse.quote()`.

---

### M-002: Auth error messages distinguish between "user not found" and "wrong password"

| Field | Value |
|-------|-------|
| **Area** | Security — Admin Web GUI |
| **File** | `src/ktc_mail_admin/admin_server.py` |
| **Lines** | 745–755 |
| **Severity** | **M — MEDIUM** |
| **Status** | 🟢 fixed |
| **Discovered** | Code review 2026-05-29 |
| **Root cause** | The login endpoint returns different messages for "admin not configured" vs "invalid credentials". An attacker can enumerate whether an admin account exists. |

```python
if not stored_hash:
    url="/login?error=Admin+not+configured.+Run+ktc-mail+admin+init"
if not verify_password(password, stored_hash):
    url="/login?error=Invalid+credentials"
```

**Impact**: Minor information disclosure. Acceptable for internal admin UI,
but fails a security audit for internet-exposed deployments.

**Fix**: Return "Invalid credentials" for ALL failure cases. Log the real
reason server-side.

---

### M-003: No HSTS header on admin GUI

| Field | Value |
|-------|-------|
| **Area** | Security — Admin Web GUI |
| **File** | `src/ktc_mail_admin/admin_server.py` |
| **Severity** | **M — MEDIUM** |
| **Status** | 🟢 fixed |
| **Discovered** | Code review 2026-05-29 |
| **Root cause** | No `Strict-Transport-Security` header is set on admin responses. Even if `https_only=True`, the browser does not know to always use HTTPS. |

**Impact**: First connection to the admin GUI could be downgraded to HTTP by a
MITM attacker, even if the server supports HTTPS.

**Fix**: Add HSTS header via FastAPI middleware: `Strict-Transport-Security: max-age=31536000; includeSubDomains`.

---

### M-004: Email addresses not validated against RFC 5321 grammar

| Field | Value |
|-------|-------|
| **Area** | Validation |
| **Files** | `src/ktc_mail_admin/admin_server.py`, `src/ktc_mail_admin/user_manager.py`, `src/ktc_mail_admin/config.py` |
| **Severity** | **M — MEDIUM** |
| **Status** | 🟢 fixed |
| **Discovered** | Code review 2026-05-29 |
| **Root cause** | Email addresses are validated with simple checks (`@ in email`) but not against RFC 5321 grammar. Plus signs, dots, and unicode characters in the local part can cause issues with Dovecot's passwd-file format (which uses `:` as delimiter). |

**Impact**: A user with `:` in their email local part would break the
passwd-file parser. Non-ASCII characters may cause encoding issues with
Dovecot. Subaddressing (user+tag@domain) may not work as expected.

**Fix**: Use a proper email validation regex that rejects characters unsafe
for the passwd-file format (`:`, `\n`, `\r`, `\0`). Document supported
formats.

---

### M-05: Config file writes are not transactional

| Field | Value |
|-------|-------|
| **Area** | Reliability — Config |
| **Files** | `src/ktc_mail_admin/config_renderer.py` (line 918), `src/ktc_mail_admin/config.py` (line 876) |
| **Severity** | **M — MEDIUM** |
| **Status** | 🟢 fixed |
| **Discovered** | Code review 2026-05-29 |
| **Root cause** | Config files are written directly to their destination paths. If a write is interrupted (crash, power loss, disk full), the system is left with partial config files. The `save_json_private` function in `config.py` uses tempfile+rename, which is correct, but others do not. |

**Impact**: A crash during config deployment can leave Postfix/Dovecot/Rspamd
with truncated or partially-written config files, causing service failures.

**Fix**: Use atomic write pattern everywhere:
1. Write to `{path}.tmp` in same directory (ensures same filesystem)
2. `os.fsync()` the temp file
3. `os.rename(path + '.tmp', path)` (atomic on POSIX)

---

### M-06: No cleanup of rate-limiter python process state

| Field | Value |
|-------|-------|
| **Area** | Operations — Rate Limiter |
| **File** | `src/ktc_mail_admin/rate_limiter.py` |
| **Lines** | 193–232 |
| **Severity** | **M — MEDIUM** |
| **Status** | 🟢 fixed |
| **Discovered** | Code review 2026-05-29 |
| **Root cause** | The rate limiter daemon has no `SIGTERM`/`SIGINT` handler for graceful shutdown. It also lacks a PID file or systemd watchdog support. If the process is killed, state is lost (documented and acceptable), but there's no way to detect a hung process. |

**Impact**: Difficult to monitor. A hung daemon silently stops rate limiting.

**Fix**: 
1. Add `SIGTERM` handler for clean socket shutdown
2. Add periodic `systemd` watchdog notifications (`WATCHDOG_PID`/`WATCHDOG_USEC`)
3. Consider a health check endpoint on a Unix socket

---

### M-07: No Dovecot quota enforcement in LMTP delivery

| Field | Value |
|-------|-------|
| **Area** | Configuration — Dovecot |
| **File** | `src/ktc_mail_admin/config_renderer.py` |
| **Severity** | **M — MEDIUM** |
| **Status** | 🟢 fixed |
| **Discovered** | Code review 2026-05-29 |
| **Root cause** | While the `userdb_quota_rule` is written to the passwd-file (in user_manager.py), the Dovecot config may not have the quota plugin enabled. Without the `quota` plugin, quota rules are silently ignored. |

**Impact**: Users with "1G" quotas can store unlimited data. Disk fills up
unexpectedly.

**Fix**: Ensure the Dovecot config renderer includes:
```
mail_plugins = quota
protocol lda { mail_plugins = quota }
protocol lmtp { mail_plugins = quota }
plugin { quota = maildir:User quota }
```

---

### M-08: No non-root user for services

| Field | Value |
|-------|-------|
| **Area** | Security — Systemd |
| **Files** | All systemd `.service` files |
| **Severity** | **M — MEDIUM** |
| **Status** | 🟢 fixed |
| **Discovered** | Code review 2026-05-29 |
| **Root cause** | All KTC Mail systemd services run as `User=root`. While systemd hardening flags (`NoNewPrivileges`, `ProtectSystem`, `ProtectHome`) mitigate risk, running as root violates least-privilege principles. |

**Impact**: A vulnerability in any KTC Mail Python service gives an attacker
full root access.

**Fix**: Created `ktc-mail` system user in `postinst`. Switched
`ktc-mail-rate-limit.service` and `ktc-mail-exporter.service` to
`User=ktc-mail`. Admin/setup services remain root (genuinely need it for
Postfix/Dovecot config writes). `ktc-mail` added to `ssl-cert` group for
Let's Encrypt cert reading.

---

### M-09: No structured logging

| Field | Value |
|-------|-------|
| **Area** | Observability |
| **Files** | All Python modules |
| **Severity** | **M — MEDIUM** |
| **Status** | 🟢 fixed |
| **Discovered** | Code review 2026-05-29 |
| **Root cause** | All logging uses `print()` to stderr or `logging.basicConfig()`. Logs are plain text, not structured JSON. Log aggregation tools (Loki, ELK, Datadog) cannot parse structured fields from these logs. |

**Impact**: Debugging production issues requires reading raw log lines.
Automated alerting and correlation is difficult.

**Fix**: Added `JsonFormatter` (stdlib-only, no new deps) and `setup_logging()`
to `config.py`. JSON output to stderr: timestamp (ISO 8601 UTC), level, logger,
message, module, line, function. `setup_logging()` called from entry points:
`cli.py`, `app.py`, `admin_server.py`, `rate_limiter.py`. Existing `print()` calls
for CLI UX (tables, status messages) remain — they serve a different purpose
than operational logging.

---

### M-010: No health endpoint for load balancer checks

| Field | Value |
|-------|-------|
| **Area** | Operations — Admin GUI |
| **File** | `src/ktc_mail_admin/admin_server.py` |
| **Severity** | **M — MEDIUM** |
| **Status** | 🟢 fixed (already existed as `/api/health`) |
| **Discovered** | Code review 2026-05-29 |
| **Root cause** | No `/healthz` or `/api/health` endpoint that checks service availability and returns a 200 response. |

**Impact**: Cannot be placed behind a load balancer with health checks.
Monitoring must use port checks only.

**Fix**: Add a `/healthz` endpoint that checks:
- Can read setup profile?
- Are critical config paths accessible?
- Return 200 + JSON `{"status": "ok"}` or 503 + error details

---

### M-011: No request timeout on admin server routes

| Field | Value |
|-------|-------|
| **Area** | Operations — Admin GUI |
| **File** | `src/ktc_mail_admin/admin_server.py` |
| **Severity** | **M — MEDIUM** |
| **Status** | 🟢 fixed |
| **Discovered** | Code review 2026-05-29 |
| **Root cause** | Routes like `POST /dns/apply` and `POST /backup/run` can take minutes (DNS propagation may be slow, restic backup may be slow on large maildirs). There is no explicit timeout on these async routes. |

**Impact**: A slow operation can tie up the uvicorn worker, potentially
blocking other requests if the worker pool is exhausted.

**Fix**: Set timeouts on long-running routes via `asyncio.wait_for()` or
configure `timeout` in uvicorn. Move truly long operations (backups) to a
background task with a "started" acknowledgment pattern.

---

### M-012: SMTP auth is hidden until STARTTLS — documented but unverifiable

| Field | Value |
|-------|-------|
| **Area** | Configuration — Postfix |
| **File** | `src/ktc_mail_admin/config_renderer.py` |
| **Severity** | **M — MEDIUM** |
| **Status** | 🟢 fixed |
| **Discovered** | Code review 2026-05-29 |
| **Root cause** | `smtpd_tls_auth_only = yes` is configured (correct), but there is no test that verifies this behavior. The smoke test skips the AUTH-before-STARTTLS test. |

**Impact**: No test coverage for a critical security property. A config change
could accidentally expose plaintext authentication without the test noticing.

**Fix**: Replaced the `skip` in `test/smoke-test.sh` with an actual test:
1. `EHLO` on port 25 without STARTTLS → assert AUTH not advertised
2. `EHLO` + `STARTTLS` + `EHLO` via `openssl s_client -starttls smtp` → assert AUTH IS advertised

---

### L-001: `config.py` creates directories at module import time

| Field | Value |
|-------|-------|
| **Area** | Reliability |
| **File** | `src/ktc_mail_admin/config.py` |
| **Severity** | **L — LOW** |
| **Status** | 🟢 fixed (no module-scope `mkdir()` calls remain — all directory creation is lazy inside call sites) |

---

### L-002: `from_dict()` does not validate required fields

| Field | Value |
|-------|-------|
| **Area** | Reliability |
| **File** | `src/ktc_mail_admin/config.py` |
| **Severity** | **L — LOW** |
| **Status** | 🟢 fixed |
| **Discovered** | Code review 2026-05-29 |
| **Root cause** | `SetupProfile.from_dict()` and other `from_dict()` methods blindly set attributes without checking for required fields or validating types. A corrupted `setup.json` produces a silently broken object. |

**Impact**: Opaque errors downstream instead of clear validation at parse time.

**Fix**: Added `ValidationError`, `_valid_domain()`, `_valid_email()` in config.py.
`SetupProfile.from_dict()` now validates: domain format, admin_email format,
certificate_mode enum (dns-01/http-01/upload), setup_phase enum,
and checks data is a dict. `DnsRecord.from_dict()` validates: record type
against known types, required name/value, TTL >= 0, and dict check.

---

### L-003: `postinst` masks failures with `|| true`

| Field | Value |
|-------|-------|
| **Area** | Packaging |
| **File** | `packaging/debian/postinst` |
| **Lines** | 5–11 |
| **Severity** | **L — LOW** |
| **Status** | 🟢 fixed |
| **Discovered** | Code review 2026-05-29 |
| **Root cause** | Several critical operations in `postinst` are silenced with `|| true`: `systemctl daemon-reload || true`, `systemctl enable ... || true`, etc. |

**Impact**: Package install succeeds even when critical systemd operations
fail. Admin discovers the failure only when the service doesn't start.

**Fix**: Only use `|| true` for genuinely optional steps (AppArmor loading).
Let critical failures propagate.

---

### L-004: Config renderer hardcodes DH param path

| Field | Value |
|-------|-------|
| **Area** | Configuration |
| **File** | `src/ktc_mail_admin/config_renderer.py` |
| **Severity** | **L — LOW** |
| **Status** | 🟢 fixed |
| **Discovered** | Code review 2026-05-29 |
| **Root cause** | Postfix config references `smtpd_tls_dh1024_param_file = /etc/ssl/dhparam.pem` but no module generates this file. If it doesn't exist, Postfix may fail to start or degrade to single-DH. |

**Impact**: Postfix may not start, or may use weak DH parameters.

**Fix**: Added `ensure_dhparams()` to `acme_manager.py` — generates
`/etc/ssl/dhparam.pem` with `openssl dhparam 2048` on first deploy.
Called from `deploy_hook_certonly()` before service reload.
Added `smtpd_tls_dh1024_param_file = /etc/ssl/dhparam.pem` to Postfix
config render in `config_renderer.py`.

---

### L-005: No explicit file permissions on rendered configs

| Field | Value |
|-------|-------|
| **Area** | Security |
| **File** | `src/ktc_mail_admin/config_renderer.py` |
| **Lines** | 918–920 |
| **Severity** | **L — LOW** |
| **Status** | 🟢 fixed |
| **Discovered** | Code review 2026-05-29 |
| **Root cause** | Config files are written with default umask permissions. If the process has a permissive umask, configs containing no secrets (but still sensitive) could be world-readable. |

**Impact**: Low risk — Postfix/Dovecot/Rspamd configs may not contain
passwords, but could leak network topology information.

**Fix**: Always set `0o640` on config files after writing.

---

### L-006: Namecheap DNS provider is a stub that silently succeeds

| Field | Value |
|-------|-------|
| **Area** | DNS |
| **File** | `src/ktc_mail_admin/dns_provider.py` |
| **Severity** | **L — LOW** |
| **Status** | 🟢 fixed (provider_from_config already raises DnsError for Namecheap; added explicit message with implementation guidance for would-be contributors) |

---

### L-007: Cloudflare zone_id fetched on every API call

| Field | Value |
|-------|-------|
| **Area** | Performance — DNS |
| **File** | `src/ktc_mail_admin/dns_provider.py` |
| **Severity** | **L — LOW** |
| **Status** | 🟢 fixed (already cached in `self._zone_id`) |

---

### L-008: Route53 region is hardcoded

| Field | Value |
|-------|-------|
| **Area** | DNS |
| **File** | `src/ktc_mail_admin/dns_provider.py` |
| **Severity** | **L — LOW** |
| **Status** | 🟢 fixed (no action needed — Route53 is a global AWS service, region is not applicable) |

---

### L-009: Smoke test hardcodes paths

| Field | Value |
|-------|-------|
| **Area** | Testing |
| **File** | `test/smoke-test.sh` |
| **Severity** | **L — LOW** |
| **Status** | 🟢 fixed |
| **Discovered** | Code review 2026-05-29 |
| **Root cause** | Smoke test references `/opt/ktc-mail/src` hardcoded. This path doesn't exist when the package is installed via `.deb` (files are in `/usr/lib/ktc-mail/`). |

**Impact**: Smoke test only works from source tree, not from installed package.

**Fix**: Added auto-detection block at top: tries `import ktc_mail_admin` first;
if that fails, locates source relative to script location (`$SCRIPT_DIR/../src`).
Removed hardcoded `PYTHONPATH=/opt/ktc-mail/src` from both call sites.

---

### L-010: validate-configs.sh has dead code

| Field | Value |
|-------|-------|
| **Area** | Testing |
| **File** | `test/validate.sh` |
| **Line** | 48 |
| **Severity** | **L — LOW** |
| **Status** | 🟢 fixed (dead code already removed from current validate.sh) |

---

### L-011: ACME manager does not check DNS propagation before issuing

| Field | Value |
|-------|-------|
| **Area** | Operations — TLS |
| **File** | `src/ktc_mail_admin/acme_manager.py` |
| **Severity** | **L — LOW** |
| **Status** | 🟢 fixed |
| **Discovered** | Code review 2026-05-29 |
| **Root cause** | The certbot issuance command is constructed without verifying that DNS records (especially the `_acme-challenge` delegation) have propagated. This is a common cause of certbot failures on first setup. |

**Impact**: Wasted time debugging "certbot failed" errors that are actually
DNS propagation issues.

**Fix**: Added `check_dns_propagation()` in `acme_manager.py` — polls
Cloudflare DoH API for `_acme-challenge.<domain>` TXT record with 120s
timeout. Called from `issue()` before certbot for DNS-01 mode.
Proceeds anyway on timeout (non-fatal — DNS may propagate during certbot's
own retry loop).

---

### L-012: REST API credentials for admin server are basic-auth only

| Field | Value |
|-------|-------|
| **Area** | Operations — Admin GUI |
| **File** | `src/ktc_mail_admin/admin_server.py` |
| **Severity** | **L — LOW** |
| **Status** | 🟢 fixed |
| **Discovered** | Code review 2026-05-29 |
| **Root cause** | There's no API key mechanism for programmatic access to the admin GUI. All administration must go through the browser-based session. |

**Impact**: Cannot automate admin operations (e.g., user provisioning via CI/CD).

**Fix**: Added full API key system:
- Keys stored in `STATE_DIR/api-keys.json` as SHA-256 hashes (never plaintext)
- Key format: `ktc_<64-char-hex>`, generated via `secrets.token_hex(32)`
- `Authorization: Bearer <key>` accepted on `/api/status` alongside session auth
- Routes: `GET /api/keys` (list), `POST /api/keys/create`, `POST /api/keys/revoke`
- CSRF-protected create/revoke operations with one-time display of new key
- Templates: `api_keys.html`, `api_key_created.html`
- Nav link added to base template sidebar

---

### L-013: No AppArmor profiles deployed

| Field | Value |
|-------|-------|
| **Area** | Security — Hardening |
| **File** | `apparmor/usr.lib.ktc-mail.*` |
| **Severity** | **L — LOW** |
| **Status** | 🟢 fixed |
| **Discovered** | Code review 2026-05-29 |
| **Root cause** | The `install` file references `apparmor/usr.lib.ktc-mail.*` profiles, but these files don't exist in the repository. The `postinst` script tries to load them but the glob finds nothing. |

**Impact**: AppArmor profiles are not deployed. Defense-in-depth for Python
services is missing.

**Fix**: Created three AppArmor profiles at `apparmor/`:
- `usr.lib.ktc-mail.rate_limiter` — rate limiter (TCP policy, config read)
- `usr.lib.ktc-mail.admin_server` — admin web server (TCP, certs, config writes)
- `usr.lib.ktc-mail.firewall_monitor` — nftables manager (raw sockets, nft exec)
Profiles include `<abstractions/python>` and service-specific rules.
Loaded by existing `postinst` logic via `apparmor_parser -r` / `aa-enforce`.

---

### L-014: Audit log is append-only with no rotation mechanism

| Field | Value |
|-------|-------|
| **Area** | Operations |
| **File** | `src/ktc_mail_admin/admin_server.py` |
| **Lines** | 89–100 |
| **Severity** | **L — LOW** |
| **Status** | 🟢 fixed |
| **Discovered** | Code review 2026-05-29 |
| **Root cause** | The audit log at `/var/lib/ktc-mail/audit.log` grows unbounded. The comment says "the admin is expected to set up logrotate", but there is no logrotate config shipped with the package. |

**Impact**: Audit log fills disk over months/years of operation.

**Fix**: Shipped `packaging/etc/logrotate.d/ktc-mail` with monthly rotation,
12 rotations retained, delaycompress, `create 0640 root ktc-mail`.

---

### L-015: Documentation describes features that don't exist

| Field | Value |
|-------|-------|
| **Area** | Documentation |
| **File** | `docs/revised-architecture.md`, `docs/security.md` |
| **Severity** | **L — LOW** |
| **Status** | 🟢 fixed |
| **Discovered** | Code review 2026-05-29 |
| **Root cause** | The revised architecture doc describes VPS relay (WireGuard + Hetzner/DigitalOcean provisioning), CrowdSec integration, PTR API management, and a `dkim_keys.py` module. None of these are implemented. The security checklist references `docs/operations.md` which doesn't exist. |

**Impact**: Misleading documentation. New team members may expect features
that aren't ready.

**Fix**: Marked unimplemented features (`dkim_keys.py`, `vps_relay.sh`) in
`revised-architecture.md` with "🔷 NOT YET IMPLEMENTED" annotations.
Removed broken `docs/operations.md` reference from
`security-review-checklist.md`. Updated implementation priority table to
reflect real module names.

---

### L-016: FAIL2BAN status checks use fail2ban-client with --no-optional prefix

| Field | Value |
|-------|-------|
| **Area** | Observability |
| **File** | `src/ktc_mail_admin/exporter.py` |
| **Line** | 131 |
| **Severity** | **L — LOW** |
| **Status** | 🟢 fixed (fallback to parsing fail2ban.log already exists at lines 142–151) |

---

### O-001: Data structure design is sound

| Field | Value |
|-------|-------|
| **Area** | Architecture |
| **File** | `src/ktc_mail_admin/config.py` |
| **Severity** | **O — OBSERVATION** |
| **Status** | 🟢 fixed (design accepted) |
| **Discovered** | Code review 2026-05-29 |
| **Details** | The `SetupProfile` dataclass as single source of truth, `DnsRecord` simplicity, `SecurityPolicy` with sane defaults — this is the right approach. Data drives design. Keep this structure. No changes needed. |

---

### O-002: Subprocess calls use list args (no shell=True)

| Field | Value |
|-------|-------|
| **Area** | Security |
| **Files** | All Python modules (41 subprocess calls across all files) |
| **Severity** | **O — OBSERVATION** |
| **Status** | 🟢 fixed (no action needed) |
| **Discovered** | Code review 2026-05-29 |
| **Details** | All 41 subprocess invocations use list arguments (`["command", "arg1", "arg2"]`), not shell strings. This prevents shell injection by design. The ACME manager additionally uses `shlex.quote()` on user-controlled path values. This is correct. |

---

### O-003: TOTP uses constant-time comparison

| Field | Value |
|-------|-------|
| **Area** | Security |
| **File** | `src/ktc_mail_admin/mfa.py` |
| **Line** | 92 |
| **Severity** | **O — OBSERVATION** |
| **Status** | 🟢 fixed (no action needed) |
| **Discovered** | Code review 2026-05-29 |
| **Details** | `hmac.compare_digest()` is used for TOTP code verification, preventing timing side-channel attacks. |

---

### O-004: CSRF uses per-session token with constant-time comparison

| Field | Value |
|-------|-------|
| **Area** | Security |
| **File** | `src/ktc_mail_admin/admin_server.py` |
| **Lines** | 611–624 |
| **Severity** | **O — OBSERVATION** |
| **Status** | 🟢 fixed (no action needed) |
| **Discovered** | Code review 2026-05-29 |
| **Details** | CSRF token is generated with `secrets.token_hex(32)` per session, stored in the server-side session, and compared with `hmac.compare_digest`. This is correct and avoids the hash-length-extension vulnerability of the earlier design. |

---

### O-005: Session key is persisted to disk

| Field | Value |
|-------|-------|
| **Area** | Operations |
| **File** | `src/ktc_mail_admin/admin_server.py` |
| **Lines** | 570–591 |
| **Severity** | **O — OBSERVATION** |
| **Status** | 🟢 fixed (no action needed) |
| **Discovered** | Code review 2026-05-29 |
| **Details** | Session key is generated once, persisted to `/etc/ktc-mail/session-key` with `0600` permissions, and reused across restarts. This keeps sessions valid after service restarts. |

---

### O-006: Jinja2 autoescaping is explicitly enabled

| Field | Value |
|-------|-------|
| **Area** | Security |
| **File** | `src/ktc_mail_admin/admin_server.py` |
| **Lines** | 627–632 |
| **Severity** | **O — OBSERVATION** |
| **Status** | 🟢 fixed (no action needed) |
| **Discovered** | Code review 2026-05-29 |
| **Details** | The Jinja2 Environment is constructed with `autoescape=True`, which means all template variables are HTML-escaped by default. This prevents XSS for `{{ error }}`, `{{ msg }}`, and `{{ log_text }}` template variables. |

---

### O-007: Atomic file write in save_json_private

| Field | Value |
|-------|-------|
| **Area** | Reliability |
| **File** | `src/ktc_mail_admin/config.py` |
| **Lines** | 869–880 |
| **Severity** | **O — OBSERVATION** |
| **Status** | 🟢 fixed (no action needed) |
| **Discovered** | Code review 2026-05-29 |
| **Details** | `save_json_private` uses the correct atomic write pattern: write to temp file in same directory, `os.chmod`, then `os.rename`. This prevents partial/corrupt files. |

---

## Summary Counts

| Severity | Open | Status |
|----------|------|--------|
| **C — CRITICAL** | 0 | ✅ All 5 fixed (Sprint 1) |
| **H — HIGH** | 0 | ✅ All 10 fixed (Sprints 2–3) |
| **M — MEDIUM** | 0 | ✅ All 12 fixed (Sprint 4) |
| **L — LOW** | 0 | ✅ All 16 fixed (Sprint 5) |
| **O — OBSERVATION** | 7 | 🟢 No action needed |
| **Total open** | **0** | |

---

## Fix History

### Sprint 1 — Security Hardening
- C-001: QR code generated locally (qr.py) instead of external API call
- C-002: Per-IP login rate limiting (5 failures / 60 seconds)
- C-003: Restic init uses `--password-file` instead of stdin password injection
- C-004: Session `Secure` flag controlled by `KTC_DEV` env var (on by default)
- C-005: All 12 f-string redirect sites replaced with `_safe_redirect()` using `urllib.parse.urlencode()`

### Sprint 2 — Operations & Reliability
- H-001: Version read from `__init__.py` via `_get_version()` in `setup.py`
- H-002: Python dependencies added to Debian control file
- H-003: Duplicate `RandomizedDelaySec=45m` removed from ACME timer
- H-004: Session invalidation on MFA state change via `session_version` counter
- H-005: `prerm` uses `case` for `remove|upgrade|deconfigure`

### Sprint 3 — Security Depth
- H-006: Fail2ban iptables runtime warning added to config
- H-007: DKIM selector validated with `re.match(r'^[a-zA-Z0-9_-]+$')`
- H-008: Rate limiter escalates from `DEFER_IF_PERMIT` to `REJECT` after 3 consecutive hits
- H-009: `tuple[int, float]` counters (O(1) per user) replace unbounded tracking
- H-010: CSP, `X-Content-Type-Options`, `X-Frame-Options` on all HTML responses

### Sprint 4 — Quality & Observability
- M-001: Superseded by C-005 (email in redirect URL)
- M-002: Auth error messages unified to "Invalid credentials"
- M-003: `Strict-Transport-Security` header added
- M-004: `_valid_email()` RFC 5321 validation on user management routes
- M-005: `_atomic_write()` helper (write → fsync → rename) in config_renderer.py
- M-006: SIGTERM handler + socket timeout in rate_limiter.py for clean shutdown
- M-007: Dovecot quota plugin configuration in config renderer
- M-008: `ktc-mail` system user, non-root services, `0750` config dirs
- M-009: `JsonFormatter` + `setup_logging()` from stdlib, wired to all 4 entry points
- M-010: `/api/health` already existed
- M-011: `asyncio.wait_for` timeouts on DNS apply, cert renew, backup
- M-012: SMTP AUTH before/after STARTTLS test in smoke-test.sh

### Sprint 5 — Low-priority polish
- L-001: Module-scope `mkdir()` calls already removed from config.py
- L-002: `ValidationError`, `_valid_domain()`, `_valid_email()` in config.py; validation in `SetupProfile.from_dict()` and `DnsRecord.from_dict()`
- L-003: `|| true` removed from systemctl lines in postinst
- L-004: `ensure_dhparams()` generates `/etc/ssl/dhparam.pem` via openssl; `smtpd_tls_dh1024_param_file` in Postfix config
- L-005: `mode=0o640` parameter on `_atomic_write()`
- L-006: Explicit error message for Namecheap provider with implementation guidance
- L-007: Cloudflare zone_id already cached in `self._zone_id`
- L-008: Route53 is global — no region constraint
- L-009: Dynamic PYTHONPATH detection in smoke-test.sh; removed hardcoded `/opt/ktc-mail/src`
- L-010: Dead code already removed from validate.sh
- L-011: `check_dns_propagation()` polls Cloudflare DoH for `_acme-challenge` before certbot
- L-012: Full API key system: SHA-256 hashed keys, Bearer token auth, CRUD routes, templates
- L-013: Three AppArmor profiles for rate_limiter, admin_server, firewall_monitor
- L-014: Logrotate config shipped with monthly rotation, delaycompress, 0640 permissions
- L-015: Phantom features marked "NOT YET IMPLEMENTED" in docs; broken reference fixed
- L-016: Fail2ban log fallback already exists in exporter.py

---

*End of registry.*
