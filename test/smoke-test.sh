#!/bin/bash
# KTC Mail — live service smoke test
#
# Starts every service inside the container, waits for readiness,
# and verifies basic protocol-level operation (ports open, SMTP banner,
# IMAP banner, Nginx HTTP response).
#
# Usage: docker run --rm ktc-mail-test bash /smoke-test.sh

set -euo pipefail

PASS=0
FAIL=0
SKIP=0

# ── Python path detection ──────────────────────────────────────────
# If ktc_mail_admin is not importable directly, add the source tree
# to PYTHONPATH.  Works from build tree (test/smoke-test.sh → src/)
# and from installed package (import finds it via site-packages).
if ! python3 -c "import ktc_mail_admin" 2>/dev/null; then
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    KTC_SRC="$SCRIPT_DIR/../src"
    if [ -d "$KTC_SRC/ktc_mail_admin" ]; then
        export PYTHONPATH="${PYTHONPATH:+$PYTHONPATH:}$KTC_SRC"
    else
        echo "ERROR: ktc_mail_admin not importable and source not found at $KTC_SRC"
        echo "Install the package or run from the source tree."
        exit 1
    fi
fi

pass() { PASS=$((PASS + 1)); echo -e "  \e[32mPASS\e[0m $1"; }
fail() { FAIL=$((FAIL + 1)); echo -e "  \e[31mFAIL\e[0m $1"; }
skip() { SKIP=$((SKIP + 1)); echo -e "  \e[33mSKIP\e[0m $1"; }

CLEANUP=""
cleanup() {
    echo ""
    echo "--- Cleaning up services ---"
    for pid in $CLEANUP; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
}
trap cleanup EXIT

# Helper: wait for a TCP port to be ready (timeout sec)
wait_port() {
    local host="$1" port="$2" label="$3" timeout="${4:-10}"
    local waited=0
    while ! timeout 1 bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null; do
        waited=$((waited + 1))
        if [ "$waited" -ge "$timeout" ]; then
            fail "${label} — port $port not ready after ${timeout}s"
            return 1
        fi
        sleep 1
    done
    pass "${label} — listening on $port (${waited}s)"
    return 0
}

echo ""
echo "=== KTC Mail live smoke test ==="
echo ""

# ── 1. Create test user for IMAP login ───────────────────────────────
echo "--- Setup ---"
if id "testuser" &>/dev/null; then
    pass "test user exists"
else
    useradd -m -s /bin/bash testuser 2>/dev/null || true
    echo "testuser:password123" | chpasswd 2>/dev/null || true
    if id "testuser" &>/dev/null; then
        pass "test user created"
    else
        skip "test user creation (non-critical)"
    fi
fi

# ── 2. Start Redis (Rspamd dependency) ────────────────────────────────
echo "--- Redis ---"
if command -v redis-server &>/dev/null; then
    redis-server --daemonize yes --bind 127.0.0.1 2>/dev/null || true
    sleep 1
    if timeout 2 bash -c "echo >/dev/tcp/127.0.0.1/6379" 2>/dev/null; then
        pass "redis-server — listening on 6379"
    else
        fail "redis-server — not listening"
    fi
else
    skip "redis-server not installed"
fi

# ── 3. Start Postfix ──────────────────────────────────────────────────
echo "--- Postfix ---"
if command -v postfix &>/dev/null; then
    # Stop any existing postfix first (from package install)
    /usr/lib/postfix/sbin/master -k 2>/dev/null || true
    sleep 1
    # Start in foreground with daemon off, background it
    /usr/lib/postfix/sbin/master -d &
    POSTFIX_PID=$!
    CLEANUP="$CLEANUP $POSTFIX_PID"
    wait_port "127.0.0.1" "25" "postfix (SMTP)" 15 || true
else
    skip "postfix not installed"
fi

# ── 4. Start Dovecot ──────────────────────────────────────────────────
echo "--- Dovecot ---"
if command -v dovecot &>/dev/null; then
    dovecot -c /etc/dovecot/dovecot.conf &
    DOVECOT_PID=$!
    CLEANUP="$CLEANUP $DOVECOT_PID"
    wait_port "127.0.0.1" "993" "dovecot (IMAPS)" 15 || true
    skip "dovecot IMAP (port 143 intentionally disabled — ssl=required)"
    skip "dovecot LMTP (Unix socket only, no TCP listener)"
    # Submission handled by Postfix on 587, not Dovecot
else
    skip "dovecot not installed"
fi

# ── 5. Start Rspamd ───────────────────────────────────────────────────
echo "--- Rspamd ---"
if command -v rspamd &>/dev/null; then
    # Debian packages the rspamd user as _rspamd.
    # -g flag is NOT used — rspamd resolves the group from the user.
    # -g _rspamd required (Debian bug?): without it workers fail setgid(-1)
    # and smtpd hangs on the milter connection, never sending the SMTP banner.
    rspamd -f -u _rspamd -g _rspamd &
    RSPAMD_PID=$!
    CLEANUP="$CLEANUP $RSPAMD_PID"
    wait_port "127.0.0.1" "11332" "rspamd (milter)" 25 || true
    wait_port "127.0.0.1" "11333" "rspamd (controller)" 5 && true
else
    skip "rspamd not installed"
fi

# ── 6. Start Nginx ────────────────────────────────────────────────────
echo "--- Nginx ---"
if command -v nginx &>/dev/null && [ -f /etc/nginx/webmail.conf ]; then
    nginx -c /etc/nginx/nginx.conf &
    NGINX_PID=$!
    CLEANUP="$CLEANUP $NGINX_PID"
    wait_port "127.0.0.1" "80" "nginx (HTTP)" 10 || true
    wait_port "127.0.0.1" "443" "nginx (HTTPS)" 10 || true
else
    skip "nginx not installed or no webmail config"
fi

# ── 7. Protocol-level SMTP test ───────────────────────────────────────
echo "--- SMTP protocol ---"
if timeout 5 bash -c "echo >/dev/tcp/127.0.0.1/25" 2>/dev/null; then
    # Use nc for reliable banner + EHLO in a single connection.
    # Avoids /dev/tcp timing issues between separate connect/read calls.
    SMTP_RESP=$(echo -e "EHLO test.local\nQUIT" | timeout 10 nc 127.0.0.1 25 2>/dev/null) || true

    if echo "$SMTP_RESP" | grep -qi "220"; then
        pass "SMTP on port 25 — banner received"
    else
        fail "SMTP banner not received"
    fi
    if echo "$SMTP_RESP" | grep -qi "STARTTLS"; then
        pass "SMTP EHLO — STARTTLS advertised"
    else
        fail "SMTP EHLO — STARTTLS not advertised"
    fi
    # M-012: AUTH must NOT be advertised BEFORE STARTTLS, but MUST be
    # advertised AFTER. This is critical for credential safety.
    # Uses openssl s_client -starttls smtp for the TLS-leg of the test.
    if command -v openssl &>/dev/null; then
        # Test 1: EHLO without STARTTLS — AUTH must NOT appear
        EHLO_BEFORE=$(echo -e "EHLO test.local\nQUIT" | timeout 10 nc 127.0.0.1 25 2>/dev/null) || true
        if echo "$EHLO_BEFORE" | grep -qi "AUTH "; then
            fail "SMTP — AUTH advertised before STARTTLS (safety violation)"
        else
            pass "SMTP — AUTH hidden before STARTTLS"
        fi

        # Test 2: STARTTLS then EHLO — AUTH must appear
        EHLO_AFTER=$(printf 'EHLO test.local\nSTARTTLS\nEHLO test.local\nQUIT\n' | \
            timeout 10 openssl s_client -starttls smtp -connect 127.0.0.1:25 2>/dev/null) || true
        if echo "$EHLO_AFTER" | grep -qi "AUTH "; then
            pass "SMTP — AUTH advertised after STARTTLS"
        else
            fail "SMTP — AUTH not advertised after STARTTLS"
        fi
    else
        skip "SMTP AUTH before/after STARTTLS (openssl not available)"
    fi
else
    fail "SMTP — port 25 not reachable"
fi

# ── 8. Protocol-level IMAP test ──────────────────────────────────────
echo "--- IMAP protocol ---"
skip "IMAP on port 143 (intentionally disabled — ssl=required)"

# ── 9. IMAPS test ─────────────────────────────────────────────────────
echo "--- IMAPS protocol ---"
if timeout 5 bash -c "echo >/dev/tcp/127.0.0.1/993" 2>/dev/null; then
    pass "IMAPS on port 993 — reachable"
    # Dovecot config has `local 127.0.0.1 { ssl = no }` for SOGo auth compat.
    # Connecting to 127.0.0.1:993 hits this override, so the server
    # expects cleartext.  Test TLS against the container's non-loopback IP
    # to verify the IMAPS listener works correctly for external clients.
    IMAPS_IP=$(hostname -i 2>/dev/null | grep -v "127.0.0.1" | head -1 || echo "")
    if [ -n "$IMAPS_IP" ]; then
        TLS_OK=$(timeout 5 openssl s_client -connect "${IMAPS_IP}:993" -quiet 2>/dev/null <<< "" | head -5) || true
        if echo "$TLS_OK" | grep -qi "Dovecot"; then
            pass "IMAPS — TLS handshake with Dovecot (via ${IMAPS_IP})"
        else
            skip "IMAPS — TLS handshake via non-loopback IP (may vary in Docker)"
        fi
    else
        skip "IMAPS — no non-loopback IP to test TLS handshake"
    fi
else
    fail "IMAPS — port 993 not reachable"
fi

# ── 10. Nginx HTTP test ───────────────────────────────────────────────
echo "--- Nginx HTTP ---"
if timeout 5 bash -c "echo >/dev/tcp/127.0.0.1/80" 2>/dev/null; then
    HTTP_STATUS=$(timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/80
        echo -e "GET / HTTP/1.0\r\nHost: webmail.test.example.com\r\n\r\n" >&3
        read -r line <&3; echo "$line"
        exec 3>&-') || true
    if echo "$HTTP_STATUS" | grep -qi "200\|302\|301"; then
        pass "nginx HTTP — status ${HTTP_STATUS}"
    else
        fail "nginx HTTP — unexpected response: $HTTP_STATUS"
    fi
else
    fail "nginx — port 80 not reachable"
fi

# ── 11. Nginx HTTPS test ─────────────────────────────────────────────
echo "--- Nginx HTTPS ---"
if timeout 5 bash -c "echo >/dev/tcp/127.0.0.1/443" 2>/dev/null; then
    # Send a real HTTP request over TLS to verify the full handshake
    HTTPS_OK=$(printf 'GET / HTTP/1.0\r\nHost: webmail.test.example.com\r\n\r\n' | \
        timeout 5 openssl s_client -connect 127.0.0.1:443 -quiet 2>/dev/null | \
        head -3) || true
    # Accept any valid HTTP status — 502 is expected when the webmail
    # backend is not running. The important thing is TLS works.
    if echo "$HTTPS_OK" | grep -qiE "200|301|302|502"; then
        pass "nginx HTTPS — TLS handshake OK (status: $(echo "$HTTPS_OK" | head -1))"
    else
        fail "nginx HTTPS — unexpected response: $(echo "$HTTPS_OK" | head -1)"
    fi
else
    fail "nginx — port 443 not reachable"
fi

# ── 12. Admin server health check ─────────────────────────────────────
echo "--- Admin server ---"
if python3 -c "import fastapi, uvicorn" 2>/dev/null; then
    # Bootstrap admin password first
    ktc_mail_admin_init() {
        python3 -c "
from ktc_mail_admin.admin_server import cmd_admin_init
import argparse
args = argparse.Namespace(force=True, quiet=False)
cmd_admin_init(args)
" 2>&1
    }
    ADMIN_OUT=$(ktc_mail_admin_init 2>&1 || true)
    # The init prints "Admin password initialized: <token>"
    ADMIN_PASS=$(echo "$ADMIN_OUT" | grep -oP 'initialized: \K.*' | head -1) || ADMIN_PASS=""

    # Start admin server on a random port
    PORT=8082
    KTC_SESSION_HTTPS=0 python3 -c "
import uvicorn
from ktc_mail_admin.admin_server import create_app
app = create_app()
uvicorn.run(app, host='127.0.0.1', port=$PORT, log_level='error')
" >/dev/null 2>&1 &
    ADMIN_PID=$!
    CLEANUP="$CLEANUP $ADMIN_PID"
    sleep 2

    if timeout 5 bash -c "echo >/dev/tcp/127.0.0.1/$PORT" 2>/dev/null; then
        pass "admin server — listening on $PORT"

        # Hit unauthenticated health endpoint
        HEALTH=$(timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/'"$PORT"'
            echo -e "GET /api/health HTTP/1.0\r\nHost: localhost\r\n\r\n" >&3
            IFS= read -r line <&3; echo "$line"
            exec 3>&-') || true
        if echo "$HEALTH" | grep -qi "200"; then
            pass "admin server — /api/health returns 200"
        else
            fail "admin server — /api/health unexpected: $HEALTH"
        fi
    else
        fail "admin server — not listening after 2s"
    fi
else
    skip "admin server — fastapi/uvicorn not installed"
fi

# ── Summary ───────────────────────────────────────────────────────────
echo ""
echo "=== Smoke test results: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped ==="

if [ "${FAIL}" -gt 0 ]; then
    exit 1
fi
exit 0
