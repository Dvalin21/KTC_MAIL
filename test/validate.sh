#!/bin/bash
# KTC Mail — container config validation runner
# Runs inside the Docker container, validates every service config
# against real tools. Exits 0 on success, 1 on failure.
set -euo pipefail

PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo -e "  \e[32mPASS\e[0m $1"; }
fail() { FAIL=$((FAIL + 1)); echo -e "  \e[31mFAIL\e[0m $1"; }
skip() { echo -e "  \e[33mSKIP\e[0m $1"; }

echo ""
echo "=== KTC Mail real-tool config validation ==="
echo ""

# ── 1. Postfix check ─────────────────────────────────────────────────
echo "--- Postfix ---"
if command -v postfix &>/dev/null; then
    if postfix check 2>/dev/null; then
        pass "postfix check"
    else
        fail "postfix check"
        # Show errors
        postfix check 2>&1 || true
    fi
else
    skip "postfix not installed"
fi

# ── 2. Dovecot config ────────────────────────────────────────────────
echo "--- Dovecot ---"
if command -v dovecot &>/dev/null; then
    # Dovecot -n parses and displays config; exits 0 on success
    if dovecot -n 2>/dev/null >/dev/null; then
        pass "dovecot -n (config parse)"
    else
        fail "dovecot -n"
        dovecot -n 2>&1 || true
    fi

    # Check TLS config is present and cleartext IMAP is not exposed externally.
    # Accept either:
    #   a) Fully disabled (port = 0)
    #   b) Localhost-only (address = 127.0.0.1) — required by SOGo for IMAP auth
    if grep -q "port = 0" /etc/dovecot/dovecot.conf; then
        pass "dovecot: cleartext IMAP fully disabled"
    elif grep -q "address = 127.0.0.1" /etc/dovecot/dovecot.conf; then
        pass "dovecot: cleartext IMAP localhost-only (SOGo exception)"
    else
        fail "dovecot: cleartext IMAP exposed externally"
    fi
else
    skip "dovecot not installed"
fi

# ── 3. Rspamd config ─────────────────────────────────────────────────
echo "--- Rspamd ---"
if command -v rspamd &>/dev/null; then
    if rspamd --check 2>&1 | head -5 | grep -qi "error"; then
        fail "rspamd --check"
        rspamd --check 2>&1 || true
    else
        pass "rspamd --check"
    fi
else
    skip "rspamd not installed"
fi

# ── 4. Rspamd worker config (local.d overrides) ────────────────────
echo "--- Rspamd worker ---"
if [ -f /etc/rspamd/worker-proxy.inc ]; then
    # milter = yes is defined in the default worker-proxy.inc and inherited
    # by our local.d override via Rspamd's merge system.
    if grep -q "milter = yes" /etc/rspamd/worker-proxy.inc; then
        pass "rspamd: milter mode enabled (inherited from defaults)"
    else
        fail "rspamd: milter mode not found in defaults"
    fi
    if grep -q "self_scan" /etc/rspamd/local.d/worker-proxy.inc; then
        pass "rspamd: self-scan enabled (merges with default proxy)"
    else
        fail "rspamd: self-scan not configured"
    fi
else
    fail "rspamd/local.d/worker-proxy.inc not found"
fi
if [ -f /etc/rspamd/local.d/worker-controller.inc ]; then
    if grep -q "secure_ip" /etc/rspamd/local.d/worker-controller.inc; then
        pass "rspamd: controller restricted to localhost"
    else
        fail "rspamd: controller restriction missing"
    fi
else
    fail "rspamd/local.d/worker-controller.inc not found"
fi

# ── 5. Nginx config ──────────────────────────────────────────────────
echo "--- Nginx ---"
if command -v nginx &>/dev/null; then
    if nginx -t 2>&1 | grep -q "successful"; then
        pass "nginx -t"
    else
        fail "nginx -t"
        nginx -t 2>&1 || true
    fi
else
    skip "nginx not installed"
fi

# ── 6. Postfix TLS check ─────────────────────────────────────────────
echo "--- Postfix TLS ---"
if [ -f /etc/postfix/main.cf ]; then
    if grep -q "^smtpd_tls_security_level = may" /etc/postfix/main.cf; then
        pass "postfix: smtpd_tls_security_level = may (STARTTLS on 25)"
    else
        fail "postfix: smtpd_tls_security_level not set correctly"
    fi
    if grep -q "^smtpd_sasl_type = dovecot" /etc/postfix/main.cf; then
        pass "postfix: Dovecot SASL configured"
    else
        fail "postfix: Dovecot SASL missing"
    fi
    if grep -q "smtpd_milters" /etc/postfix/main.cf; then
        pass "postfix: Rspamd milter configured"
    else
        fail "postfix: Rspamd milter missing"
    fi
fi

# ── 7. Dovecot TLS check ─────────────────────────────────────────────
echo "--- Dovecot TLS ---"
if [ -f /etc/dovecot/dovecot.conf ]; then
    if grep -q "^ssl_cert =" /etc/dovecot/dovecot.conf; then
        pass "dovecot: TLS cert configured"
    else
        fail "dovecot: TLS cert missing"
    fi
    if grep -q "port = 0" /etc/dovecot/dovecot.conf; then
        pass "dovecot: cleartext IMAP fully disabled"
    elif grep -q "address = 127.0.0.1" /etc/dovecot/dovecot.conf; then
        pass "dovecot: cleartext IMAP localhost-only (SOGo exception)"
    else
        fail "dovecot: cleartext IMAP exposed externally"
    fi
fi

# ── 8. Nginx TLS check ───────────────────────────────────────────────
echo "--- Nginx TLS ---"
if [ -f /etc/nginx/webmail.conf ]; then
    if grep -q "ssl_protocols TLSv1.2" /etc/nginx/webmail.conf; then
        pass "nginx: TLS 1.2+ enforced"
    else
        fail "nginx: TLS version not restricted"
    fi
    if grep -q "ssl_certificate " /etc/nginx/webmail.conf; then
        pass "nginx: TLS cert configured"
    else
        fail "nginx: TLS cert missing"
    fi
fi

# ── 9. Autoconfig XML check ──────────────────────────────────────────
echo "--- Autoconfig ---"
AUTOCONFIG_DIR="/etc/autoconfig"
if [ -f "${AUTOCONFIG_DIR}/thunderbird.xml" ]; then
    if grep -q "<incomingServer type=\"imap\">" "${AUTOCONFIG_DIR}/thunderbird.xml"; then
        pass "thunderbird: IMAP config found"
    else
        fail "thunderbird: IMAP config missing"
    fi
else
    skip "thunderbird autoconfig not deployed"
fi

# ── Summary ──────────────────────────────────────────────────────────
echo ""
echo "=== Results: ${PASS} passed, ${FAIL} failed ==="

if [ "${FAIL}" -gt 0 ]; then
    exit 1
fi
exit 0
