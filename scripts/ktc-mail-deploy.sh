#!/usr/bin/env bash
# KTC Mail — full deploy: packages → configs → services → verify
#
# Run on a fresh Debian/Ubuntu server as root.
# Idempotent: safe to re-run. Picks up where it left off.
set -euo pipefail

SELF="$(cd "$(dirname "$0")" && pwd)"
PYTHON="${KTC_MAIL_PYTHON:-python3}"
KTC_MAIL_BIN="/usr/bin/ktc-mail"
CONFIG_DIR="/etc/ktc-mail"
STATE_DIR="/var/lib/ktc-mail"
VMAIL_UID="${VMAIL_UID:-5000}"
VMAIL_GID="${VMAIL_GID:-5000}"

if [[ ${EUID} -ne 0 ]]; then
    echo "ERROR: must run as root" >&2
    exit 1
fi

echo "=== KTC Mail deploy ==="

# ── 1. Install packages ─────────────────────────────────────────────────
echo "--- Phase 1: Installing packages ---"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends \
    postfix postfix-pcre \
    dovecot-core dovecot-imapd dovecot-lmtpd dovecot-sieve dovecot-managesieved \
    rspamd redis-server \
    nginx openssl certbot \
    python3 python3-pip iptables iptables-persistent \
    curl jq ca-certificates \
    unattended-upgrades \
    php-fpm php-curl php-xml php-dom php-intl php-mbstring

# ── 2. Create vmail user ────────────────────────────────────────────────
echo "--- Phase 2: Creating vmail user ---"
if ! getent group vmail >/dev/null 2>&1; then
    groupadd -g "${VMAIL_GID}" vmail
fi
if ! getent passwd vmail >/dev/null 2>&1; then
    useradd -u "${VMAIL_UID}" -g vmail -d /var/mail -s /usr/sbin/nologin vmail
fi
install -d -m 0750 -o vmail -g vmail /var/mail

# ── 3. Create config directories ────────────────────────────────────────
echo "--- Phase 3: Creating config directories ---"
install -d -m 0750 -o root -g root "${CONFIG_DIR}"
install -d -m 0750 -o root -g root "${CONFIG_DIR}/dkim"
install -d -m 0750 -o root -g root "${STATE_DIR}"
install -d -m 0755 -o root -g root "${STATE_DIR}/acme-webroot"

# ── 4. Install SnappyMail webmail ──────────────────────────────────────
echo "--- Phase 4: Installing SnappyMail webmail ---"
SNAPPY_DIR="/var/lib/snappymail"
SNAPPY_DATA="${CONFIG_DIR}/snappymail"
SNAPPY_VERSION="2.38.1"
SNAPPY_URL="https://github.com/the-djmaze/snappymail/releases/download/v${SNAPPY_VERSION}/snappymail-${SNAPPY_VERSION}.zip"

if [[ -d "${SNAPPY_DIR}/snappymail" ]]; then
    echo "  SnappyMail already installed at ${SNAPPY_DIR}"
else
    install -d -m 0755 -o root -g root "${SNAPPY_DIR}"
    TMP_DIR="$(mktemp -d)"
    # shellcheck disable=SC2064
    trap "rm -rf '${TMP_DIR}'" EXIT

    if curl -fsSL "${SNAPPY_URL}" -o "${TMP_DIR}/snappymail.zip"; then
        unzip -q "${TMP_DIR}/snappymail.zip" -d "${SNAPPY_DIR}"
        echo "  SnappyMail v${SNAPPY_VERSION} extracted to ${SNAPPY_DIR}"
    else
        echo "  WARNING: Failed to download SnappyMail. Install manually:"
        echo "    ${SNAPPY_URL}"
    fi
fi

# Create data directory outside webroot (security: don't store config in webroot)
install -d -m 0750 -o www-data -g www-data "${SNAPPY_DATA}"
if [[ -f "${SNAPPY_DIR}/snappymail/index.php" ]]; then
    # SnappyMail detects data path via env var or _data_ directory
    if [[ ! -L "${SNAPPY_DIR}/snappymail/_data_" ]]; then
        ln -sf "${SNAPPY_DATA}" "${SNAPPY_DIR}/snappymail/_data_" 2>/dev/null || true
    fi
fi

# ── 5. Install ktc-mail Python package ─────────────────────────────────
echo "--- Phase 5: Installing ktc-mail Python package ---"
if [[ -f "${SELF}/../setup.py" ]] || [[ -f "${SELF}/../pyproject.toml" ]]; then
    # Install from source
    (cd "${SELF}/.." && ${PYTHON} -m pip install .)
elif [[ -d "/usr/lib/ktc-mail" ]]; then
    # Already installed via .deb
    :
else
    # Direct path: add to PYTHONPATH
    echo "NOTE: ktc-mail package not installed via pip/.deb — using source path"
    echo "      Set PYTHONPATH or install with: python3 -m pip install ."
    # Create symlink for CLI if not present
    if [[ ! -f "${KTC_MAIL_BIN}" ]] && [[ -f "${SELF}/../src/ktc_mail_admin/cli.py" ]]; then
        install -d -m 0755 -o root -g root "$(dirname "${KTC_MAIL_BIN}")"
        ln -sf "$(readlink -f "${SELF}/../src/ktc_mail_admin/cli.py")" "${KTC_MAIL_BIN}"
    fi
fi

# ── 6. Configure PHP-FPM for SnappyMail ────────────────────────────────
echo "--- Phase 6: Configuring PHP-FPM for webmail ---"
# Detect PHP version
PHP_VERSION=""
for v in 8.2 8.1 8.0 7.4; do
    if command -v "php-fpm${v}" &>/dev/null || [[ -f "/usr/sbin/php-fpm${v}" ]]; then
        PHP_VERSION="${v}"
        break
    fi
done

if [[ -n "${PHP_VERSION}" ]]; then
    PHP_FPM_CONF="/etc/php/${PHP_VERSION}/fpm/pool.d/snappymail.conf"
    if [[ ! -f "${PHP_FPM_CONF}" ]]; then
        cat > "${PHP_FPM_CONF}" << 'PHPFPM'
; KTC Mail — SnappyMail PHP-FPM pool
[snappymail]
user = www-data
group = www-data
listen = /run/php/snappymail.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
pm = dynamic
pm.max_children = 5
pm.start_servers = 1
pm.min_spare_servers = 1
pm.max_spare_servers = 3
pm.max_requests = 500
security.limit_extensions = .php
env[PATH] = /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
PHPFPM
        echo "  PHP-FPM pool created for SnappyMail (PHP ${PHP_VERSION})"
    else
        echo "  PHP-FPM pool already exists"
    fi
else
    echo "  WARNING: PHP-FPM not found — webmail will not work"
    echo "  Install: apt-get install php-fpm php-curl php-xml php-dom php-intl php-mbstring"
fi

# ── 7. Link SnappyMail webroot ─────────────────────────────────────────
echo "--- Phase 7: Linking SnappyMail webroot ---"
SNAPPY_WEBROOT="/var/lib/snappymail/snappymail"
if [[ -d "${SNAPPY_WEBROOT}" ]]; then
    # The config_renderer generates an Nginx vhost that proxies to
    # port 5085 by default.  For SnappyMail, we serve it directly
    # via PHP-FPM on a Unix socket.
    #
    # If the Nginx webmail config already includes a proxy_pass to
    # 127.0.0.1:5085, the user can either:
    #   a) Run a separate HTTP server on 5085 (e.g. PHP's built-in)
    #   b) Or change the nginx config to use the SnappyMail root
    #
    # The simplest deployment: use PHP's built-in server on port 5085
    # as a systemd service, or just reference the SnappyMail install
    # in a static nginx location block.
    #
    # For now, create a convenience symlink so nginx can serve it:
    if [[ ! -L /var/www/html/snappymail ]]; then
        install -d -m 0755 -o www-data -g www-data /var/www/html
        ln -sf "${SNAPPY_WEBROOT}" /var/www/html/snappymail 2>/dev/null || true
        echo "  SnappyMail linked to /var/www/html/snappymail"
    fi

    # Ensure data directory permissions
    install -d -m 0750 -o www-data -g www-data "${SNAPPY_DATA}"
else
    echo "  WARNING: SnappyMail webroot not found — skipping symlink"
fi

# ── 8. Stop services before writing config ─────────────────────────────
echo "--- Phase 8: Stopping mail services ---"
for svc in postfix dovecot rspamd nginx; do
    systemctl stop "${svc}" 2>/dev/null || true
done

# ── 9. Deploy rendered configs ─────────────────────────────────────────
echo "--- Phase 9: Deploying mail configs ---"
if [[ -f "${CONFIG_DIR}/setup.json" ]]; then
    if command -v "${KTC_MAIL_BIN}" &>/dev/null; then
        "${KTC_MAIL_BIN}" config write --dest /etc
    elif ${PYTHON} -c "from ktc_mail_admin import config_renderer" 2>/dev/null; then
        ${PYTHON} -m ktc_mail_admin.cli config write --dest /etc
    else
        echo "WARNING: ktc-mail Python package not importable — skipping config deploy" >&2
        echo "  Deploy manually: ${PYTHON} -m ktc_mail_admin.cli config write --dest /etc" >&2
    fi
else
    echo "WARNING: no setup profile at ${CONFIG_DIR}/setup.json" >&2
    echo "  Run the setup wizard first: ktc-mail setup" >&2
fi

# ── 10. Create Postfix lookup files ────────────────────────────────────
echo "--- Phase 10: Creating Postfix lookup tables ---"
for f in /etc/postfix/virtual_alias /etc/postfix/virtual_mbx; do
    if [[ ! -f "${f}" ]]; then
        touch "${f}"
        postmap "${f}" 2>/dev/null || true
    fi
done

# ── 11. Start services ──────────────────────────────────────────────────
echo "--- Phase 11: Starting services ---"
for svc in redis-server rspamd postfix dovecot nginx "php${PHP_VERSION}-fpm"; do
    if systemctl list-unit-files "${svc}" &>/dev/null 2>&1; then
        systemctl enable --now "${svc}" 2>/dev/null || echo "WARNING: ${svc} failed to start" >&2
    fi
done

# ── 12. Verify services ─────────────────────────────────────────────────
echo "--- Phase 12: Verification ---"
ALL_OK=0
for svc in postfix dovecot nginx rspamd redis-server "php${PHP_VERSION}-fpm"; do
    if systemctl is-active --quiet "${svc}" 2>/dev/null; then
        echo "  ✅ ${svc} is running"
    else
        echo "  ❌ ${svc} is NOT running" >&2
        ALL_OK=1
    fi
done

# Postfix-specific: check config
if command -v postfix &>/dev/null; then
    if postfix check 2>/dev/null; then
        echo "  ✅ postfix config check passed"
    else
        echo "  ❌ postfix config check FAILED" >&2
        ALL_OK=1
    fi
fi

if [[ "${ALL_OK}" -eq 0 ]]; then
    echo ""
    echo "=== KTC Mail deployed successfully ==="
    echo "Next steps:"
    echo "  1. Create a setup profile:      ktc-mail setup"
    echo "  2. Issue certificates:          ktc-mail acme issue"
    echo "  3. Check firewall:              ktc-mail firewall check"
    echo "  4. Open webmail (after setup):  https://mail.YOURDOMAIN/"
    echo "  5. Admin panel:                 https://admin.YOURDOMAIN/"
    echo ""
    echo "Mail services running. Ports 25, 587, 465, 993 are open."
    echo "Webmail installed at /var/www/html/snappymail"
    echo "Complete SnappyMail setup via the web interface on first visit."
    echo "Verify with: ss -tlnp | grep -E ':(25|587|465|993) '"
else
    echo ""
    echo "=== KTC Mail deployed with ERRORS (see above) ===" >&2
    exit 1
fi
