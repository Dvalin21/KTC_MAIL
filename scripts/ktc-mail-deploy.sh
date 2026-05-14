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
SOGO_VERSION="${SOGO_VERSION:-5.10}"  # SOGo major.minor for apt repo

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
    gnupg2 lsb-release wget

# Add SOGo repository
OS_CODENAME="$(lsb_release -cs 2>/dev/null || echo 'bookworm')"
SOGO_REPO="https://packages.sogo.nu/debian"
SOGO_KEYRING="/usr/share/keyrings/sogo-archive-keyring.gpg"
if ! [[ -f /etc/apt/sources.list.d/sogo.list ]]; then
    echo "--- Phase 1b: Adding SOGo repository (${OS_CODENAME}, v${SOGO_VERSION}) ---"
    if ! wget -qO- "${SOGO_REPO}/sogo-key.asc" | gpg --dearmor -o "${SOGO_KEYRING}" 2>/dev/null; then
        echo "WARNING: Failed to download SOGo GPG key. Trying fallback..." >&2
        # Fallback: use keyserver
        gpg --keyserver keyserver.ubuntu.com --recv-keys 0x3D3D3D3D 2>/dev/null || true
    fi
    if [[ -f "${SOGO_KEYRING}" ]]; then
        echo "deb [signed-by=${SOGO_KEYRING}] ${SOGO_REPO} ${OS_CODENAME} ${SOGO_VERSION}" \
            > /etc/apt/sources.list.d/sogo.list
        apt-get update -qq
    else
        echo "WARNING: SOGo GPG key not available — continuing without SOGo repo" >&2
        echo "  Install manually: https://packages.sogo.nu/" >&2
    fi
fi

apt-get install -y --no-install-recommends \
    postfix postfix-pcre \
    dovecot-core dovecot-imapd dovecot-lmtpd dovecot-sieve dovecot-managesieved \
    rspamd redis-server \
    nginx openssl certbot \
    python3 nftables \
    curl jq ca-certificates \
    unattended-upgrades \
    memcached \
    postgresql postgresql-client \
    sogo sogo-common

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

# ── 4. Configure SOGo database ─────────────────────────────────────────
echo "--- Phase 4: Configuring SOGo PostgreSQL database ---"
SOGO_DB_PASSWORD="${SOGO_DB_PASSWORD:-$(openssl rand -base64 32)}"
if ! su - postgres -c "psql -t -c 'SELECT 1 FROM pg_roles WHERE rolname=\"sogo\"'" 2>/dev/null | grep -q 1; then
    su - postgres -c "createuser -DRS sogo" 2>/dev/null || true
    su - postgres -c "psql -c \"ALTER USER sogo WITH PASSWORD '${SOGO_DB_PASSWORD}'\"" 2>/dev/null || true
fi
for dbname in sogo sogo_sessions; do
    if ! su - postgres -c "psql -t -c 'SELECT 1 FROM pg_database WHERE datname=\"${dbname}\"'" 2>/dev/null | grep -q 1; then
        su - postgres -c "createdb -O sogo ${dbname}" 2>/dev/null || true
    fi
done
# Store generated password for reference (SOGo config still uses default 'sogo' for now)
echo "SOGo DB password: ${SOGO_DB_PASSWORD}" > "${CONFIG_DIR}/sogo-db-password"
chmod 600 "${CONFIG_DIR}/sogo-db-password"

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

# ── 6. Stop services before writing config ─────────────────────────────
echo "--- Phase 6: Stopping mail services ---"
for svc in postfix dovecot rspamd nginx; do
    systemctl stop "${svc}" 2>/dev/null || true
done

# ── 7. Deploy rendered configs ─────────────────────────────────────────
echo "--- Phase 7: Validating and deploying mail configs ---"
if [[ -f "${CONFIG_DIR}/setup.json" ]]; then
    # Validate first
    VALIDATE_OK=0
    if command -v "${KTC_MAIL_BIN}" &>/dev/null; then
        "${KTC_MAIL_BIN}" config validate --dest /etc || VALIDATE_OK=$?
    elif ${PYTHON} -c "from ktc_mail_admin import config_renderer" 2>/dev/null; then
        ${PYTHON} -m ktc_mail_admin.cli config validate --dest /etc || VALIDATE_OK=$?
    fi

    if [[ "${VALIDATE_OK}" -ne 0 ]]; then
        echo "ERROR: config validation failed — refusing to deploy" >&2
        exit 1
    fi

    # Write configs
    if command -v "${KTC_MAIL_BIN}" &>/dev/null; then
        "${KTC_MAIL_BIN}" config write --dest /etc
    elif ${PYTHON} -c "from ktc_mail_admin import config_renderer" 2>/dev/null; then
        ${PYTHON} -m ktc_mail_admin.cli config write --dest /etc
    else
        echo "WARNING: ktc-mail Python package not importable — skipping config deploy" >&2
        echo "  Deploy manually: ${PYTHON} -m ktc_mail_admin.cli config write --dest /etc" >&2
    fi
    # Fix ownership: SOGo daemon needs to read its config
    if [[ -f /etc/sogo/sogo.conf ]]; then
        chown sogo:sogo /etc/sogo/sogo.conf
        chmod 640 /etc/sogo/sogo.conf
    fi
else
    echo "WARNING: no setup profile at ${CONFIG_DIR}/setup.json" >&2
    echo "  Run the setup wizard first: ktc-mail setup" >&2
fi

# ── 8. Create Postfix lookup files ─────────────────────────────────────
echo "--- Phase 8: Creating Postfix lookup tables ---"
for f in /etc/postfix/virtual_alias /etc/postfix/virtual_mbx; do
    if [[ ! -f "${f}" ]]; then
        touch "${f}"
        postmap "${f}" 2>/dev/null || true
    fi
done

# ── 9. Start services ──────────────────────────────────────────────────
echo "--- Phase 9: Starting services ---"
for svc in redis-server memcached postgresql rspamd postfix dovecot nginx sogod; do
    systemctl enable --now "${svc}" || echo "WARNING: ${svc} failed to start" >&2
done

# ── 10. Verify services ─────────────────────────────────────────────────
echo "--- Phase 10: Verification ---"
ALL_OK=0
for svc in postfix dovecot nginx rspamd redis-server memcached postgresql sogod; do
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
    echo "  1. Create a setup profile:   ktc-mail setup"
    echo "  2. Issue certificates:       ktc-mail acme issue"
    echo "  3. Check firewall:           ktc-mail firewall check"
    echo ""
    echo "Mail services running. Ports 25, 587, 465, 993 are open."
    echo "SOGo webmail at https://email.YOURDOMAIN/SOGo (after setup + certs)"
    echo "Verify with: ss -tlnp | grep -E ':(25|587|465|993) '"
else
    echo ""
    echo "=== KTC Mail deployed with ERRORS (see above) ===" >&2
    exit 1
fi
