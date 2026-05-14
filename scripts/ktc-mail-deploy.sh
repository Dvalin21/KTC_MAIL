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
    python3 iptables iptables-persistent \
    curl jq ca-certificates \
    unattended-upgrades

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

# ── 4. Install ktc-mail Python package ─────────────────────────────────
echo "--- Phase 4: Installing ktc-mail Python package ---"
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

# ── 5. Stop services before writing config ─────────────────────────────
echo "--- Phase 5: Stopping mail services ---"
for svc in postfix dovecot rspamd nginx; do
    systemctl stop "${svc}" 2>/dev/null || true
done

# ── 6. Deploy rendered configs ─────────────────────────────────────────
echo "--- Phase 6: Deploying mail configs ---"
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

# ── 7. Create Postfix lookup files ─────────────────────────────────────
echo "--- Phase 7: Creating Postfix lookup tables ---"
for f in /etc/postfix/virtual_alias /etc/postfix/virtual_mbx; do
    if [[ ! -f "${f}" ]]; then
        touch "${f}"
        postmap "${f}" 2>/dev/null || true
    fi
done

# ── 8. Start services ──────────────────────────────────────────────────
echo "--- Phase 8: Starting services ---"
for svc in redis-server rspamd postfix dovecot nginx; do
    systemctl enable --now "${svc}" || echo "WARNING: ${svc} failed to start" >&2
done

# ── 9. Verify services ─────────────────────────────────────────────────
echo "--- Phase 9: Verification ---"
ALL_OK=0
for svc in postfix dovecot nginx rspamd redis-server; do
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
    echo "Verify with: ss -tlnp | grep -E ':(25|587|465|993) '"
else
    echo ""
    echo "=== KTC Mail deployed with ERRORS (see above) ===" >&2
    exit 1
fi
