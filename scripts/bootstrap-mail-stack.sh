#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root on a fresh Debian/Ubuntu server." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y \
  postfix postfix-pcre dovecot-core dovecot-imapd dovecot-lmtpd dovecot-sieve dovecot-managesieved \
  rspamd redis-server fail2ban python3 python3-venv nginx openssl certbot ca-certificates curl jq \
  nftables unattended-upgrades python3-qrcode

# Enable but DO NOT start mail services yet — they need KTC Mail config first.
# The setup GUI (ktc-mail-setup.service) will start them after the wizard completes.
systemctl enable redis-server rspamd fail2ban postfix dovecot nginx
systemctl restart redis-server  # Redis is needed by Rspamd during setup

install -d -m 0750 -o root -g root /etc/ktc-mail /var/lib/ktc-mail

echo "KTC Mail package dependencies are installed. Open http://SERVER_IP:8080 to continue setup."
