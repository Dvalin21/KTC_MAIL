#!/usr/bin/env bash
# KTC Mail — open firewall ports (thin wrapper around ktc-mail firewall enforce).
#
# This script is a convenience wrapper that delegates to the Python CLI.
# Direct nftables calls are only used when ktc-mail is unavailable
# (e.g. rescue mode, before the package is installed).
set -euo pipefail

config="${1:-/etc/ktc-mail/setup.json}"

# Prefer the Python CLI
if command -v ktc-mail &>/dev/null; then
    exec ktc-mail firewall --enforce --config "${config}"
fi

# Fallback: direct nftables
if ! command -v nft &>/dev/null; then
    echo "ERROR: neither ktc-mail nor nft found — cannot configure firewall" >&2
    exit 1
fi

# Extract ports from config, or use defaults
if [[ -r "${config}" ]]; then
    mapfile -t ports < <(python3 - "${config}" <<'PY'
import json, sys
payload = json.loads(open(sys.argv[1]))
sec = payload.get("security", {})
ports = sec.get("ports_open", payload.get("open_ports", [22, 25, 443, 587, 993]))
seen = set()
for p in ports:
    p = int(p)
    if 1 <= p <= 65535:
        seen.add(p)
for p in sorted(seen):
    print(p)
PY
    )
else
    ports=(22 25 443 587 993)
fi

port_set="$(IFS=,; echo "${ports[*]}")"

nft add table inet ktc_mail 2>/dev/null || true
nft add chain inet ktc_mail INPUT '{ type filter hook input priority 0; policy drop; }' 2>/dev/null || true
nft flush chain inet ktc_mail INPUT 2>/dev/null || true
nft add rule inet ktc_mail INPUT ct state established,related accept
nft add rule inet ktc_mail INPUT iif lo accept
nft add rule inet ktc_mail INPUT tcp dport "{ ${port_set} }" accept
