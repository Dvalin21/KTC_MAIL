#!/usr/bin/env bash
set -euo pipefail

config=${1:-/etc/ktc-mail/setup.json}
if command -v /usr/lib/ktc-mail/security_controls.py >/dev/null 2>&1 && command -v nft >/dev/null 2>&1; then
  /usr/lib/ktc-mail/security_controls.py enforce-nft --config "${config}"
  exit 0
fi

if [[ -r "${config}" ]]; then
  mapfile -t ports < <(python3 - "${config}" <<'PY'
import json
import sys
from pathlib import Path
payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for port in sorted({int(port) for port in payload.get("open_ports", [22, 25, 443, 587, 993, 4190])}):
    if port < 1 or port > 65535:
        raise SystemExit(f"invalid TCP port: {port}")
    print(port)
PY
)
else
  ports=(22 25 443 587 993 4190)
fi

for bin in iptables ip6tables; do
  $bin -N KTC-MAIL-IN 2>/dev/null || true
  $bin -D INPUT -j KTC-MAIL-IN 2>/dev/null || true
  $bin -I INPUT 1 -j KTC-MAIL-IN
  $bin -F KTC-MAIL-IN
  $bin -A KTC-MAIL-IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  $bin -A KTC-MAIL-IN -i lo -j ACCEPT
  for port in "${ports[@]}"; do
    $bin -A KTC-MAIL-IN -p tcp -m tcp --dport "$port" -j ACCEPT
  done
  $bin -A KTC-MAIL-IN -j DROP
done
