#!/usr/bin/env bash
set -euo pipefail

ports=(22 25 80 443 587 993 4190)
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
