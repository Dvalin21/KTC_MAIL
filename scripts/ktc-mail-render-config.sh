#!/usr/bin/env bash
set -euo pipefail

config=${1:-/etc/ktc-mail/setup.json}
output_dir=${2:-/var/lib/ktc-mail/rendered-config}

/usr/lib/ktc-mail/config_render.py --config "${config}" --output-dir "${output_dir}"
cat <<MSG
Rendered mail stack configuration to ${output_dir}.
Review before copying into /etc/postfix, /etc/dovecot, /etc/rspamd, /etc/nginx, or /etc/sogo.
MSG
