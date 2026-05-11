#!/usr/bin/env bash
set -euo pipefail

command=${1:-render}
config=${2:-/etc/ktc-mail/setup.json}
output_dir=${3:-/var/lib/ktc-mail/ops-controls}

/usr/lib/ktc-mail/ops_controls.py "${command}" --config "${config}" --output-dir "${output_dir}"
