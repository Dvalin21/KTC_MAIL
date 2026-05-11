#!/usr/bin/env bash
set -euo pipefail

command=${1:-render}
config=${2:-/etc/ktc-mail/setup.json}
output_dir=${3:-/var/lib/ktc-mail/security-controls}

case "${command}" in
  render)
    /usr/lib/ktc-mail/security_controls.py render --config "${config}" --output-dir "${output_dir}"
    ;;
  check)
    /usr/lib/ktc-mail/security_controls.py check --config "${config}"
    ;;
  enforce-nft)
    /usr/lib/ktc-mail/security_controls.py enforce-nft --config "${config}"
    ;;
  dry-run-enforce-nft)
    /usr/lib/ktc-mail/security_controls.py enforce-nft --config "${config}" --dry-run
    ;;
  *)
    echo "usage: $0 {render|check|enforce-nft|dry-run-enforce-nft} [setup.json] [output-dir]" >&2
    exit 2
    ;;
esac
