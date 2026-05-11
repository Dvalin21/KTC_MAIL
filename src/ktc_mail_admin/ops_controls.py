#!/usr/bin/env python3
"""Phase 6 backup, restore, and observability controls for KTC Mail."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

CONFIG_DIR = Path(os.environ.get("KTC_MAIL_CONFIG_DIR", "/etc/ktc-mail"))
STATE_DIR = Path(os.environ.get("KTC_MAIL_STATE_DIR", "/var/lib/ktc-mail"))
SETUP_PATH = CONFIG_DIR / "setup.json"
OUTPUT_DIR = STATE_DIR / "ops-controls"
DEFAULT_BACKUP_PATHS = ["/etc/ktc-mail", "/var/lib/ktc-mail", "/var/vmail", "/var/lib/rspamd/dkim"]


class OpsError(RuntimeError):
    """Raised when ops controls cannot be rendered or checked."""


def load_setup(path: Path) -> dict[str, Any]:
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {"domain": "example.com", "hostname": "mail.example.com", "admin_email": "admin@example.com"}


def ops_policy(setup: dict[str, Any]) -> dict[str, Any]:
    configured = setup.get("ops_controls", {})
    return {
        "backup_repository": configured.get("backup_repository", "sftp:user@backup-host:/srv/restic/ktc-mail"),
        "backup_paths": configured.get("backup_paths", DEFAULT_BACKUP_PATHS),
        "retention": configured.get("retention", {"daily": 7, "weekly": 4, "monthly": 6}),
        "queue_alert_threshold": int(configured.get("queue_alert_threshold", 500)),
        "disk_alert_percent": int(configured.get("disk_alert_percent", 85)),
        "certificate_expiry_days": int(configured.get("certificate_expiry_days", 21)),
        "audit_log_target": configured.get("audit_log_target", "local-jsonl; remote syslog/SIEM pending"),
    }


def restic_env(policy: dict[str, Any]) -> str:
    return f"""# Managed by KTC Mail. Fill RESTIC_PASSWORD_FILE before enabling backups.
RESTIC_REPOSITORY={policy['backup_repository']}
RESTIC_PASSWORD_FILE=/etc/ktc-mail/restic-password
"""


def backup_script(policy: dict[str, Any]) -> str:
    paths = " ".join(policy["backup_paths"])
    retention = policy["retention"]
    return f"""#!/usr/bin/env bash
set -euo pipefail
source /etc/ktc-mail/restic.env
restic backup {paths}
restic forget --prune --keep-daily {retention['daily']} --keep-weekly {retention['weekly']} --keep-monthly {retention['monthly']}
"""


def restore_drill_script() -> str:
    return """#!/usr/bin/env bash
set -euo pipefail
source /etc/ktc-mail/restic.env
target=${1:-/tmp/ktc-mail-restore-drill}
mkdir -p "${target}"
restic restore latest --target "${target}"
find "${target}" -maxdepth 3 -type f | sort | sed -n '1,50p'
"""


def health_check_script(policy: dict[str, Any]) -> str:
    return f"""#!/usr/bin/env bash
set -euo pipefail
queue_threshold={policy['queue_alert_threshold']}
disk_threshold={policy['disk_alert_percent']}
cert_days={policy['certificate_expiry_days']}
queue_count=$(mailq 2>/dev/null | awk '/^[A-F0-9]/{{c++}} END{{print c+0}}')
if (( queue_count > queue_threshold )); then
  echo "CRIT queue_depth=${{queue_count}} threshold=${{queue_threshold}}"
  exit 2
fi
disk_used=$(df -P /var/vmail 2>/dev/null | awk 'NR==2{{gsub(/%/,"",$5); print $5+0}}')
if [[ -n "${{disk_used}}" ]] && (( disk_used > disk_threshold )); then
  echo "CRIT disk_used=${{disk_used}} threshold=${{disk_threshold}}"
  exit 2
fi
cert=/etc/letsencrypt/live/ktc-mail/fullchain.pem
if [[ -r "${{cert}}" ]]; then
  if ! openssl x509 -checkend $((cert_days*86400)) -noout -in "${{cert}}" >/dev/null; then
    echo "WARN certificate expires within ${{cert_days}} days"
    exit 1
  fi
fi
echo "OK queue_depth=${{queue_count}} disk_used=${{disk_used:-unknown}}"
"""


def dns_drift_script() -> str:
    return """#!/usr/bin/env bash
set -euo pipefail
config=${1:-/etc/ktc-mail/setup.json}
python3 - <<'PYCHECK' "${config}"
import json, sys
setup=json.load(open(sys.argv[1]))
for record in setup.get('dns_records', []):
    if record.get('type') in {'A','AAAA','MX','TXT','CNAME'} and not str(record.get('value','')).startswith('<'):
        print(f"CHECK {record['type']} {record['name']} expected={record['value']}")
PYCHECK
"""


def render(setup: dict[str, Any]) -> dict[str, str]:
    policy = ops_policy(setup)
    return {
        "restic.env.example": restic_env(policy),
        "bin/ktc-mail-backup.sh": backup_script(policy),
        "bin/ktc-mail-restore-drill.sh": restore_drill_script(),
        "bin/ktc-mail-health-check.sh": health_check_script(policy),
        "bin/ktc-mail-dns-drift-check.sh": dns_drift_script(),
        "ops-policy.json": json.dumps(policy, indent=2) + "\n",
    }


def write_outputs(files: dict[str, str], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for relative, content in files.items():
        target = output_dir / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        target.chmod(0o750 if relative.startswith("bin/") else 0o640)


def run(command: list[str], dry_run: bool) -> None:
    if dry_run:
        print("dry-run:", " ".join(command))
        return
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode != 0:
        raise OpsError(f"command failed {' '.join(command)}: {result.stderr.strip()}")
    if result.stdout.strip():
        print(result.stdout.strip())


def check(config_path: Path) -> dict[str, Any]:
    setup = load_setup(config_path)
    policy = ops_policy(setup)
    return {"phase": "Phase 6", "backup_paths": policy["backup_paths"], "alerts": {"queue": policy["queue_alert_threshold"], "disk": policy["disk_alert_percent"], "cert_days": policy["certificate_expiry_days"]}, "rendered_files": sorted(render(setup))}


def main() -> int:
    parser = argparse.ArgumentParser(description="Render/check KTC Mail Phase 6 ops controls")
    parser.add_argument("command", choices=("render", "check", "backup", "restore-drill", "health-check"))
    parser.add_argument("--config", type=Path, default=SETUP_PATH)
    parser.add_argument("--output-dir", type=Path, default=OUTPUT_DIR)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "check":
            print(json.dumps(check(args.config), indent=2))
            return 0
        if args.command == "render":
            write_outputs(render(load_setup(args.config)), args.output_dir)
            print(f"rendered Phase 6 controls into {args.output_dir}")
            return 0
        files = render(load_setup(args.config))
        write_outputs(files, args.output_dir)
        script_map = {"backup": "bin/ktc-mail-backup.sh", "restore-drill": "bin/ktc-mail-restore-drill.sh", "health-check": "bin/ktc-mail-health-check.sh"}
        run([str(args.output_dir / script_map[args.command])], dry_run=args.dry_run)
        return 0
    except (OSError, json.JSONDecodeError, OpsError, KeyError, ValueError) as exc:
        print(f"ops controls error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
