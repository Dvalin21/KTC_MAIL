#!/usr/bin/env python3
"""KTC Mail — Prometheus textfile collector for mail server health.

Output goes to ``/var/lib/ktc-mail/metrics.prom`` for the node_exporter
textfile collector.  Run periodically via systemd timer.

Metrics:
  - Service status (0=down, 1=up)
  - Queue depth
  - Mail user count
  - Certificate expiry (days remaining)
  - DNS last-verified timestamp
  - Backup last-success timestamp
  - Fail2ban banned IP count
  - Build info

Usage:
  ktc-mail metrics collect
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from .config import (
    CONFIG_DIR,
    STATE_DIR,
    SETUP_PATH,
    TLS_STATE_PATH,
    DNS_STATE_PATH,
    read_json,
)
from . import user_manager as um

# Path where node_exporter's textfile collector reads
METRICS_PATH = STATE_DIR / "metrics.prom"
TMP_METRICS_PATH = STATE_DIR / "metrics.prom.tmp"

# Services to monitor
TRACKED_SERVICES = ("postfix", "dovecot", "rspamd", "nginx", "redis-server")


# ── Helpers ────────────────────────────────────────────────────────────────


def _run(cmd: list[str], timeout: int = 10) -> subprocess.CompletedProcess[str]:
    """Run a command with a timeout.  Returns a CompletedProcess with
    ``stdout`` and ``stderr`` always set (empty string on failure)."""
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return subprocess.CompletedProcess(cmd, -1, "", "")


# ── Metric builders ────────────────────────────────────────────────────────


def _service_metrics() -> list[str]:
    """Collect up/down status for each tracked service.

    Returns lines like::
        ktc_mail_service_up{name="postfix"} 1
    """
    lines: list[str] = []
    for svc in TRACKED_SERVICES:
        result = _run(["systemctl", "is-active", svc])
        up = 1 if result.stdout.strip() == "active" else 0
        lines.append(f'ktc_mail_service_up{{name="{svc}"}} {up}')
    return lines


def _queue_depth() -> int:
    """Count queued messages via postqueue -p."""
    result = _run(["postqueue", "-p"])
    output = result.stdout.strip()
    if not output or "mail queue is empty" in output:
        return 0
    if result.returncode != 0:
        return -1
    # Count queue IDs: each starts with a hex string at the beginning of a line
    count = 0
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or len(stripped) < 10:
            continue
        parts = stripped.split()
        if len(parts) >= 5 and parts[0].isalnum() and parts[1].isdigit():
            count += 1
    return count


def _user_count() -> int:
    """Count active mail users from the Dovecot passwd file."""
    lines = um._read_lines(um.PASSWD_FILE)
    return sum(1 for l in lines if um._parse_passwd(l) is not None)


def _cert_expiry() -> float:
    """Return days until the TLS certificate expires (0 if expired)."""
    if not TLS_STATE_PATH.exists():
        return -1.0
    try:
        from .admin_server import _cert_info_from_path, _cert_expiry_days
        from pathlib import Path
        # Standard Let's Encrypt paths
        cert_path = Path("/etc/letsencrypt/live/ktc-mail/fullchain.pem")
        if cert_path.exists():
            info = _cert_info_from_path(str(cert_path))
            end_date = info.get("end_date", "")
            if end_date:
                days = _cert_expiry_days(end_date)
                return float(days) if days is not None else -1.0
        return -1.0
    except Exception:
        return -1.0


def _fail2ban_banned() -> int:
    """Count currently banned IPs across all jails.

    Uses ``fail2ban-client banned`` which returns a JSON summary.
    Falls back to counting lines in fail2ban log.
    """
    # Try the newer fail2ban-client banned command (fail2ban 1.0+)
    result = _run(["fail2ban-client", "banned"])
    if result.returncode == 0 and result.stdout.strip():
        try:
            import json
            data = json.loads(result.stdout)
            # Format: { "jail_name": ["ip1", "ip2"], ... }
            return sum(len(ips) for ips in data.values())
        except (json.JSONDecodeError, AttributeError):
            pass

    # Fallback: count banned entries in the fail2ban log
    log = Path("/var/log/fail2ban.log")
    if log.exists():
        try:
            text = log.read_text(encoding="utf-8", errors="replace")
            # Count "Ban" lines in recent entries (last 10K)
            recent = text[-10000:]
            return recent.count(" Ban ") + recent.count("Ban\t")
        except OSError:
            pass
    return -1


def _last_success(path: Path, key: str = "updated_at") -> float:
    """Read the 'updated_at' timestamp from a JSON state file.

    Returns the timestamp (as epoch seconds) or -1 if the file doesn't
    exist or the key is missing.
    """
    if not path.exists():
        return -1.0
    try:
        data = read_json(path)
        ts = data.get(key, -1)
        return float(ts) if ts > 0 else -1.0
    except Exception:
        return -1.0


# ── Composite writer ───────────────────────────────────────────────────────


METRIC_HELP: dict[str, str] = {
    "ktc_mail_service_up": "Service active state (1=active, 0=inactive/failed)",
    "ktc_mail_queue_depth": "Number of messages in Postfix mail queue",
    "ktc_mail_user_count": "Number of mail users configured in Dovecot",
    "ktc_mail_cert_expiry_days": "Days until TLS certificate expires (-1 = unknown, 0 = expired)",
    "ktc_mail_dns_last_verified": "Unix timestamp of last successful DNS verification",
    "ktc_mail_backup_last_success": "Unix timestamp of last successful backup",
    "ktc_mail_fail2ban_banned": "Number of IPs currently banned by Fail2ban (-1 = unknown)",
    "ktc_mail_build_info": "Build metadata (version always 1 for presence check)",
}


def collect() -> str:
    """Run all collectors and format as Prometheus textfile metrics.

    Returns the complete ``.prom`` file content as a string.
    """
    now = time.time()
    services = _service_metrics()
    queue = _queue_depth()
    users = _user_count()
    cert = _cert_expiry()
    dns_ts = _last_success(DNS_STATE_PATH)
    backup_ts = _last_success(STATE_DIR / "backup-state.json", "last_success")
    f2b = _fail2ban_banned()

    lines: list[str] = [
        "# KTC Mail metrics — generated by ktc-mail exporter",
        f"# {datetime.now(timezone.utc).isoformat()}",
        "",
    ]

    def emit(name: str, value: float | int, labels: str = "") -> None:
        help_text = METRIC_HELP.get(name, "")
        if help_text:
            lines.append(f"# HELP {name} {help_text}")
            lines.append(f"# TYPE {name} gauge")
        lines.append(f"{name}{{{labels}}} {value}")
        lines.append("")

    emit("ktc_mail_queue_depth", queue)
    emit("ktc_mail_user_count", users)
    emit("ktc_mail_cert_expiry_days", cert)
    emit("ktc_mail_dns_last_verified", dns_ts)
    emit("ktc_mail_backup_last_success", backup_ts)
    emit("ktc_mail_fail2ban_banned", f2b)
    emit("ktc_mail_build_info", 1, f'version="0.2.0"')

    for svc_line in services:
        lines.append(svc_line)
    lines.append("")

    return "\n".join(lines)


def write() -> None:
    """Collect metrics and atomically write to the textfile path.

    Writes to a temp file first, then renames atomically so that a
    partial write is never visible to node_exporter.
    """
    metrics = collect()
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    TMP_METRICS_PATH.write_text(metrics, encoding="utf-8")
    TMP_METRICS_PATH.chmod(0o644)
    fd = os.open(TMP_METRICS_PATH, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    TMP_METRICS_PATH.rename(METRICS_PATH)  # atomic on same filesystem
    print(f"ktc-mail exporter: wrote {len(metrics)} bytes to {METRICS_PATH}")


# ── CLI ────────────────────────────────────────────────────────────────────


def main() -> int:
    write()
    return 0


if __name__ == "__main__":
    sys.exit(main())
