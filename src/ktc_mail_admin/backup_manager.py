#!/usr/bin/env python3
"""KTC Mail — backup management via restic (Phase 6 deliverable).

Uses restic as the backup engine — encrypted, deduplicated, and
cloud-agnostic.  Supports any restic backend: local paths, SFTP,
S3, Backblaze B2, GCS, Azure Blob, and rclone remotes.

Design rules:
  - restic(1) MUST be installed (``apt install restic``).
  - Repository password lives in a 0400 file, never in argv.
  - Backups run via ``ktc-mail backup now`` or a systemd timer.
  - Restore is always a deliberate manual operation — too dangerous
    to automate via GUI (you don't want "click restore" to nuke a
    working server).
  - Mailbox data (``/var/mail/``) is the primary concern. Config and
    state are secondary but included because losing them is annoying.
  - Retention is configurable via BackupConfig. Defaults to 7 daily,
    4 weekly, 3 monthly, 2 yearly.
"""

from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import (
    BACKUP_CONFIG_PATH,
    BACKUP_STATE_PATH,
    BACKUP_DEFAULT_PATHS,
    CONFIG_DIR,
    RESTIC_PASSWORD_PATH,
    read_json,
    save_json_private,
)

logger = logging.getLogger("ktc-mail.backup")

# ── Data structures ─────────────────────────────────────────────────────────


@dataclass
class RetentionPolicy:
    """How long to keep backup snapshots.

    Applied by ``restic forget`` after every successful backup.
    """
    keep_daily: int = 7
    keep_weekly: int = 4
    keep_monthly: int = 3
    keep_yearly: int = 2

    def to_dict(self) -> dict[str, int]:
        return {
            "keep_daily": self.keep_daily,
            "keep_weekly": self.keep_weekly,
            "keep_monthly": self.keep_monthly,
            "keep_yearly": self.keep_yearly,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RetentionPolicy:
        return cls(
            keep_daily=int(data.get("keep_daily", 7)),
            keep_weekly=int(data.get("keep_weekly", 4)),
            keep_monthly=int(data.get("keep_monthly", 3)),
            keep_yearly=int(data.get("keep_yearly", 2)),
        )


@dataclass
class BackupConfig:
    """Backup configuration stored in /etc/ktc-mail/backup.json.

    ``repository`` is a restic-compatible repo URL:
      - ``/backup``                            local path
      - ``s3:https://s3.eu-central-1.amazonaws.com/bucket``
      - ``b2:bucketname:/path``
      - ``rclone:remote:path``
      - ``rest:https://user:pass@rest-server/``
      - ``sftp:user@host:/backup``

    The repository password is stored SEPARATELY in
    ``/etc/ktc-mail/restic-password`` (mode 0400) and never
    appears in config JSON or command-line arguments.
    """
    repository: str = ""
    schedule: str = "daily"
    retention: RetentionPolicy = field(default_factory=RetentionPolicy)
    enabled: bool = False
    paths: tuple[str, ...] = BACKUP_DEFAULT_PATHS
    exclude_patterns: tuple[str, ...] = (
        "*.tmp",
        "*.lock",
        ".cache/",
    )

    def is_configured(self) -> bool:
        """True if the repository URL is set and enabled."""
        return bool(self.repository) and self.enabled

    def to_dict(self) -> dict[str, Any]:
        return {
            "repository": self.repository,
            "schedule": self.schedule,
            "retention": self.retention.to_dict(),
            "enabled": self.enabled,
            "paths": list(self.paths),
            "exclude_patterns": list(self.exclude_patterns),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BackupConfig:
        return cls(
            repository=str(data.get("repository", "")),
            schedule=str(data.get("schedule", "daily")),
            retention=RetentionPolicy.from_dict(
                data.get("retention", {})
            ),
            enabled=bool(data.get("enabled", False)),
            paths=tuple(data.get("paths", BACKUP_DEFAULT_PATHS)),
            exclude_patterns=tuple(data.get("exclude_patterns", [])),
        )


@dataclass
class BackupStatus:
    """Latest backup run status, stored in /var/lib/ktc-mail/backup-state.json.

    Updated atomically after every backup run (success or failure).
    The GUI reads this to show backup status on the dashboard.
    """
    last_run: int | None = None       # timestamp of most recent attempt
    last_success: int | None = None   # timestamp of last successful backup
    last_failure: int | None = None   # timestamp of last failed attempt
    last_error: str | None = None     # error message from last failure
    last_snapshot: str | None = None  # snapshot ID from last backup
    total_size: int = 0               # bytes in last backup
    file_count: int = 0               # files in last backup
    repo_initialized: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "last_run": self.last_run,
            "last_success": self.last_success,
            "last_failure": self.last_failure,
            "last_error": self.last_error,
            "last_snapshot": self.last_snapshot,
            "total_size": self.total_size,
            "file_count": self.file_count,
            "repo_initialized": self.repo_initialized,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> BackupStatus:
        if not data:
            return cls()
        return cls(
            last_run=data.get("last_run"),
            last_success=data.get("last_success"),
            last_failure=data.get("last_failure"),
            last_error=data.get("last_error"),
            last_snapshot=data.get("last_snapshot"),
            total_size=int(data.get("total_size", 0)),
            file_count=int(data.get("file_count", 0)),
            repo_initialized=bool(data.get("repo_initialized", False)),
        )


# ── I/O helpers ─────────────────────────────────────────────────────────────


def load_config() -> BackupConfig:
    """Load backup config from disk. Returns defaults if not configured."""
    if not BACKUP_CONFIG_PATH.exists():
        return BackupConfig()
    try:
        return BackupConfig.from_dict(read_json(BACKUP_CONFIG_PATH))
    except Exception:
        logger.exception("loading backup config from %s", BACKUP_CONFIG_PATH)
        return BackupConfig()


def save_config(config: BackupConfig) -> None:
    """Write backup config atomically."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    save_json_private(BACKUP_CONFIG_PATH, config.to_dict())


def load_status() -> BackupStatus:
    """Load backup status from state file."""
    if not BACKUP_STATE_PATH.exists():
        return BackupStatus()
    try:
        return BackupStatus.from_dict(read_json(BACKUP_STATE_PATH))
    except Exception:
        logger.exception("loading backup state from %s", BACKUP_STATE_PATH)
        return BackupStatus()


def save_status(status: BackupStatus) -> None:
    """Write backup status atomically. Called after every backup run."""
    BACKUP_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    # Stored as 0640 so the admin GUI (running as a different user) can
    # read it. The restic-password file stays 0400.
    import json
    tmp = BACKUP_STATE_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(status.to_dict(), indent=2) + "\n",
                   encoding="utf-8")
    tmp.chmod(0o640)
    tmp.rename(BACKUP_STATE_PATH)


# ── Restic wrapper ──────────────────────────────────────────────────────────


def _restic(args: list[str], timeout: int = 3600,
            check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run restic with the configured repository and password file.

    Args:
        args: restic subcommand and arguments.
        timeout: max seconds to wait (default 3600 = 1 hour).
        check: if True, raises CalledProcessError on non-zero exit.

    Returns:
        ``subprocess.CompletedProcess`` with stdout/stderr captured.

    The repository and password file are injected automatically from
    the loaded BackupConfig.
    """
    config = load_config()
    if not config.repository:
        raise RuntimeError("backup repository not configured "
                           "(run 'ktc-mail backup init')")

    cmd = [
        "restic",
        "--repo", config.repository,
        "--password-file", str(RESTIC_PASSWORD_PATH),
        "--json",  # machine-readable output
    ] + args

    logger.debug("running: %s", " ".join(str(c) for c in cmd))

    result = subprocess.run(
        cmd,
        capture_output=True, text=True, timeout=timeout,
        check=False,  # we handle errors ourselves
    )
    if check and result.returncode != 0:
        error_msg = result.stderr.strip() or f"exit code {result.returncode}"
        raise RuntimeError(f"restic: {error_msg}")

    return result


def _restic_nonjson(args: list[str], timeout: int = 3600,
                    check: bool = True) -> subprocess.CompletedProcess[str]:
    """Like _restic but without ``--json`` flag (for commands that
    don't support it, like ``init`` and ``check``)."""
    config = load_config()
    if not config.repository:
        raise RuntimeError("backup repository not configured")

    cmd = [
        "restic",
        "--repo", config.repository,
        "--password-file", str(RESTIC_PASSWORD_PATH),
    ] + args

    logger.debug("running: %s", " ".join(str(c) for c in cmd))

    result = subprocess.run(
        cmd,
        capture_output=True, text=True, timeout=timeout,
        check=False,
    )
    if check and result.returncode != 0:
        error_msg = result.stderr.strip() or f"exit code {result.returncode}"
        raise RuntimeError(f"restic: {error_msg}")

    return result


# ── Restic tooling checks ───────────────────────────────────────────────────


def restic_installed() -> bool:
    """Check if restic binary is available on the system."""
    result = subprocess.run(
        ["which", "restic"],
        capture_output=True, text=True, check=False,
    )
    return result.returncode == 0


def restic_version() -> str:
    """Return restic version string, or 'not installed'."""
    result = subprocess.run(
        ["restic", "version"],
        capture_output=True, text=True, check=False,
    )
    if result.returncode == 0:
        return result.stdout.strip()
    return "not installed"


# ── Password file management ────────────────────────────────────────────────


def restic_password_path() -> Path:
    """Return the path to the restic password file.

    The file is created with 0400 permissions when ``backup init`` is
    run.  It is stored SEPARATELY from the backup config JSON so that
    a config backup (which includes the JSON) does NOT include the
    repository password.
    """
    return RESTIC_PASSWORD_PATH


def write_password(password: str) -> None:
    """Write the restic repository password to disk (mode 0400).

    The password is stored in a separate file from the backup config
    so that backing up the config doesn't expose the repo password.
    """
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    RESTIC_PASSWORD_PATH.write_text(password.strip() + "\n", encoding="utf-8")
    RESTIC_PASSWORD_PATH.chmod(0o400)


def password_exists() -> bool:
    """Check if the restic password file exists and is non-empty."""
    return RESTIC_PASSWORD_PATH.exists() and RESTIC_PASSWORD_PATH.stat().st_size > 0


# ── Core operations ─────────────────────────────────────────────────────────


def init_repository(repository: str, password: str,
                    dry_run: bool = False) -> int:
    """Initialize a restic repository.

    Args:
        repository: restic repo URL.
        password: repository encryption password.
        dry_run: if True, only print what would be done.

    Returns:
        0 on success, 1 on failure.
    """
    if dry_run:
        print(f"dry-run: restic init --repo {repository}")
        print("dry-run: would create restic-password file")
        return 0

    if not restic_installed():
        print("error: restic is not installed (apt install restic)",
              file=sys.stderr)
        return 1

    # Check if already initialized
    config = load_config()
    if config.repository and password_exists():
        # Try opening the repo to verify
        result = subprocess.run(
            ["restic", "--repo", repository, "--password-file",
             str(RESTIC_PASSWORD_PATH), "snapshots", "--json", "-q"],
            capture_output=True, text=True, timeout=30, check=False,
        )
        if result.returncode == 0:
            print(f"repository already initialized: {repository}")
            return 0

    # Write password first
    write_password(password)

    # Initialize the repository
    result = subprocess.run(
        ["restic", "--repo", repository, "init"],
        input=password + "\n",
        capture_output=True, text=True, timeout=60, check=False,
    )
    if result.returncode != 0:
        error = result.stderr.strip() or "unknown error"
        print(f"error: restic init failed: {error}", file=sys.stderr)
        return 1

    # Save config
    config = BackupConfig(
        repository=repository,
        enabled=True,
    )
    save_config(config)

    # Save status
    status = load_status()
    status.repo_initialized = True
    save_status(status)

    print(f"backup repository initialized: {repository}")
    print(f"password stored: {RESTIC_PASSWORD_PATH}")
    print("run 'ktc-mail backup now' to create the first snapshot")
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    """CLI handler for ``ktc-mail backup init``."""
    return init_repository(
        repository=args.repository,
        password=args.password,
        dry_run=args.dry_run,
    )


def run_backup(dry_run: bool = False) -> int:
    """Run a backup now.

    Creates a restic snapshot of all configured paths.  After a
    successful backup, applies retention policy and updates status.

    Returns:
        0 on success, 1 on failure.
    """
    config = load_config()

    if not config.is_configured():
        print("error: backup not configured (run 'ktc-mail backup init')",
              file=sys.stderr)
        return 1

    if not restic_installed():
        print("error: restic is not installed (apt install restic)",
              file=sys.stderr)
        return 1

    if not password_exists():
        print("error: restic password file not found at "
              f"{RESTIC_PASSWORD_PATH}", file=sys.stderr)
        return 1

    now = int(time.time())
    status = load_status()
    status.last_run = now

    # Build exclude patterns
    exclude_args: list[str] = []
    for pattern in config.exclude_patterns:
        exclude_args.extend(["--exclude", pattern])

    if dry_run:
        paths_str = " ".join(config.paths)
        print(f"dry-run: restic backup {paths_str}")
        print(f"dry-run: exclude patterns: {config.exclude_patterns}")
        return 0

    try:
        result = _restic(
            ["backup"] + exclude_args + list(config.paths),
            timeout=7200,  # 2 hour timeout for large maildirs
            check=False,
        )
    except RuntimeError as exc:
        status.last_failure = int(time.time())
        status.last_error = str(exc)
        save_status(status)
        print(f"error: backup failed: {exc}", file=sys.stderr)
        return 1
    except subprocess.TimeoutExpired:
        status.last_failure = int(time.time())
        status.last_error = "backup timed out after 2 hours"
        save_status(status)
        print("error: backup timed out after 2 hours", file=sys.stderr)
        return 1

    if result.returncode != 0:
        error = result.stderr.strip() or f"exit code {result.returncode}"
        status.last_failure = int(time.time())
        status.last_error = error
        save_status(status)
        print(f"error: backup failed: {error}", file=sys.stderr)
        return 1

    # Parse JSON output for snapshot info
    snapshot_id = ""
    total_size = 0
    file_count = 0
    try:
        for line in result.stdout.strip().splitlines():
            if not line:
                continue
            entry = json.loads(line)
            if entry.get("message_type") == "summary":
                snapshot_id = entry.get("snapshot_id", "")
                total_size = entry.get("total_bytes_processed", 0)
                file_count = entry.get("total_files_processed", 0)
                break
    except (json.JSONDecodeError, KeyError):
        pass

    # Update status
    status.last_success = int(time.time())
    status.last_failure = None
    status.last_error = None
    status.last_snapshot = snapshot_id
    status.total_size = total_size
    status.file_count = file_count
    status.repo_initialized = True
    save_status(status)

    # Pretty-print size
    def _human_size(b: int) -> str:
        for unit in ("B", "K", "M", "G", "T"):
            if b < 1024:
                return f"{b:.1f}{unit}"
            b /= 1024
        return f"{b:.1f}P"

    print(f"backup completed: snapshot {snapshot_id}")
    print(f"  files: {file_count}")
    print(f"  size:  {_human_size(total_size)}")

    # Apply retention after successful backup
    try:
        forget_result = _restic_nonjson(
            ["forget",
             "--keep-daily", str(config.retention.keep_daily),
             "--keep-weekly", str(config.retention.keep_weekly),
             "--keep-monthly", str(config.retention.keep_monthly),
             "--keep-yearly", str(config.retention.keep_yearly),
             "--prune"],
            timeout=3600,
            check=False,
        )
        if forget_result.returncode == 0:
            print("retention policy applied")
        else:
            print(f"warning: retention policy failed: "
                  f"{forget_result.stderr.strip()}", file=sys.stderr)
    except RuntimeError as exc:
        print(f"warning: retention policy error: {exc}", file=sys.stderr)

    return 0


def cmd_now(args: argparse.Namespace) -> int:
    """CLI handler for ``ktc-mail backup now``."""
    return run_backup(dry_run=args.dry_run)


def show_status() -> int:
    """Print backup status to stdout.

    Returns:
        0 if backup is configured and has run at least once,
        1 otherwise.
    """
    config = load_config()
    status = load_status()
    restic_ver = restic_version()

    print(f"restic:       {restic_ver}")
    print(f"repository:   {config.repository or '(not configured)'}")
    print(f"enabled:      {'yes' if config.enabled else 'no'}")
    print(f"schedule:     {config.schedule}")

    print()
    print("Last backup status:")
    if status.last_success:
        ts = time.strftime(
            "%Y-%m-%d %H:%M UTC",
            time.gmtime(status.last_success),
        )
        print(f"  last success: {ts}")
        print(f"  snapshot:     {status.last_snapshot or 'unknown'}")
        if status.file_count:
            print(f"  files:        {status.file_count}")
        if status.total_size:
            print(f"  size:         {_human_bytes(status.total_size)}")
    else:
        print("  (no successful backup yet)")

    if status.last_failure:
        ts = time.strftime(
            "%Y-%m-%d %H:%M UTC",
            time.gmtime(status.last_failure),
        )
        print(f"  last failure: {ts}")
        if status.last_error:
            print(f"  error:        {status.last_error}")

    if not status.repo_initialized:
        print()
        print("Repository not initialized. Run: ktc-mail backup init <repo>")

    configured = config.is_configured() and status.repo_initialized
    return 0 if configured else 1


def _human_bytes(b: int) -> str:
    for unit in ("B", "K", "M", "G", "T"):
        if b < 1024:
            return f"{b:.1f}{unit}"
        b /= 1024
    return f"{b:.1f}P"


def cmd_status(args: argparse.Namespace) -> int:
    """CLI handler for ``ktc-mail backup status``."""
    return show_status()


def list_snapshots(dry_run: bool = False) -> int:
    """List all backup snapshots.

    Returns:
        0 on success, 1 on failure.
    """
    config = load_config()
    if not config.repository:
        print("error: backup not configured", file=sys.stderr)
        return 1

    if dry_run:
        print("dry-run: restic snapshots")
        return 0

    try:
        result = _restic(
            ["snapshots"],
            timeout=60,
            check=False,
        )
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if result.returncode != 0:
        print(f"error: {result.stderr.strip()}", file=sys.stderr)
        return 1

    # Parse JSON output
    try:
        snapshots = json.loads(result.stdout) if result.stdout.strip() else []
    except json.JSONDecodeError:
        print("warning: could not parse restic output", file=sys.stderr)
        print()
        print(result.stdout)
        return 1

    if not snapshots:
        print("no snapshots found")
        return 0

    print(f"{'ID':<20} {'Time':<25} {'Paths':<30} {'Size':<12}")
    print("-" * 90)
    for snap in snapshots:
        sid = snap.get("short_id", "")[:19]
        stime = snap.get("time", "")
        # Format time
        try:
            parsed = time.strptime(stime[:19], "%Y-%m-%dT%H:%M:%S")
            stime_fmt = time.strftime("%Y-%m-%d %H:%M:%S", parsed)
        except (ValueError, IndexError):
            stime_fmt = stime[:19]
        paths = ", ".join(snap.get("paths", []))
        # Truncate paths if too long
        if len(paths) > 29:
            paths = paths[:26] + "..."
        print(f"{sid:<20} {stime_fmt:<25} {paths:<30}")
    print(f"\n{len(snapshots)} snapshot(s)")

    return 0


def cmd_snapshots(args: argparse.Namespace) -> int:
    """CLI handler for ``ktc-mail backup snapshots``."""
    return list_snapshots(dry_run=args.dry_run)


def restore_snapshot(snapshot_id: str, target: str = "/",
                     dry_run: bool = False) -> int:
    """Restore a backup snapshot.

    Args:
        snapshot_id: restic snapshot ID (short or full).
        target: restore target path (default: /, i.e. in-place restore).
        dry_run: if True, only print what would be done.

    Returns:
        0 on success, 1 on failure.
    """
    config = load_config()
    if not config.repository:
        print("error: backup not configured", file=sys.stderr)
        return 1

    if not dry_run:
        print("WARNING: This will overwrite files in", target)
        print("Make sure no mail services are running during restore.")
        print("Suggested: systemctl stop postfix dovecot rspamd")
        try:
            response = input("Continue? [y/N]: ")
        except (EOFError, KeyboardInterrupt):
            print("\nrestore cancelled")
            return 1
        if response.lower() not in ("y", "yes"):
            print("restore cancelled")
            return 1

    if dry_run:
        print(f"dry-run: restic restore {snapshot_id} --target {target}")
        return 0

    try:
        result = _restic_nonjson(
            ["restore", snapshot_id, "--target", target],
            timeout=7200,
            check=False,
        )
    except RuntimeError as exc:
        print(f"error: restore failed: {exc}", file=sys.stderr)
        return 1

    if result.returncode != 0:
        print(f"error: restore failed: {result.stderr.strip()}",
              file=sys.stderr)
        return 1

    print(f"restored snapshot {snapshot_id} to {target}")
    print("Restart mail services: systemctl restart postfix dovecot rspamd")
    return 0


def cmd_restore(args: argparse.Namespace) -> int:
    """CLI handler for ``ktc-mail backup restore``."""
    return restore_snapshot(
        snapshot_id=args.snapshot_id,
        target=args.target,
        dry_run=args.dry_run,
    )


def check_repository(dry_run: bool = False) -> int:
    """Check restic repository integrity.

    Returns:
        0 if healthy, 1 if issues found.
    """
    config = load_config()
    if not config.repository:
        print("error: backup not configured", file=sys.stderr)
        return 1

    if dry_run:
        print("dry-run: restic check")
        return 0

    print("checking repository integrity (this may take a while)...")
    try:
        result = _restic_nonjson(
            ["check", "--read-data-subset", "5%"],
            timeout=7200,
            check=False,
        )
    except RuntimeError as exc:
        print(f"error: check failed: {exc}", file=sys.stderr)
        return 1

    if result.returncode != 0:
        print(f"repository has issues: {result.stderr.strip()}",
              file=sys.stderr)
        return 1

    print("repository is healthy")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """CLI handler for ``ktc-mail backup check``."""
    return check_repository(dry_run=args.dry_run)


def forget_snapshots(dry_run: bool = False) -> int:
    """Apply retention policy and prune old snapshots.

    Returns:
        0 on success, 1 on failure.
    """
    config = load_config()
    if not config.repository:
        print("error: backup not configured", file=sys.stderr)
        return 1

    if dry_run:
        print("dry-run: restic forget --dry-run "
              f"--keep-daily {config.retention.keep_daily} "
              f"--keep-weekly {config.retention.keep_weekly} "
              f"--keep-monthly {config.retention.keep_monthly} "
              f"--keep-yearly {config.retention.keep_yearly}")
        return 0

    try:
        args_list = [
            "forget",
            "--keep-daily", str(config.retention.keep_daily),
            "--keep-weekly", str(config.retention.keep_weekly),
            "--keep-monthly", str(config.retention.keep_monthly),
            "--keep-yearly", str(config.retention.keep_yearly),
            "--prune",
        ]
        if dry_run:
            args_list.append("--dry-run")

        result = _restic_nonjson(args_list, timeout=3600, check=False)
    except RuntimeError as exc:
        print(f"error: forget failed: {exc}", file=sys.stderr)
        return 1

    if result.returncode != 0:
        print(f"error: forget failed: {result.stderr.strip()}",
              file=sys.stderr)
        return 1

    print("retention policy applied")
    # Show what was removed
    for line in result.stdout.splitlines():
        if line.strip():
            print(f"  {line.strip()}")

    return 0


def cmd_forget(args: argparse.Namespace) -> int:
    """CLI handler for ``ktc-mail backup forget``."""
    return forget_snapshots(dry_run=args.dry_run)


# ── Configuration management ────────────────────────────────────────────────


def cmd_configure(args: argparse.Namespace) -> int:
    """CLI handler for ``ktc-mail backup set``.

    Updates backup config values without needing to re-init.
    """
    config = load_config()

    if args.repository:
        config.repository = args.repository
    if args.schedule:
        config.schedule = args.schedule
    if args.enable:
        config.enabled = True
    if args.disable:
        config.enabled = False

    save_config(config)
    print("backup configuration updated")
    return 0


# ── Argparse subcommand builder ─────────────────────────────────────────────


def add_subparser(sub) -> None:
    """Add the 'backup' subcommand parser to the CLI."""
    p = sub.add_parser("backup", help="Backup management (restic)")
    bsub = p.add_subparsers(dest="backup_cmd", required=True)

    # init
    p_init = bsub.add_parser("init", help="Initialize backup repository")
    p_init.add_argument("repository",
                        help="restic repo URL (e.g. /backup, s3:..., b2:...)")
    p_init.add_argument("--password", default="",
                        help="Repository password (omit for prompt)")
    p_init.add_argument("--dry-run", action="store_true")

    # now
    p_now = bsub.add_parser("now", help="Run backup now")
    p_now.add_argument("--dry-run", action="store_true")

    # status
    bsub.add_parser("status", help="Show backup status")

    # snapshots
    p_snap = bsub.add_parser("snapshots", help="List backup snapshots")
    p_snap.add_argument("--dry-run", action="store_true")

    # restore
    p_restore = bsub.add_parser("restore",
                                help="Restore from a snapshot (DANGEROUS)")
    p_restore.add_argument("snapshot_id", help="Snapshot ID to restore")
    p_restore.add_argument("--target", default="/",
                           help="Restore target directory (default: /)")
    p_restore.add_argument("--dry-run", action="store_true",
                           help="Show what would be restored")

    # check
    p_check = bsub.add_parser("check", help="Verify repository integrity")
    p_check.add_argument("--dry-run", action="store_true")

    # forget
    p_forget = bsub.add_parser("forget", help="Apply retention policy")
    p_forget.add_argument("--dry-run", action="store_true",
                          help="Show what would be removed")

    # set
    p_set = bsub.add_parser("set", help="Update backup configuration")
    p_set.add_argument("--repository", help="New repository URL")
    p_set.add_argument("--schedule",
                       choices=("hourly", "daily", "weekly", "manual"),
                       help="Backup schedule")
    p_set.add_argument("--enable", action="store_true",
                       help="Enable scheduled backups")
    p_set.add_argument("--disable", action="store_true",
                       help="Disable scheduled backups")


def dispatch(args: argparse.Namespace) -> int:
    """Dispatch backup subcommands."""
    dispatch_map = {
        "init": cmd_init,
        "now": cmd_now,
        "status": cmd_status,
        "snapshots": cmd_snapshots,
        "restore": cmd_restore,
        "check": cmd_check,
        "forget": cmd_forget,
        "set": cmd_configure,
    }
    handler = dispatch_map.get(args.backup_cmd)
    if handler is None:
        print(f"unknown backup command: {args.backup_cmd}", file=sys.stderr)
        return 1
    return handler(args)
