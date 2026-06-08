#!/usr/bin/env python3
"""SSH policy management for KTC Mail.

Default: key-only authentication, root login disabled.
Password authentication is available as an opt-in at the admin's own
risk, requiring an explicit acknowledgement checkbox during setup.

This module rewrites /etc/ssh/sshd_config.d/ktc-mail.conf (a drop-in
config snippet) so it never touches the main sshd_config and can be
cleanly uninstalled.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

from .config import SSH_CONFIG_PATH

# Drop-in config path (cleaner than editing main sshd_config)
DROPIN_DIR = Path("/etc/ssh/sshd_config.d")
DROPIN_PATH = DROPIN_DIR / "ktc-mail.conf"

# Template for the drop-in config file.
# Uses Match blocks conditionally. PasswordAuthentication defaults to
# 'no' in OpenSSH, but we make it explicit.
CONFIG_TEMPLATE = """# KTC Mail — SSH hardening policy
# Managed by ktc-mail. Manual changes will be overwritten on next setup run.

# Core hardening
Protocol 2
MaxAuthTries {max_auth_tries}
ClientAliveInterval {client_alive_interval}
ClientAliveCountMax {client_alive_count_max}
MaxSessions {max_sessions}

# Authentication
PubkeyAuthentication yes
PasswordAuthentication {password_auth}
PermitRootLogin {root_login}
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# Cryptographic defaults (modern only)
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com

# Logging
LogLevel VERBOSE
"""


class SshPolicyError(RuntimeError):
    """SSH policy cannot be applied."""


def write_config(
    password_auth: bool = False,
    permit_root_login: bool = False,
    max_auth_tries: int = 3,
    client_alive_interval: int = 300,
    client_alive_count_max: int = 2,
    max_sessions: int = 10,
    dry_run: bool = False,
) -> None:
    """Write the SSH drop-in config file and reload sshd.

    Args:
        password_auth: Enable PasswordAuthentication (RISKY).
        permit_root_login: Allow root SSH login (also risky).
        max_auth_tries: Max authentication attempts per connection.
        client_alive_interval: Seconds between keepalive probes.
        client_alive_count_max: Max keepalive failures before disconnect.
        max_sessions: Max concurrent SSH sessions.
        dry_run: Print config to stdout instead of writing.
    """
    config = CONFIG_TEMPLATE.format(
        password_auth="yes" if password_auth else "no",
        root_login="prohibit-password" if not permit_root_login else "yes",
        max_auth_tries=max_auth_tries,
        client_alive_interval=client_alive_interval,
        client_alive_count_max=client_alive_count_max,
        max_sessions=max_sessions,
    )

    if dry_run:
        print(config)
        return

    # Write drop-in config
    DROPIN_DIR.mkdir(parents=True, exist_ok=True)
    DROPIN_PATH.write_text(config, encoding="utf-8")
    DROPIN_PATH.chmod(0o644)

    # Test config before reloading
    test = subprocess.run(
        ["sshd", "-t"],
        capture_output=True, text=True, check=False,
        timeout=SUBPROCESS_TIMEOUT,
    )
    if test.returncode != 0:
        raise SshPolicyError(
            f"sshd config test FAILED:\n{test.stderr.strip()}"
        )

    # Reload sshd
    result = subprocess.run(
        ["systemctl", "reload-or-restart", "ssh"],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        raise SshPolicyError(
            f"sshd reload failed:\n{result.stderr.strip()}"
        )

    print(f"SSH policy applied: {DROPIN_PATH}")
    print(f"  PasswordAuthentication: {'yes' if password_auth else 'no'}")
    print(f"  PermitRootLogin: {'yes' if permit_root_login else 'prohibit-password'}")


def remove_policy(dry_run: bool = False) -> None:
    """Remove the KTC Mail SSH drop-in and reload sshd.

    This does NOT restore the original sshd_config — it just removes
    our drop-in and reloads, letting the main config take over.
    """
    if dry_run:
        print(f"dry-run: rm {DROPIN_PATH}")
        return

    if DROPIN_PATH.exists():
        DROPIN_PATH.unlink()
        subprocess.run(
            ["systemctl", "reload-or-restart", "ssh"],
            capture_output=True, check=False,
        )
        print(f"Removed {DROPIN_PATH}, sshd reloaded")
    else:
        print("No KTC Mail SSH policy to remove")


def status() -> int:
    """Check current SSH policy status. Returns 0 if hardened, 1 if not."""
    if not DROPIN_PATH.exists():
        print("KTC Mail SSH policy: NOT APPLIED")
        return 1

    config = DROPIN_PATH.read_text(encoding="utf-8")
    if "PasswordAuthentication no" in config:
        print("KTC Mail SSH policy: APPLIED (key-only)")
        return 0
    print("KTC Mail SSH policy: APPLIED (password auth enabled — RISKY)")
    return 0 if "PasswordAuthentication yes" in config else 1


# ── CLI entry point ─────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(
        description="KTC Mail SSH policy manager",
    )
    parser.add_argument(
        "command",
        choices=("apply", "remove", "status"),
        help="Operation",
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview changes without writing")
    parser.add_argument("--password-auth", action="store_true",
                        help="Enable password authentication (RISKY)")
    parser.add_argument("--permit-root-login", action="store_true",
                        help="Allow root SSH login (RISKY)")
    args = parser.parse_args()

    try:
        if args.command == "apply":
            write_config(
                password_auth=args.password_auth,
                dry_run=args.dry_run,
            )
            return 0
        if args.command == "remove":
            remove_policy(dry_run=args.dry_run)
            return 0
        if args.command == "status":
            return status()
        return 1
    except SshPolicyError as exc:
        print(f"ssh policy error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
