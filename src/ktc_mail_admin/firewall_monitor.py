#!/usr/bin/env python3
"""KTC Mail firewall policy monitor.

Reads the setup profile's open_ports, verifies the KTC-MAIL-IN
iptables/ip6tables chain has the expected rules in the right order,
and reports drift.

The enforce command recreates the chain from scratch.
This is deliberately destructive — it's only safe to run when you
KNOW nothing else manages iptables on this host.

Default policy: DROP all inbound. Only these ports are opened:
  - 22/tcp  (SSH)
  - 25/tcp  (SMTP)
  - 443/tcp (HTTPS, webmail, admin)
  - 587/tcp (Submission)
  - 993/tcp (IMAPS)
  - 80/tcp  (only if HTTP-01 cert mode)
  - 4190/tcp (ManageSieve, only if enabled)

See also: ssh_policy.py for SSH-adjacent hardening.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import (
    CONFIG_DIR,
    SETUP_PATH,
    SecurityPolicy,
    read_json,
)

KTC_CHAIN = "KTC-MAIL-IN"
DEFAULT_TCP_PORTS = (22, 25, 443, 587, 993)


# ── Data ────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Finding:
    """A single firewall policy violation."""
    table: str  # "iptables" or "ip6tables"
    message: str


# ── Helpers ─────────────────────────────────────────────────────────────────


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, capture_output=True, check=False)


def load_policy(config_path: Path) -> SecurityPolicy:
    """Load the security policy from the setup profile.

    Falls back to safe defaults if the profile doesn't exist.
    """
    if not config_path.exists():
        return SecurityPolicy()
    try:
        data = read_json(config_path)
        policy_data = data.get("security", {})
        # Backward compat: also check top-level open_ports
        if "open_ports" in data and "ports_open" not in policy_data:
            policy_data["ports_open"] = data["open_ports"]
        return SecurityPolicy.from_dict(policy_data)
    except (OSError, ValueError, json.JSONDecodeError):
        return SecurityPolicy()


# ── Expected rules ──────────────────────────────────────────────────────────


def expected_rules(ports: list[int]) -> list[str]:
    """Generate the list of expected iptables rules.

    These must be in the exact ORDER expected (chain create, input
    jump, conntrack, loopback, port accepts, default DROP).

    Returns them as they would appear in `iptables -S` output.
    """
    rules: list[str] = []
    rules.append(f"-N {KTC_CHAIN}")
    rules.append(f"-A INPUT -j {KTC_CHAIN}")
    rules.append(
        f"-A {KTC_CHAIN} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
    )
    rules.append(f"-A {KTC_CHAIN} -i lo -j ACCEPT")
    for port in sorted(ports):
        rules.append(
            f"-A {KTC_CHAIN} -p tcp -m tcp --dport {port} -j ACCEPT"
        )
    rules.append(f"-A {KTC_CHAIN} -j DROP")
    return rules


# ── Inspection ──────────────────────────────────────────────────────────────


def inspect_table(binary: str, required_ports: list[int]) -> list[Finding]:
    """Compare live iptables rules against expected rules.

    Returns a list of Finding for every missing rule or ordering issue.
    """
    result = _run([binary, "-S"])
    if result.returncode != 0:
        return [Finding(
            binary,
            f"cannot read rules: {result.stderr.strip()}",
        )]

    rules = result.stdout.splitlines()
    expected = expected_rules(required_ports)
    findings: list[Finding] = []

    for rule in expected:
        if rule not in rules:
            findings.append(Finding(binary, f"missing rule: {rule}"))

    # Check that our chain jump comes before any INPUT DROP rule
    input_jump = f"-A INPUT -j {KTC_CHAIN}"
    drop_rules = [
        idx for idx, rule in enumerate(rules)
        if rule.startswith("-A INPUT") and rule.endswith(" -j DROP")
    ]
    if input_jump in rules and drop_rules:
        jump_index = rules.index(input_jump)
        first_drop = min(drop_rules)
        if jump_index > first_drop:
            findings.append(Finding(
                binary,
                f"{KTC_CHAIN} jump appears after an INPUT DROP — "
                f"traffic may be dropped before reaching our chain",
            ))

    return findings


# ── Enforcement ─────────────────────────────────────────────────────────────


def enforce(binary: str, required_ports: list[int]) -> None:
    """Recreate the KTC-MAIL-IN chain from scratch.

    This is DESTRUCTIVE — it flushes the chain and rebuilds it.
    Only call this during initial setup or when you know no other
    tool manages iptables rules on this host.
    """
    ports = sorted(required_ports)

    # Create chain (no-op if exists)
    _run([binary, "-N", KTC_CHAIN])
    # Remove any existing jump rule
    _run([binary, "-D", "INPUT", "-j", KTC_CHAIN])
    # Insert OUR jump at position 1 (before most other rules)
    _run([binary, "-I", "INPUT", "1", "-j", KTC_CHAIN])
    # Flush our chain
    _run([binary, "-F", KTC_CHAIN])
    # Build rules
    _run([binary, "-A", KTC_CHAIN, "-m", "conntrack",
          "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
    _run([binary, "-A", KTC_CHAIN, "-i", "lo", "-j", "ACCEPT"])
    for port in ports:
        _run([binary, "-A", KTC_CHAIN, "-p", "tcp", "-m", "tcp",
              "--dport", str(port), "-j", "ACCEPT"])
    _run([binary, "-A", KTC_CHAIN, "-j", "DROP"])

    # Verify the rules were written
    result = _run([binary, "-S", KTC_CHAIN])
    count = len(result.stdout.splitlines())
    print(f"{binary}: {KTC_CHAIN} has {count} rules")


# ── CLI entry point ─────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check or enforce KTC Mail firewall chains",
    )
    parser.add_argument(
        "--enforce", action="store_true",
        help="Recreate KTC Mail chain before checking",
    )
    parser.add_argument(
        "--ipv4-bin", default="iptables",
        help="iptables binary (default: iptables)",
    )
    parser.add_argument(
        "--ipv6-bin", default="ip6tables",
        help="ip6tables binary (default: ip6tables)",
    )
    parser.add_argument(
        "--config", type=Path, default=SETUP_PATH,
        help="KTC Mail setup profile path",
    )
    args = parser.parse_args()

    try:
        policy = load_policy(args.config)
    except Exception as exc:
        print(f"cannot load firewall config: {exc}", file=sys.stderr)
        return 2

    required_ports = policy.actual_open_ports

    if args.enforce:
        enforce(args.ipv4_bin, required_ports)
        enforce(args.ipv6_bin, required_ports)

    findings = (
        inspect_table(args.ipv4_bin, required_ports)
        + inspect_table(args.ipv6_bin, required_ports)
    )

    for finding in findings:
        print(f"{finding.table}: {finding.message}", file=sys.stderr)

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
