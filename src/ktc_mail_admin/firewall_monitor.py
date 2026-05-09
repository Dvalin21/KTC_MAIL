#!/usr/bin/env python3
"""Monitor KTC Mail iptables/ip6tables policy ordering.

The monitor is deliberately conservative: by default it reports drift and exits
non-zero. Use --enforce from a systemd timer only after the generated rules have
been reviewed on the target host.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass

REQUIRED_TCP_PORTS = (22, 25, 80, 443, 587, 993, 4190)
KTC_CHAIN = "KTC-MAIL-IN"


@dataclass(frozen=True)
class Finding:
    table: str
    message: str


def run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)


def expected_rules() -> list[str]:
    rules = [f"-N {KTC_CHAIN}", f"-A INPUT -j {KTC_CHAIN}", f"-A {KTC_CHAIN} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT", f"-A {KTC_CHAIN} -i lo -j ACCEPT"]
    rules.extend(f"-A {KTC_CHAIN} -p tcp -m tcp --dport {port} -j ACCEPT" for port in REQUIRED_TCP_PORTS)
    rules.append(f"-A {KTC_CHAIN} -j DROP")
    return rules


def inspect_table(binary: str) -> list[Finding]:
    result = run_command([binary, "-S"])
    if result.returncode != 0:
        return [Finding(binary, f"cannot read rules: {result.stderr.strip()}")]
    rules = result.stdout.splitlines()
    findings: list[Finding] = []
    for rule in expected_rules():
        if rule not in rules:
            findings.append(Finding(binary, f"missing rule: {rule}"))
    input_jump = f"-A INPUT -j {KTC_CHAIN}"
    drop_rules = [idx for idx, rule in enumerate(rules) if rule.startswith("-A INPUT") and rule.endswith(" -j DROP")]
    if input_jump in rules and drop_rules:
        jump_index = rules.index(input_jump)
        first_drop = min(drop_rules)
        if jump_index > first_drop:
            findings.append(Finding(binary, f"{KTC_CHAIN} jump appears after an INPUT DROP rule"))
    return findings


def enforce(binary: str) -> None:
    run_command([binary, "-N", KTC_CHAIN])
    run_command([binary, "-D", "INPUT", "-j", KTC_CHAIN])
    run_command([binary, "-I", "INPUT", "1", "-j", KTC_CHAIN])
    run_command([binary, "-F", KTC_CHAIN])
    run_command([binary, "-A", KTC_CHAIN, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
    run_command([binary, "-A", KTC_CHAIN, "-i", "lo", "-j", "ACCEPT"])
    for port in REQUIRED_TCP_PORTS:
        run_command([binary, "-A", KTC_CHAIN, "-p", "tcp", "-m", "tcp", "--dport", str(port), "-j", "ACCEPT"])
    run_command([binary, "-A", KTC_CHAIN, "-j", "DROP"])


def main() -> int:
    parser = argparse.ArgumentParser(description="Check or enforce KTC Mail firewall chains")
    parser.add_argument("--enforce", action="store_true", help="Recreate KTC Mail chains before checking")
    parser.add_argument("--ipv4-bin", default="iptables", help="iptables binary")
    parser.add_argument("--ipv6-bin", default="ip6tables", help="ip6tables binary")
    args = parser.parse_args()

    if args.enforce:
        enforce(args.ipv4_bin)
        enforce(args.ipv6_bin)

    findings = inspect_table(args.ipv4_bin) + inspect_table(args.ipv6_bin)
    for finding in findings:
        print(f"{finding.table}: {finding.message}", file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
