#!/usr/bin/env python3
"""KTC Mail — unified command-line interface.

Single entry point for ALL operations. No more 4 argparse CLIs with
inconsistent error handling. This replaces the separate main() in:
  - dns_provider.py
  - acme_manager.py
  - firewall_monitor.py
  - ssh_policy.py
  - config_renderer.py

Usage:
  ktc-mail setup                   Start first-run web GUI
  ktc-mail dns apply               Push DNS records
  ktc-mail dns verify              Verify DNS records
  ktc-mail dns plan                Show DNS plan
  ktc-mail acme issue              Issue certificate
  ktc-mail acme renew              Renew certificates
  ktc-mail acme deploy-hook        Post-renewal deploy hook
  ktc-mail acme auth               ACME DNS-01 auth hook
  ktc-mail acme cleanup            ACME DNS-01 cleanup hook
  ktc-mail firewall check          Verify firewall rules
  ktc-mail firewall enforce        Enforce firewall rules
  ktc-mail ssh apply               Apply SSH hardening
  ktc-mail ssh remove              Remove SSH policy
  ktc-mail ssh status              Check SSH policy
   ktc-mail config render           Print config to stdout
   ktc-mail config write            Write config to /etc
   ktc-mail dkim generate           Generate DKIM keypair and print DNS record
   ktc-mail user add <email>        Create mail user
   ktc-mail user del <email>        Remove mail user
   ktc-mail user list               List mail users
   ktc-mail user passwd <email>     Change user password
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import SETUP_PATH, SECRETS_PATH, setup_logging


def cmd_setup(args: argparse.Namespace) -> int:
    """Start the first-run setup web GUI on :8080."""
    from .app import main as app_main

    # Forward relevant args
    sys.argv = ["app.py"]
    if args.expose:
        sys.argv.append("--expose")
    sys.argv.extend(["--host", args.host, "--port", str(args.port)])
    return app_main()


def cmd_dns(args: argparse.Namespace) -> int:
    """Dispatch to dns_provider module functions."""
    # providers subcommand doesn't need a profile
    if args.dns_cmd == "providers":
        return cmd_dns_providers(args)

    from .dns_provider import (
        sync_records,
        verify_records,
        ptr_report,
        provider_from_config,
    )
    from .config import SetupProfile, read_json, save_json_private, DNS_STATE_PATH
    import time

    setup = read_json(args.config)
    profile = SetupProfile.from_dict(setup)
    secrets = {} if args.dry_run else read_json(args.secrets)
    transport = provider_from_config(setup, secrets, dry_run=args.dry_run)

    if args.dns_cmd == "plan":
        print(profile.generate_dns_plan())
        print()
        print(ptr_report(profile))
        return 0

    if args.dns_cmd == "apply":
        local = profile.generate_dns_records()
        actions = sync_records(local, transport, profile.domain, args.dry_run)
        for action in actions:
            print(action)
        if not args.dry_run:
            state = {
                "domain": profile.domain,
                "records": [r.to_dict() for r in local],
                "hash": local.content_hash(),
                "updated_at": int(time.time()),
                "actions": actions,
            }
            save_json_private(DNS_STATE_PATH, state)
        return 0

    if args.dns_cmd == "verify":
        local = profile.generate_dns_records()
        issues = verify_records(local, transport, profile.domain)
        if issues:
            for issue in issues:
                print(f"DRIFT: {issue}", file=sys.stderr)
            return 1
        print("DNS verification: all records match provider state.")
        return 0

    return 1


def cmd_dns_providers(args: argparse.Namespace) -> int:
    """List supported DNS providers and token requirements."""
    from .dns_provider import list_providers
    print(list_providers())
    return 0


def cmd_acme(args: argparse.Namespace) -> int:
    """Dispatch to acme_manager module functions."""
    from .acme_manager import (
        issue,
        renew,
        deploy_hook,
        acme_hook,
        check_tools,
        AcmeError,
    )

    try:
        if args.acme_cmd == "issue":
            if not args.dry_run:
                check_tools("issue")
            return issue(args.config, args.dry_run)

        if args.acme_cmd == "renew":
            if not args.dry_run:
                check_tools("renew")
            return renew(args.dry_run)

        if args.acme_cmd == "deploy-hook":
            return deploy_hook(args.config, args.dry_run)

        if args.acme_cmd == "auth":
            return acme_hook(
                args.config, args.secrets, cleanup=False,
                dry_run=args.dry_run,
                propagation_seconds=args.propagation_seconds,
            )

        if args.acme_cmd == "cleanup":
            return acme_hook(
                args.config, args.secrets, cleanup=True,
                dry_run=args.dry_run,
                propagation_seconds=0,
            )

        return 1
    except AcmeError as exc:
        print(f"acme error: {exc}", file=sys.stderr)
        return 1


def cmd_firewall(args: argparse.Namespace) -> int:
    """Dispatch to firewall_monitor module functions."""
    from .firewall_monitor import main as fw_main

    # Build argv for the existing firewall_monitor.main()
    sys.argv = ["firewall_monitor.py"]
    if args.enforce:
        sys.argv.append("--enforce")
    sys.argv.extend(["--config", str(args.config)])
    return fw_main()


def cmd_ssh(args: argparse.Namespace) -> int:
    """Dispatch to ssh_policy module functions."""
    from .ssh_policy import write_config, remove_policy, status, SshPolicyError

    try:
        if args.ssh_cmd == "apply":
            write_config(
                password_auth=args.password_auth,
                permit_root_login=args.permit_root_login,
                dry_run=args.dry_run,
            )
            return 0
        if args.ssh_cmd == "remove":
            remove_policy(dry_run=args.dry_run)
            return 0
        if args.ssh_cmd == "status":
            return status()
        return 1
    except SshPolicyError as exc:
        print(f"ssh policy error: {exc}", file=sys.stderr)
        return 1


def cmd_dkim(args: argparse.Namespace) -> int:
    """Generate DKIM keypair and write to disk."""
    from .config_renderer import dkim_write
    return dkim_write(args)


def cmd_user(args: argparse.Namespace) -> int:
    """Mail user account management."""
    from .user_manager import cmd_user as dispatch
    return dispatch(args)


def cmd_admin(args: argparse.Namespace) -> int:
    """Admin web interface management."""
    from .admin_server import dispatch as admin_dispatch
    return admin_dispatch(args)


def cmd_fail2ban(args: argparse.Namespace) -> int:
    """Fail2ban jail management."""
    from .fail2ban import dispatch as f2b_dispatch
    return f2b_dispatch(args)


def cmd_backup(args: argparse.Namespace) -> int:
    """Backup management (restic)."""
    from .backup_manager import dispatch as backup_dispatch
    return backup_dispatch(args)


def cmd_metrics(args: argparse.Namespace) -> int:
    """Prometheus metrics collection."""
    from .exporter import main as metric_main
    sys.argv = ["exporter.py"]
    return metric_main()


def cmd_config(args: argparse.Namespace) -> int:
    """Dispatch to config_renderer module functions."""
    from .config_renderer import main as cr_main

    sys.argv = ["config_renderer.py", args.config_cmd]
    sys.argv.extend(["--config", str(args.config)])
    if args.config_cmd in ("write", "validate"):
        sys.argv.extend(["--dest", str(args.dest)])
    if args.config_cmd == "write":
        if args.dry_run:
            sys.argv.append("--dry-run")
    return cr_main()


def main() -> int:
    setup_logging()
    parser = argparse.ArgumentParser(
        description="KTC Mail — bare-metal Debian/Ubuntu mail server suite",
    )
    parser.add_argument(
        "--config", type=Path, default=SETUP_PATH,
        help="Setup profile path (default: /etc/ktc-mail/setup.json)",
    )
    parser.add_argument(
        "--secrets", type=Path, default=SECRETS_PATH,
        help="Secrets file path (default: /etc/ktc-mail/secrets.json)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Preview changes without writing",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # ── setup ──────────────────────────────────────────────────────────
    p_setup = sub.add_parser("setup", help="Start first-run setup GUI")
    p_setup.add_argument("--host", default="127.0.0.1")
    p_setup.add_argument("--port", type=int, default=8080)
    p_setup.add_argument("--expose", action="store_true")

    # ── dns ────────────────────────────────────────────────────────────
    p_dns = sub.add_parser("dns", help="DNS record management")
    p_dns.add_argument(
        "dns_cmd", choices=("plan", "apply", "verify", "providers"),
        help="DNS operation: plan=preview, apply=push, verify=check drift, providers=list all",
    )

    # ── acme ───────────────────────────────────────────────────────────
    p_acme = sub.add_parser("acme", help="ACME certificate automation")
    p_acme.add_argument(
        "acme_cmd",
        choices=("issue", "renew", "deploy-hook", "auth", "cleanup"),
        help="ACME operation",
    )
    p_acme.add_argument(
        "--propagation-seconds", type=int, default=45,
        help="DNS propagation wait time (auth only)",
    )

    # ── firewall ───────────────────────────────────────────────────────
    p_fw = sub.add_parser("firewall", help="Firewall policy management (nftables)")
    p_fw.add_argument("--enforce", action="store_true",
                       help="Recreate nftables rules before checking")

    # ── ssh ────────────────────────────────────────────────────────────
    p_ssh = sub.add_parser("ssh", help="SSH policy management")
    p_ssh.add_argument(
        "ssh_cmd", choices=("apply", "remove", "status"),
        help="SSH operation",
    )
    p_ssh.add_argument("--password-auth", action="store_true")
    p_ssh.add_argument("--permit-root-login", action="store_true")

    # ── config ─────────────────────────────────────────────────────────
    p_cfg = sub.add_parser("config", help="Mail stack configuration")
    p_cfg.add_argument(
        "config_cmd", choices=("render", "write", "validate"),
        help="Config operation: render=print, write=deploy, validate=check with real tools",
    )
    p_cfg.add_argument("--dest", type=Path, default=Path("/etc"))

    # ── dkim ───────────────────────────────────────────────────────────
    p_dkim = sub.add_parser("dkim", help="DKIM key management")
    p_dkim.add_argument(
        "dkim_cmd", choices=("generate",),
        help="DKIM operation",
    )
    p_dkim.add_argument(
        "--selector", default="default",
        help="DKIM selector name (default: default)",
    )

    # ── user ───────────────────────────────────────────────────────────
    p_user = sub.add_parser("user", help="Mail user account management")
    p_user.add_argument(
        "user_cmd", choices=("add", "del", "list", "passwd"),
        help="User operation",
    )
    p_user.add_argument("email", nargs="?",
                        help="User email address (required for add/del/passwd)")
    p_user.add_argument("--password",
                        help="Password (omit for prompt)")
    p_user.add_argument("--quota", default="1G",
                        help="Mailbox quota (default: 1G)")

    # ── admin ──────────────────────────────────────────────────────────
    from .admin_server import add_subparser as add_admin_subparser
    add_admin_subparser(sub)

    # ── fail2ban ───────────────────────────────────────────────────────
    from .fail2ban import add_subparser as add_f2b_subparser
    add_f2b_subparser(sub)

    # ── metrics ─────────────────────────────────────────────────────────
    p_metrics = sub.add_parser("metrics", help="Prometheus metrics collection")
    p_metrics.add_argument(
        "metrics_cmd", choices=("collect",),
        help="collect = run all collectors and write .prom file",
    )

    # ── backup ─────────────────────────────────────────────────────────
    from .backup_manager import add_subparser as add_backup_subparser
    add_backup_subparser(sub)

    args = parser.parse_args()

    dispatch = {
        "setup": cmd_setup,
        "dns": cmd_dns,
        "acme": cmd_acme,
        "firewall": cmd_firewall,
        "ssh": cmd_ssh,
        "config": cmd_config,
        "dkim": cmd_dkim,
        "user": cmd_user,
        "admin": cmd_admin,
        "fail2ban": cmd_fail2ban,
        "backup": cmd_backup,
        "metrics": cmd_metrics,
    }

    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        return 1

    try:
        return handler(args)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
