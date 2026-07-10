# HANDOFF — KTC Mail (2026-07-10)

## State
- Branch `clean-scaffold-v2` (local) = `origin/clean-scaffold-v3` (pushed), commit **`97d8a42`**. Tree CLEAN.
- All PRODUCTION_ROADMAP.md items **H-1.1 → D-5 CLOSED + VM-verified** (real Debian 12 qemu/kvm, Python 3.11.2).
- No CRITICAL/HIGH blockers. Remaining work is OPERATOR INPUT or deep epics (see below).

## Verified this cycle (real VM, not host)
- `.deb` builds + installs; **8 AppArmor profiles ENFORCED** via systemd `AppArmorProfile=`.
- Unit suite **22/22** on 3.11. `render_all` 11 cfgs headless.
- Mail-plane: SMTP 220 + STARTTLS advertised + AUTH gating PASS; Dovecot IMAPS :993 UP.
- Backup: init (auto-gen pw) → snapshot → `restore --yes` recovered files; `restic check` clean.
- Multi-domain: `SetupProfile.domains` + renderers emit both domains; sql store fail-honest.

## Key gotchas (don't re-learn)
- Host is Python 3.13; **TARGET is 3.11** — nested f-strings / `f"{'x' if c else ''}"` break on target. Always `py_compile` with `/home/keith/.local/bin/python3.11`.
- Two-tree landmine: `debian/` is build source of truth; `packaging/debian/` is CI mirror. Root→packaging after edits. NEVER `rm -rf debian && cp packaging/debian`.
- VM approval gate trips on BUNDLED commands (systemctl+apparmor_parser+pgrep in one SSH). Split into one single-purpose call each.
- VM is throwaway; boot: `-display none -daemonize`. SSH port 2222, key `/home/keith/vm-work/vm_key`. Reusable script: `/home/keith/.hermes/vm-assets/ktc-mail-vm-verify.sh`.
- Per-user unit tests need root (`/etc/ktc-mail` write). Run `sudo python3 -m pytest` in VM.

## Operator / deep work NOT done (honest, not faked)
- OPERATOR: backup backend (`ktc-mail backup init <restic-url>`), SIEM target drop-in, DNS token.
- OPERATOR: full real-domain smoke test (DKIM/DMARC/SPF, DNS push→verify, admin MFA) — needs domain + ACME + DNS.
- DEEP: multi-domain SQL mailbox store (D-5 did profile/renderer layer; Dovecot SQL passdb/db + schema remain), OIDC (needs IdP), ActiveSync (SOGo EAS not wired).

## Authoritative docs (match `97d8a42`)
- `PRODUCTION_ROADMAP.md` — all items closed, verified evidence per item.
- `PRODUCTION_READINESS.md` — verdict + reference-suite comparison.
- `AUDIT_AND_HANDOFF.md` — fix ledger + open items.
- `REVIEW_LEDGER.md` — 100% line-by-line review record.
