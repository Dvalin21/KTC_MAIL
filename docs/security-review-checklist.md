# KTC Mail — Security Review Checklist

## Purpose
Pre-flight checklist to run before exposing a KTC Mail server to production
traffic.  Each item has a pass/fail test or command.

---

### 1. Network Exposure

- [ ] **Port 25 is firewalled** if not behind a relay/VPS.
      `sudo nft list ruleset | grep 'tcp dport 25'` shows drop/reject.

- [ ] **Admin GUI is not exposed to the internet** (behind Nginx on localhost
      or VPN).  `ss -tlnp | grep 8081` shows `127.0.0.1:8081`.

- [ ] **Port 80 is closed** except during ACME HTTP-01 challenges.
      ACME timer handles this automatically.

- [ ] **SSH is key-only** — no password authentication.
      `sudo grep PasswordAuthentication /etc/ssh/sshd_config.d/ktc-mail.conf`
      shows `PasswordAuthentication no`.

### 2. TLS / Certificates

- [ ] **Certificate is valid and not expiring soon.**
      `openssl s_client -connect localhost:25 -starttls smtp < /dev/null \
        2>/dev/null | openssl x509 -noout -enddate`

- [ ] **TLSA records are published** for ports 25, 465, 993.
      `dig +short tlsa _25._tcp.<domain>`

- [ ] **DH parameters use 2048 bits or higher** (Postfix config).

### 3. Authentication & Access Control

- [ ] **Admin password is changed** from the auto-generated default.
      Verify: login, check audit log for password changes.

- [ ] **MFA is enabled** for the admin account.
      Settings → Two-Factor Auth in admin GUI.

- [ ] **Admin role is not 'admin' for daily-use accounts** — use 'operator'
      for non-admin staff.

- [ ] **Rate limiting is enabled** (default: on).
      `systemctl status ktc-mail-rate-limit.service`

### 4. Abuse Prevention

- [ ] **Fail2ban jails are active.**
      `sudo fail2ban-client status` shows `Postfix`, `Dovecot`, `Roundcube`
      jails with non-zero totals.

- [ ] **DNSBL checks are enabled** in Postfix config.
      `postconf smtpd_recipient_restrictions` includes `reject_rbl_client`.

- [ ] **SPF / DKIM / DMARC records are published** and valid.
      `dig +short txt <selector>._domainkey.<domain>`
      `dig +short txt <domain> | grep 'v=spf1'`
      `dig +short txt _dmarc.<domain>`

- [ ] **Postscreen is enabled** (greylisting at the SMTP level).
      `postconf postscreen_access_list` is non-empty.

### 5. Backups & Recovery

- [ ] **Backup destination is configured** (restic repo).
      `ktc-mail backup status` shows last success.

- [ ] **Backup encryption password is stored safely** (not in config file).
      Check: `/etc/ktc-mail/backup-password` is `0400` permissions.

- [ ] **Restore procedure is documented** and tested at least once.
      See `docs/operations.md` or run `ktc-mail backup restore --help`.

### 6. System Hardening

- [ ] **AppArmor profiles are loaded and enforcing.**
      `sudo aa-status | grep ktc-mail` shows profiles in enforce mode.

- [ ] **Unattended-upgrades is installed** and configured.
      `sudo dpkg -l unattended-upgrades`
      Check: `/etc/apt/apt.conf.d/50ktc-mail-unattended-upgrades`

- [ ] **System is up-to-date** with security patches.
      `sudo apt-get upgrade --dry-run | grep -c 'upgraded'` is acceptable.

- [ ] **Audit logging is enabled** and logrotate is configured.
      `ls -la /var/lib/ktc-mail/audit.log`

### 7. Monitoring

- [ ] **Health check endpoint returns 200.**
      `curl -f http://localhost:8081/api/health`

- [ ] **Service status page shows all services active.**
      Admin GUI → Dashboard.

- [ ] **Log monitoring** — at minimum, check mail.log daily for
      authentication failures and bounce spikes.

---

## First-Response Runbook

If the server is blacklisted or compromised:

1. **Stop mail flow**: `postfix stop`
2. **Check audit log**: `tail -50 /var/lib/ktc-mail/audit.log`
3. **Check auth failures**: `sudo fail2ban-client status Postfix`
4. **Check outbound queue**: `postqueue -p | wc -l`
5. **Rotate credentials**: Change admin password, revoke API tokens,
   generate new DKIM keys.
6. **Restore from backup**: `ktc-mail backup restore <snapshot>`

---

*Last reviewed: 2026-05-13*
