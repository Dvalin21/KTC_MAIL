INSTALL
=======

KTC Mail installs on a plain Debian 12 or Ubuntu 24.04 server. You need
root access and a domain where you can edit DNS records.

========================================================================
1. REQUIREMENTS
========================================================================

- A fresh Debian 12 or Ubuntu 24.04 server with root SSH access.
  Minimum: 2 GB RAM, 20 GB disk.
- A domain name you own (example.com).
- If your DNS provider is Cloudflare, Route53, Hetzner, Porkbun, GoDaddy,
  or DigitalOcean, have your API token ready.
- Port 25 must be reachable from the internet. Most residential ISPs
  block it. You need a VPS or business connection.

========================================================================
2. SSH IN AND UPDATE

========================================================================

  ssh root@<SERVER_IP>
  apt update && apt upgrade -y
  reboot

Wait for the reboot, then ssh back in.

========================================================================
3. INSTALL EVERYTHING

========================================================================

One script installs the entire mail stack and the KTC Mail package:

  cd /opt
  git clone https://github.com/Dvalin21/KTC_MAIL.git ktc-mail
  cd ktc-mail
  bash scripts/bootstrap-mail-stack.sh
  pip install .
  # if pip complains about an externally managed environment:
  pip install . --break-system-packages

Verify:

  ktc-mail --help

If "ktc-mail" is not found, use python3 -m ktc_mail_admin.cli instead.

========================================================================
4. OPEN THE WEB GUI

========================================================================

  ktc-mail setup

Open http://<SERVER_IP>:8080 in a browser. You see a form with three
fields:

  Domain           -- your domain (e.g. example.com)
  DNS API token    -- your DNS provider key
  Admin email      -- your email address on this server

Fill them in and click "Check everything." The system detects your
public IP, IPv6, DNS registrar, and whether port 25 is blocked. It
generates DKIM keys and builds a DNS record plan.

Review the plan. Click "Build my mail server."

========================================================================
5. WHAT HAPPENS

========================================================================

The button does six things in order:

  1. Save setup profile and API secrets
  2. Write all mail configs (Postfix, Dovecot, Rspamd, Nginx, autoconfig)
  3. Push DNS records (A, AAAA, MX, SPF, DKIM, DMARC, CAA)
  4. Start mail services (postfix, dovecot, nginx, rspamd)
  5. Issue a Let's Encrypt TLS certificate
  6. Apply firewall rules (only mail ports open, everything else dropped)

Each step shows a result on the next page: OK, WARN, or FAIL. Warnings
are normal for things like DNS propagation delay -- the system retries
automatically. If anything fails, the error tells you what to fix.

========================================================================
6. DONE

========================================================================

Your mail server is running. Connect your email client to:

  Server:    mail.yourdomain.com
  IMAP:      port 993 with TLS
  SMTP:      port 587 with STARTTLS
  Username:  your_full_email@yourdomain.com
  Password:  what you set with ktc-mail user add

========================================================================
7. CREATE USERS

========================================================================

  ktc-mail user add user@example.com

It prompts for a password. Your mailbox is ready.

========================================================================
8. WHAT RUNS AUTOMATICALLY

========================================================================

Systemd timers handle maintenance:

  ktc-mail-acme-renew.timer        -- renews TLS certs daily at 3 AM
  ktc-mail-backup.timer            -- nightly backup at 2 AM
  ktc-mail-firewall-monitor.timer  -- firewall drift check every 5 min

Logs:

  journalctl -u postfix -f         -- watch mail delivery
  journalctl -u dovecot -f
  journalctl -u rspamd -f

========================================================================
9. TROUBLESHOOTING

========================================================================

Postfix will not start:   postfix check
Dovecot will not start:    dovecot -n
Cert failed to issue:      run certbot certonly manually to see the error
Port 25 is blocked:        nothing KTC Mail can do, your ISP blocks it
