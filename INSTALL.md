INSTALL
=======

KTC Mail installs on a plain Debian 12 or Ubuntu 24.04 server. You need
root access and a domain where you can edit DNS records.

It is a two-script install plus a web form with three fields. No JSON
editing required.

========================================================================
1. REQUIREMENTS
========================================================================

- A fresh Debian 12 or Ubuntu 24.04 server with root SSH access.
  Minimum: 2 GB RAM, 20 GB disk.
- A domain name that you own (like example.com).
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
3. INSTALL THE MAIL PACKAGES

========================================================================

The bootstrap script installs Postfix, Dovecot, Rspamd, Redis, Nginx,
certbot, nftables, and fail2ban -- all from standard Debian packages.

  cd /opt
  git clone https://github.com/Dvalin21/KTC_MAIL.git ktc-mail
  cd ktc-mail
  bash scripts/bootstrap-mail-stack.sh

When it finishes, verify the services are running:

  systemctl status postfix dovecot nginx rspamd redis-server

All five should say "active (running)". If any say "failed" or "not found",
stop and fix that before continuing.

========================================================================
4. INSTALL THE KTC MAIL PACKAGE

========================================================================

  pip install .

If you get an error about an externally managed environment, run:

  pip install . --break-system-packages

Verify the CLI works:

  ktc-mail --help

If "ktc-mail" is not found, your PATH does not include the pip install
location. Use this instead for all commands:

  python3 -m ktc_mail_admin.cli --help

========================================================================
5. RUN THE SETUP WIZARD

========================================================================

  ktc-mail setup

This starts a web server on port 8080. Open this URL in your browser:

  http://<SERVER_IP>:8080

You will see a three-field form asking for:

  Domain           -- your domain (e.g. example.com)
  DNS API token    -- your DNS provider API key
  Admin email      -- your email address on this server

Fill it in and click "Check everything". The system will auto-detect
your public IP, IPv6 address, DNS registrar, and whether port 25 is
blocked. It will also generate DKIM keys and build a DNS record plan.

Review the plan. If it looks right, click "Build my mail server".

This saves the setup profile and pushes your DNS records (A, AAAA, MX,
SPF, DKIM, DMARC, CAA). If you selected "manual" as your DNS provider,
no records are pushed -- the wizard shows you what to create by hand.

After the wizard finishes, close the browser and stop the setup server
(Ctrl+C in the terminal).

========================================================================
6. DEPLOY THE MAIL CONFIGS

========================================================================

Now that the setup profile exists, generate and write all mail configs:

  ktc-mail config write --dest /etc

This renders 11 config files for Postfix, Dovecot, Rspamd, Nginx,
MTA-STS, and autoconfig.

Validate every config with the actual tools:

  postfix check
  dovecot -n
  rspamd --check
  nginx -t

All four must print no errors. If any fails, something is wrong with
your profile. Re-run the setup wizard or check /etc/ktc-mail/setup.json.

If you also want SOGo groupware (webmail, calendars, contacts), there
is a combined deploy script that does steps 3-6 and more:

  bash /opt/ktc-mail/scripts/ktc-mail-deploy.sh

It installs SOGo, PostgreSQL, and Memcached on top of the base stack,
creates databases, deploys configs, and starts everything. Run it instead
of steps 3-6 if you want the full groupware stack.

========================================================================
7. ISSUE TLS CERTIFICATES

========================================================================

  ktc-mail acme issue

This uses Let's Encrypt DNS-01 challenge through your DNS provider API.
No port 80 needed.

It will:
  1. Create a _acme-challenge TXT record via your provider API
  2. Tell Let's Encrypt to verify it
  3. Save the certificate to /etc/letsencrypt/live/
  4. Delete the challenge record
  5. Restart Postfix and Dovecot

If you use manual DNS, the command prints a TXT record value. Create it
in your DNS control panel, then run:

  ktc-mail acme issue --manual-continue

Verify the certificate exists:

  ls /etc/letsencrypt/live/MAIL.YOURDOMAIN/

========================================================================
8. CHECK THE FIREWALL

========================================================================

  ktc-mail firewall enforce

This ensures only ports 22, 25, 443, 587, 993, and 4190 are open.
Everything else is dropped by default.

Verify:

  ktc-mail firewall check

It should report "nftables: OK" (or iptables).

========================================================================
9. VERIFY EVERYTHING

========================================================================

Ports are listening:

  ss -tlnp | grep -E ':(25|587|465|993|443) '

You should see: 25 (SMTP), 587 (submission), 465 (smtps), 993 (IMAPS),
443 (HTTPS).

SMTP works:

  openssl s_client -connect localhost:25 -starttls smtp -quiet

You should see a 220 banner.

IMAPS works:

  openssl s_client -connect localhost:993 -quiet

You should see a Dovecot banner.

DNS from the outside (run on your desktop, not the server):

  dig MX example.com +short
  dig TXT _dmarc.example.com +short

========================================================================
10. CREATE YOUR FIRST MAILBOX

========================================================================

  ktc-mail user add user@example.com

It prompts for a password. Done. You can now log into this mailbox
with any IMAP client.

List users:

  ktc-mail user list

========================================================================
11. WHAT RUNS AUTOMATICALLY

========================================================================

Installed systemd timers:

  ktc-mail-acme-renew.timer        Daily at 3 AM
  ktc-mail-backup.timer            Daily at 2 AM
  ktc-mail-exporter.timer          Every 60 seconds
  ktc-mail-firewall-monitor.timer  Every 5 minutes
  ktc-mail-rate-limit.timer        Every hour

Logs:

  journalctl -u postfix -f
  journalctl -u dovecot -f
  journalctl -u rspamd -f

========================================================================
12. TROUBLESHOOTING

========================================================================

Postfix won't start -> postfix check
Dovecot won't start  -> dovecot -n
Cert failed          -> run certbot manually to see the exact error
Port 25 blocked      -> nothing KTC Mail can do, your ISP blocks it

========================================================================
13. HEADLESS INSTALL (NO WEB BROWSER)

========================================================================

If you are setting up a server that has no web browser, skip step 5.
Create the setup profile manually:

  nano /etc/ktc-mail/setup.json

Paste this and fill in your values:

  {
    "domain": "example.com",
    "hostname": "mail.example.com",
    "admin_email": "admin@example.com",
    "public_ipv4": "203.0.113.10",
    "dns_provider": "cloudflare",
    "dns_api_token": "your-api-token",
    "certificate_mode": "dns-01-api"
  }

Save it. Then create the secrets file:

  nano /etc/ktc-mail/secrets.json

  {
    "dns_api_token": "your-api-token"
  }

  chmod 600 /etc/ktc-mail/secrets.json

Then continue from step 6.
