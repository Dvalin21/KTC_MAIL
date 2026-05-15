INSTALL
=======

KTC Mail installs on a plain Debian 12 or Ubuntu 24.04 server. It requires
root access and a domain where you can edit DNS records. Everything runs
on bare metal -- no Docker, no Kubernetes, no containers.

There is no automated install script that hides what it does. This document
tells you exactly what each command does so if something breaks you know
where to look.

========================================================================
1. REQUIREMENTS
========================================================================

What you need before you start:

- A server running Debian 12 or Ubuntu 24.04. Fresh install.
  Minimum: 2 GB RAM, 20 GB disk, public IP with ports 25 and 443 reachable.
- Root access (ssh root@your-server or sudo).
- A domain. If you do not have one, get one first -- mail without a domain
  is not a thing.
- DNS provider API key (for automatic DNS records). Supported providers:
  Cloudflare, AWS Route53, Hetzner, Porkbun, GoDaddy, DigitalOcean.
  If your provider is not listed you can still use manual DNS (see section 6b).

========================================================================
2. LOG IN AND UPDATE

========================================================================

Open a terminal and ssh to your server:

  ssh root@<SERVER_IP>

Bring the system up to date:

  apt update && apt upgrade -y

This will take a minute. When it finishes, reboot to make sure you are
running the latest kernel:

  reboot

Wait for the server to come back, then ssh in again.

========================================================================
3. INSTALL THE MAIL PACKAGES

========================================================================

KTC Mail uses standard Debian packages for the actual mail software.
Postfix, Dovecot, Rspamd, Nginx -- all installed from apt, not from
some random PPA or tarball.

Clone the repository:

  cd /opt
  git clone https://github.com/Dvalin21/KTC_MAIL.git ktc-mail
  cd ktc-mail

Run the bootstrap script. It installs everything with a single apt command
and enables the services:

  bash scripts/bootstrap-mail-stack.sh

What this does:
  1. Runs apt-get update
  2. Installs postfix, dovecot, rspamd, redis, nginx, certbot, nftables,
     fail2ban, unattended-upgrades, python3, openssl, curl, jq
  3. Enables redis-server, rspamd, fail2ban, postfix, dovecot, nginx
  4. Creates /etc/ktc-mail and /var/lib/ktc-mail directories

When it finishes you should see:

  "KTC Mail package dependencies are installed. Open http://SERVER_IP:8080
   to continue setup."

Ignore the part about opening port 8080 for now. We will use the CLI
instead of the web GUI for the initial setup.

Verify the services are running:

  systemctl status postfix dovecot nginx rspamd redis-server

Each should show "active (running)". If any say "failed" or "not found",
stop and check what went wrong before continuing.

========================================================================
4. INSTALL THE KTC MAIL PYTHON PACKAGE

========================================================================

The Python package provides the CLI and config generation.

  cd /opt/ktc-mail
  pip install .

Wait for "Successfully installed ktc-mail". If you see errors about
"externally-managed-environment" (this happens on modern Debian/Ubuntu),
use:

  pip install . --break-system-packages

After install, verify the CLI works:

  ktc-mail --help

You should see the available subcommands: setup, dns, acme, config,
firewall, ssh, user, dkim, backup.

If "ktc-mail" is not found, the install path is not in your PATH. Use
python3 -m ktc_mail_admin.cli instead:

  python3 -m ktc_mail_admin.cli --help

========================================================================
5. CREATE A SETUP PROFILE

========================================================================

KTC Mail needs to know your domain, hostname, DNS provider, and other
settings before it can generate configs. Create these as a JSON file.

  nano /opt/ktc-mail/setup.json

Paste the following, replacing the values with your own:

  {
    "domain": "example.com",
    "hostname": "mail.example.com",
    "admin_host": "admin.example.com",
    "webmail_host": "webmail.example.com",
    "admin_email": "admin@example.com",
    "public_ipv4": "203.0.113.10",
    "public_ipv6": "",
    "dns_provider": "cloudflare",
    "certificate_mode": "dns-01-api"
  }

Fill in these values:

  domain         -- the domain you own (e.g. example.com)
  hostname       -- the server hostname (e.g. mail.example.com)
  admin_host     -- hostname for the admin web GUI
  webmail_host   -- hostname for the webmail
  admin_email    -- your email address on this server
  public_ipv4    -- your server's public IPv4 address
  public_ipv6    -- your server's public IPv6 address, or "" if none
  dns_provider   -- one of: cloudflare, route53, hetzner, porkbun,
                     godaddy, digitalocean, manual
  certificate_mode -- dns-01-api (automatic) or manual

Save the file.

Load the profile into KTC Mail:

  mkdir -p /etc/ktc-mail
  cp /opt/ktc-mail/setup.json /etc/ktc-mail/setup.json

If you use a DNS provider that supports API automation, also create
the secrets file:

  nano /etc/ktc-mail/secrets.json

For Cloudflare:

  {
    "cloudflare_api_token": "your-cloudflare-api-token"
  }

For Route53:

  {
    "aws_access_key_id": "your-aws-key",
    "aws_secret_access_key": "your-aws-secret"
  }

For other providers, see: ktc-mail dns providers

Set strict permissions on the secrets file:

  chmod 600 /etc/ktc-mail/secrets.json

If you use "manual" as your DNS provider, skip the secrets file.
You will be given DNS records to create by hand.

========================================================================
6. DEPLOY THE CONFIGS

========================================================================

Generate and write all mail config files (Postfix, Dovecot, Rspamd,
Nginx, MTA-STS, autoconfig):

  ktc-mail config write --dest /etc

This renders 11 config files to the correct locations:

  /etc/postfix/main.cf
  /etc/postfix/master.cf
  /etc/dovecot/dovecot.conf
  /etc/rspamd/local.d/options.conf
  /etc/rspamd/local.d/worker-controller.inc
  /etc/rspamd/local.d/worker-proxy.inc
  /etc/rspamd/local.d/dkim_signing.conf
  /etc/nginx/webmail.conf
  /etc/nginx/mta-sts.txt
  /etc/autoconfig/thunderbird.xml
  /etc/autoconfig/outlook.xml

Validate every config file with the actual tools:

  postfix check
  dovecot -n
  rspamd --check
  nginx -t

All four should print no errors. If any fails, the configs have a problem.
Fix the setup profile and try again.

========================================================================
7. (OPTIONAL) DEPLOY THE FULL STACK WITH SOGo

========================================================================

If you want SOGo groupware (webmail, calendars, contacts), run the full
deploy script instead of steps 3-6:

  bash /opt/ktc-mail/scripts/ktc-mail-deploy.sh

This does everything from steps 3-6 plus:

  - Adds the SOGo apt repository
  - Installs SOGo, PostgreSQL, Memcached
  - Creates the vmail user and mail directory
  - Creates the SOGo database and user in PostgreSQL
  - Installs the ktc-mail Python package
  - Deploys all configs from the setup profile
  - Creates Postfix lookup tables
  - Starts all services (redis, postgresql, rspamd, postfix, dovecot,
    nginx, sogod)
  - Verifies each service is running

Run it as root:

  bash /opt/ktc-mail/scripts/ktc-mail-deploy.sh

When it finishes you should see:

  "KTC Mail deployed successfully"
  "Next steps: 1. Create a setup profile..."
  "Mail services running. Ports 25, 587, 465, 993 are open."

========================================================================
8. ISSUE TLS CERTIFICATES

========================================================================

Generate TLS certificates with Let's Encrypt:

  ktc-mail acme issue

This uses DNS-01 challenge (no port 80 needed). It will:

  1. Use your DNS provider API to create a _acme-challenge TXT record
  2. Tell Let's Encrypt to verify it
  3. Save the certificate to /etc/letsencrypt/live/
  4. Remove the challenge record
  5. Restart Postfix and Dovecot to pick up the new cert

Verify the certificate exists:

  ls /etc/letsencrypt/live/MAIL.YOURDOMAIN/

You should see fullchain.pem, privkey.pem, cert.pem, chain.pem.

If you use manual DNS, the command will print a TXT record value.
Create that record in your DNS provider's control panel, then run:

  ktc-mail acme issue --manual-continue

========================================================================
9. PUSH DNS RECORDS

========================================================================

Create the required DNS records automatically:

  ktc-mail dns apply

This creates records for:

  A         mail.example.com       -> your server IPv4
  AAAA      mail.example.com       -> your server IPv6 (if set)
  MX        example.com            -> mail.example.com
  TXT       example.com            -> "v=spf1 mx ~all"
  TXT       _dmarc.example.com     -> DMARC policy
  TXT       mail._domainkey...     -> DKIM public key
  CAA       example.com            -> "letsencrypt.org"
  SRV       _autodiscover._tcp     -> mail.example.com

If you use manual DNS, the command prints each record. Create them in
your DNS control panel. KTC Mail cannot create them for you.

========================================================================
10. VERIFY EVERYTHING

========================================================================

Check that ports are listening:

  ss -tlnp | grep -E ':(25|587|465|993|443) '

You should see at least:

  LISTEN  :25    (postfix SMTP)
  LISTEN  :587   (postfix submission)
  LISTEN  :465   (postfix smtps)
  LISTEN  :993   (dovecot IMAPS)
  LISTEN  :443   (nginx HTTPS)

Check the firewall:

  ktc-mail firewall check

It should show "nftables: OK" or "iptables: OK" with the expected rules.

Test SMTP with openssl:

  openssl s_client -connect localhost:25 -starttls smtp -quiet

You should see a 220 banner and the server certificate.

Test IMAPS:

  openssl s_client -connect localhost:993 -quiet

You should see a Dovecot banner and the server certificate.

Check your DNS records from outside:

  dig MX example.com +short
  dig TXT _dmarc.example.com +short
  dig CAA example.com +short

If everything works, your mail server is live.

========================================================================
11. CREATE MAIL USERS

========================================================================

Add your first mailbox:

  ktc-mail user add user@example.com

It will prompt for a password. The user is added to Dovecot's passwd-file
at /etc/dovecot/users.

List users:

  ktc-mail user list

Change a password:

  ktc-mail user passwd user@example.com

Remove a user:

  ktc-mail user del user@example.com

========================================================================
12. WHAT RUNS AUTOMATICALLY

========================================================================

After install, these systemd timers keep things running:

  ktc-mail-acme-renew.timer    -- Renews TLS certs daily at 3 AM
  ktc-mail-backup.timer        -- Backup nightly at 2 AM
  ktc-mail-exporter.timer      -- Prometheus metrics every 60s
  ktc-mail-firewall-monitor.timer -- Firewall drift check every 5 min
  ktc-mail-rate-limit.timer    -- Rate limit cleanup hourly

You can check each with:

  systemctl status ktc-mail-acme-renew.timer

Logs go to journalctl:

  journalctl -u postfix -f     (watch mail logs)
  journalctl -u dovecot -f
  journalctl -u rspamd -f

========================================================================
13. TROUBLESHOOTING

========================================================================

Port 25 is blocked by my ISP.

Many residential ISPs block port 25. You need a VPS or business internet.
If you cannot get port 25 open, KTC Mail will not work as an MX server.
Consider a relay service.

Certificates failed to issue.

Run manually to see the error:

  certbot certonly --manual --preferred-challenges dns -d mail.example.com

The error message will tell you exactly what is wrong (DNS not propagated,
API token invalid, rate limited, etc.).

Postfix will not start.

  postfix check

Prints the exact config error with line number. Usually a missing file
or typo in main.cf.

Dovecot will not start.

  dovecot -n

Prints the parsed config. If there is an error, it says where.

I broke something and want to start over.

  rm -f /etc/ktc-mail/setup.json /etc/ktc-mail/secrets.json
  dpkg-reconfigure postfix dovecot-core

This wipes the KTC Mail configs and restores the default package configs.
Your mail data in /var/mail is not affected.

========================================================================
14. WHAT YOU DO NOT GET WITH THE BETA

========================================================================

KTC Mail v0.4.0-beta is a working mail server. It is also incomplete.
These features are not ready yet:

  - Webmail UI (use SOGo at https://webmail.YOURDOMAIN/SOGo)
  - Admin web GUI (use the CLI for now)
  - Per-domain DKIM keys (one key for the whole server)
  - Automatic spam training
  - Quota management
  - Migration tools from other mail servers

If you need any of these, wait for a later release or add them yourself.
The code is open. The configs are plain text. Nothing is hidden.
