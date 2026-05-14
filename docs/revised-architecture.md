# KTC Mail — Revised Architecture

## Why this document exists

The original `architecture.md` described what was built. This document
describes what **should** have been built, based on the original prompt
that the first ChatGPT pass failed to deliver faithfully. This is the
single source of truth going forward.

## Core design principles

1. **Caveman-simple setup, enterprise-hardened operation.**
   Setup is 3 fields and auto-detection. The rest is hidden behind
   derived defaults. Enterprise knobs are available through an explicit
   "Advanced" toggle.

2. **DNS structure is the system structure.**
   The `DnsRecordSet` is the source of truth for the entire mail
   infrastructure. All hostnames, certificates, service endpoints, and
   security policies derive from it. If you need to understand what the
   system does, read the DNS plan.

3. **No external SMTP dependency.**
   If port 25 is blocked, KTC Mail provisions its own relay VPS over
   WireGuard. Fully in-house. No third-party SMTP gateways.

4. **One wildcard certificate for everything, with explicit SANs.**
   `*.domain.com` covers all subdomains. Explicit SAN entries for 7
   service hostnames eliminate client compatibility hacks.

5. **Security is not optional.**
   SSH key-only by default. All ports closed except those needed. No
   port 80 unless HTTP-01 is selected. Rspamd + CrowdSec + GeoIP + rate
   limits. Password auth is a willingly-accepted-risk checkbox.

## Service-to-hostname mapping

| Service | Hostname | Purpose |
|---------|----------|---------|
| SMTP/IMAP | `mail.{domain}` | Primary server FQDN |
| Webmail | `email.{domain}` | SOGo or custom webmail |
| Admin GUI | `admin.{domain}` | KTC Mail admin portal |
| Auto-config | `autoconfig.{domain}` | Thunderbird auto-discovery |
| Auto-discover | `autodiscover.{domain}` | Outlook auto-discovery |
| IMAP endpoint | `imap.{domain}` | Explicit IMAP server name |
| SMTP endpoint | `smtp.{domain}` | Explicit SMTP server name |

All 7 resolve to the same IP. One wildcard cert covers `*.{domain}`
plus explicit SANs for each hostname. TLSA records are published per
service endpoint.

## DNS architecture

### DnsRecordSet — the source of truth

```
                    ┌──────────────────┐
                    │  DnsRecordSet    │
                    │  (local state)   │
                    └────────┬─────────┘
                             │ push / pull / verify
                    ┌────────▼─────────┐
                    │  DnsTransport    │
                    │  (registrar API) │
                    └────────┬─────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
     Cloudflare          Namecheap      GoDaddy ...
```

- `push()`: diff local vs remote, create/update/delete records
- `pull()`: import current state from provider (find drift)
- `verify()`: compare local vs remote, report differences
- Records are keyed by `f"{type}:{name}"` in a dict for O(1) lookup

### Record types generated

| Type | Example | Auto/manual |
|------|---------|-------------|
| A | `mail.example.com → 203.0.113.10` | Auto |
| AAAA | `mail.example.com → 2001:db8::10` | Auto (if IPv6) |
| MX | `example.com → 10 mail.example.com.` | Auto |
| TXT (SPF) | `example.com → v=spf1 ip4:203.0.113.10 mx ~all` | Auto, includes IP |
| TXT (DKIM) | `default._domainkey.example.com → v=DKIM1; k=rsa; p=...` | Auto, generated during setup |
| TXT (DMARC) | `_dmarc.example.com → v=DMARC1; p=none; ...` | Auto, optional |
| TXT (TLS-RPT) | `_smtp._tls.example.com → v=TLSRPTv1; rua=...` | Auto |
| CNAME | `admin.example.com → mail.example.com.` | Auto (7 hostnames) |
| SRV | `_submission._tcp.example.com → 0 1 587 mail.` | Auto |
| TLSA | `_25._tcp.mail.example.com → 3 1 1 <sha256>` | Auto, updated on renewal |
| PTR | `10.113.0.203.in-addr.arpa → mail.example.com` | Manual (registrar-dependent) |

### PTR (reverse DNS)

PTR is handled differently because it lives at the ISP/registrar level,
not in the DNS zone file. The system:

1. **Detects capability**: probes the registar API for PTR management
   support (most don't expose it via API)
2. **Reports the requirement**: shows the user "You need to set this PTR
   record with your ISP"
3. **Generates the command**: produces the `rdns` command for supported
   providers (e.g., DigitalOcean, Hetzner CLI)
4. **Probes compliance**: periodically checks if PTR is set correctly
   and warns if not

PTR should match `mail.{domain}` — the HELO/EHLO hostname.

### SPF

Must dynamically include the server's IPv4 and IPv6 addresses, not a
hardcoded `mx -all`. Generated per-profile:

```
v=spf1 ip4:{server_ipv4} ip6:{server_ipv6} mx ~all
```

The `mx` mechanism catches any future IP changes. The explicit `ip4`/`ip6`
mechanisms cover the initial setup.

### DMARC

Optional. Default to `p=none` with reporting only. Admin can later
promote to `p=quarantine` or `p=reject` after reviewing reports.

```
v=DMARC1; p=none; rua=mailto:dmarc@{domain}; ruf=mailto:dmarc@{domain}
```

---

## Port 25 blocking — VPS relay architecture

### Auto-detection

During setup, the system probes port 25 to a well-known SMTP server
(e.g., `gmail-smtp-in.l.google.com:25`). Three outcomes:

1. **Port 25 reachable** → direct mode, no relay needed
2. **Port 25 blocked, IPv6 available** → try IPv6 direct first
3. **Port 25 blocked, no IPv6** → VPS relay required

### VPS relay mode

```
                   WireGuard tunnel
  Internet ─────► VPS:25 ──────────► Mail Server:25
  Mail Server ──► VPS:25 ──────────► Internet
                    │
                    │ (Postfix as transparent proxy, zero mail logic)
```

The VPS runs a minimal Postfix in transparent relay mode + WireGuard.
Zero storage. Zero mail processing. Just packet forwarding.

**Setup flow:**

1. User provides Hetzner/DigitalOcean API key (optional, only if relay
   is needed)
2. KTC Mail provisions the cheapest VPS instance (~$5/month)
3. Installs WireGuard + minimal Postfix relay config
4. Establishes tunnel
5. Configures local Postfix to route outbound through relay
6. Sets MX to point to the VPS IP (or keeps pointing to local IP if
   port 25 actually works for inbound)

**Why not a public relay service?** You said "handle everything in
house if possible." A $5/month VPS is cheaper than any SMTP relay
service, and you control both ends. No rate limits, no data leaving
your tunnel, no third-party reading your mail flow.

---

## Certificate architecture

### One cert, multiple SANs

```
Subject: CN = *.example.com
SAN:
  DNS:*.example.com
  DNS:mail.example.com
  DNS:email.example.com
  DNS:admin.example.com
  DNS:autoconfig.example.com
  DNS:autodiscover.example.com
  DNS:imap.example.com
  DNS:smtp.example.com
```

Issued via ACME DNS-01 (wildcard-capable) or HTTP-01 (individual SANs
only, no wildcard).

### Why explicit SANs alongside wildcard

Some email clients (Outlook, some mobile MUAs) validate the server
certificate CN against the hostname they connected to. If CN is
`*.example.com` and they connected to `mail.example.com`, some reject
it. Explicit SAN entries fix this — every hostname appears literally.

### TLSA per service

TLSA records are published for each SMTP/IMAP endpoint:

```
_25._tcp.mail.example.com.     IN TLSA 3 1 1 <sha256>
_25._tcp.smtp.example.com.     IN TLSA 3 1 1 <sha256>
_993._tcp.imap.example.com.    IN TLSA 3 1 1 <sha256>
```

On certificate renewal, the deploy hook regenerates all TLSA records
with the new cert's SHA-256 and pushes them via DNS API.

---

## Security architecture

### Default posture

| Layer | Setting | Rationale |
|-------|---------|-----------|
| SSH auth | Key only | Password auth is opt-in, warned, logged |
| Firewall | Drop all, allow needed only | Default deny inbound |
| Port 80 | Closed unless HTTP-01 | DNS-01 keeps it shut |
| SMTP | Postfix postscreen + Rspamd milter | Multi-layer filtering |
| IMAP | Dovecot IMAPS (993), IMAP localhost-only (143) | No cleartext external; SOGo exception |
| Rate limits | Postfix anvil + Dovecot limits | Abuse containment |
| Spam | Rspamd + CrowdSec + GeoIP + DNSBL | Defense in depth |

### SSH policy

```python
@dataclass
class SshPolicy:
    key_only: bool = True
    # If False, admin must check an "I accept this risk" box
    password_auth: bool = False
    permit_root_login: bool = False
    # Additional hardening
    protocol: int = 2
    max_auth_tries: int = 3
    client_alive_interval: int = 300
    client_alive_count_max: int = 2
```

On setup completion, `/etc/ssh/sshd_config` is rewritten with these
settings and sshd is reloaded. Password auth requires an explicit
checkbox with a warning.

### Firewall

```
Chain ktc_mail INPUT (policy drop)
  ACCEPT conntrack ESTABLISHED,RELATED
  ACCEPT lo
  ACCEPT tcp/22    (SSH)
  ACCEPT tcp/25    (SMTP)
  ACCEPT tcp/443   (HTTPS)
  ACCEPT tcp/587   (Submission)
  ACCEPT tcp/993   (IMAPS)
  [tcp/80 if HTTP-01]
  [tcp/4190 if ManageSieve]
  DROP
```

Uses nftables (inet family — single ruleset for IPv4+IPv6). The iptables backend was
removed during Phase 8. There is no fallback — nftables has been the default
firewall on Debian since 10/Buster (2019) and Ubuntu since 20.04 (2020).

### Rate limiting

Three layers:

1. **Postfix anvil**: per-client connection/rate limits
2. **Postfix postscreen**: pre-queue zombie blocking
3. **CrowdSec (recommended)**: shared reputation, real-time blocklist

### DKIM key generation

Generated during setup, not deferred:

```bash
openssl rsa -in dkim-private.pem -pubout -outform DER | \
  openssl base64 -A
```

The public key is written to DNS as:
```
default._domainkey.{domain}. IN TXT "v=DKIM1; k=rsa; p={base64}"
```

The private key is stored at `/etc/ktc-mail/dkim/{selector}.private`
with `0600` permissions, readable by Rspamd.

---

## Caveman setup flow

### Screen 1: What do you want?

```
┌─────────────────────────────────────────┐
│  ✉ KTC Mail                             │
│                                         │
│  Your domain: [_____________]           │
│                                         │
│  DNS API token: [______________]        │
│                                         │
│  Admin email: [_______________]         │
│                                         │
│  [■] I understand SSH keys             │
│      are better than passwords          │
│                                         │
│   [Next →]                              │
│                                         │
│   [Advanced Settings ▾]                 │
│     (hidden until clicked)              │
└─────────────────────────────────────────┘
```

### Screen 2: Here's what I found

```
┌─────────────────────────────────────────┐
│  ✅ Everything looks good               │
│                                         │
│  Domain: example.com                    │
│  → I detected: Namecheap registrar      │
│  → I detected: 203.0.113.10 (IPv4)      │
│  → I detected: 2001:db8::10 (IPv6)      │
│  → Port 25 is BLOCKED by your ISP       │
│  → I'll set up: mail.example.com        │
│  → I'll set up: email.example.com       │
│  → I'll set up: admin.example.com       │
│  → (and 4 more auto-discovery hosts)   │
│                                         │
│  [■] Set up VPS relay for port 25      │
│      (needs Hetzner/DigitalOcean key)   │
│                                         │
│  Certificate: wildcard *.example.com    │
│  (DNS-01 via Namecheap API)             │
│                                         │
│  SSHD: Key-only (password disabled)     │
│  Firewall: Only ports 22,25,443,587,993 │
│                                         │
│   [✓ Build my mail server]              │
└─────────────────────────────────────────┘
```

### Screen 3: Complete DNS plan (before execution)

```
┌─────────────────────────────────────────┐
│  A      mail             203.0.113.10   │
│  AAAA   mail             2001:db8::10   │
│  MX     example.com      10 mail        │
│  TXT    example.com      v=spf1 ip4...  │
│  TXT    default._domain  v=DKIM1; k=... │
│  TXT    _dmarc           v=DMARC1; p=...│
│  CNAME  admin            mail           │
│  CNAME  email            mail           │
│  CNAME  autoconfig       mail           │
│  CNAME  autodiscover     mail           │
│  CNAME  imap             mail           │
│  CNAME  smtp             mail           │
│  SRV    _submission      0 1 587 mail   │
│  SRV    _imaps           0 1 993 mail   │
│  TLSA   _25._tcp.mail    3 1 1 <hash>   │
│                                         │
│  ⚠ PTR record: Contact your ISP to set │
│    10.113.0.203.in-addr.arpa → mail.ex.│
│                                         │
│   [Execute DNS plan]  [Edit]            │
└─────────────────────────────────────────┘
```

---

## File layout

```
/usr/lib/ktc-mail/
├── __init__.py              # Package marker, version
├── config.py                # Data structures, shared paths
├── app.py                   # Caveman setup GUI
├── dns_provider.py          # DnsRecordSet, transports (Cloudflare, Route53, Hetzner, DryRun)
├── acme_manager.py          # Wildcard cert, SAN list, TLSA, renew
├── firewall_monitor.py      # nftables policy monitor + enforcer
├── ssh_policy.py            # SSH configuration manager
├── dkim_keys.py             # DKIM key generation
├── bootstrap-mail-stack.sh  # Package dependency installer
├── vps_relay.sh             # VPS provisioning + WireGuard setup
```

---

## State machine

```
BOOTSTRAP ──► DNS_CONFIGURED ──► CERTS_ISSUED ──► MAIL_CONFIGURED
     │                                   │
     └──► RELAY_CONFIGURED ──────────────┘
                     │
                     ▼
            FIREWALL_APPLIED ──► SSH_HARDENED ──► READY
```

Each transition is idempotent. If the process dies mid-way, re-running
picks up where it left off.

---

## Implementation order

| Step | What | Why |
|------|------|-----|
| 1 | `config.py` data structures | Foundation for everything |
| 2 | `dns_provider.py` rewrite | DNS is the system structure |
| 3 | `app.py` caveman rewrite | UX is the product |
| 4 | `acme_manager.py` update | Cert with SAN list |
| 5 | `dkim_keys.py` | Showstopper: mail won't deliver |
| 6 | `ssh_policy.py` | Security baseline |
| 7 | `firewall_monitor.py` update | Match new security policy |
| 8 | VPS relay provisioning | Differentiator |

---

This file is the architecture source of truth. If something disagrees
with this document, the code is wrong.
