# KTC Mail — REST API (v1)

Machine-facing JSON API for automation (CI, monitoring, provisioning). It is
**independent of the browser session**: clients authenticate with a Bearer API
key, never a cookie.

## Base URL

```
/api/v1
```

The admin GUI binds loopback only and is fronted by Nginx (TLS). Point your
client at `https://<host>/api/v1/...` through the proxy, or `http://127.0.0.1:8080/api/v1/...` locally.

## Authentication

```
Authorization: Bearer ktc_<64-hex-chars>
```

- Keys are issued in the GUI at **API Keys** (or `GET /api/keys`). The raw
  key is shown **once** on creation.
- Keys are stored as SHA-256 hashes in `STATE_DIR/api-keys.json` (0600).
- Two scopes:
  - `read` — GET endpoints only.
  - `write` — all endpoints (mutating + read).
- A key with no `scope` field (created before scoping existed) is treated as
  `write`.
- Requests without a valid key get `401`; a key lacking the required scope
  gets `403`.

## Endpoints

| Method | Path | Scope | Description |
|--------|------|-------|-------------|
| GET | `/api/v1/domains` | read | List domains + per-domain mailbox counts |
| GET | `/api/v1/users` | read | List mailboxes (quota, message count, last login) |
| POST | `/api/v1/users` | write | Add a mailbox |
| DELETE | `/api/v1/users/{email}` | write | Remove a mailbox |
| POST | `/api/v1/users/{email}/password` | write | Set a mailbox password |
| GET | `/api/v1/spam-policy` | read | List rspamd user/domain overrides |
| PUT | `/api/v1/spam-policy` | write | Set a spam-policy override |
| GET | `/api/v1/quarantine` | read | List suspected spam (rspamd history) |
| POST | `/api/v1/quarantine/{message_id}/release` | write | Release a quarantined message to Inbox |
| POST | `/api/v1/quarantine/{message_id}/confirm` | write | Confirm a message as spam (train filter) |

 All responses are JSON.

 ### Domains are read-only by design

 `/api/v1/domains` is **GET-only**. Domains are infrastructure configuration
 (they drive DNS, TLS certificates and transport maps), so adding or removing a
 domain is a global server setting and lives exclusively behind the
 session-authenticated admin panel — never the API. This is enforced at
 startup by the boundary guard in `admin_server.create_app()`.

 ### Write-rate limit

 `write`-scoped keys are throttled to **60 write operations per 60 seconds per
 key** (Redis sliding window; in-process fallback if Redis is down). Exceeding
 it returns `429 Too Many Requests`. This bounds the blast radius of a leaked
 write key. `read` keys are unlimited (read-only, cheap).

 ## Examples

Issue a key in the GUI (scope `read` for dashboards, `write` for provisioning),
then:

```bash
# List domains (read key)
curl -H "Authorization: Bearer $KTC_READ_KEY" \
     https://mail.example.com/api/v1/domains

# Add a mailbox (write key)
curl -X POST -H "Authorization: Bearer $KTC_WRITE_KEY" \
     -H "Content-Type: application/json" \
     -d '{"email":"alice@example.com","password":"s3cret","quota":"2G"}' \
     https://mail.example.com/api/v1/users

# Set a per-user spam threshold (write key)
curl -X PUT -H "Authorization: Bearer $KTC_WRITE_KEY" \
     -H "Content-Type: application/json" \
     -d '{"target":"alice@example.com","target_type":"user","reject":12,"add_header":5}' \
     https://mail.example.com/api/v1/spam-policy
```

## Notes

- The endpoints reuse the same backend functions as the GUI, so behavior is
  identical between the two surfaces.
- `GET /api/status` (session **or** read-key) and unauthenticated
  `GET /api/health` are also available for monitoring.
- A machine-readable schema is served at `/openapi.json`; interactive docs at
  `/docs` (Swagger UI) and `/redoc`. These are admin-surface endpoints
  (loopback-bound, behind the TLS proxy).
- **Key hygiene:** each authenticated request updates `last_used_at` for the
  key (under a file lock) — the keys page shows last-used per key. Keys may be
  given an optional expiry (set in the GUI when created; never via the API) —
  expired keys are rejected. Rotate a key from the **API Keys** page (issues a
  new key, revokes the old in one action); revoke programmatically with
  `DELETE /api/keys/{id}` (write-scoped key).
- **Scope boundary:** the REST API is mailbox/domain-scoped only (users,
  domains, per-user/domain spam overrides, quarantine). Global server
  infrastructure — transports, DNS, TLS policy, firewall, backup, ACME, setup,
  options — is **admin-panel only** and is intentionally NOT exposed via the
  API. The schema (`/openapi.json`, `/docs`, `/redoc`) is served only to
  authenticated admins; it is not anonymously discoverable.
