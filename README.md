# Unison Consent Service

Consent management service for the Unison platform, handling grant issuance, revocation, and verification.

## Status
Core service (active) — used by orchestrator/policy; runs on `7072` in devstack.

## Purpose

- **Grant Issuance**: Issue JWT-based consent grants with specific scopes and purposes
- **Grant Revocation**: Revoke grants before their natural expiration
- **Grant Introspection**: Verify and inspect grant tokens
- **Subject Grants**: List all active grants for a subject

## API Endpoints

### POST /grants
Issue a new consent grant.

**Request Body:**
```json
{
  "subject": "user-123",
  "scopes": ["unison.echo", "unison.storage.write"],
  "purpose": "Voice assistant access",
  "ttl": 3600,
  "audience": "orchestrator",
  "context": {}
}
```

**Response:**
```json
{
  "jti": "grant-id-123",
  "jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "expires_at": "2025-01-01T01:00:00Z"
}
```

## Docs

Full docs at https://project-unisonos.github.io

### BCI scopes (new)
- `bci.raw.read` — subscribe to raw neural streams (research/diagnostics).
- `bci.intent.subscribe` — receive decoded BCI intents/events.
- `bci.device.pair` — pair/attach BCI hardware.
- `bci.profile.manage` — read/write BCI profile block.
- `bci.export` — export neural recordings (XDF/EDF).
- `bci.hid.map` — manage virtual HID mappings.

BCI grants should be explicit, short-lived for raw/export, and logged via `unison-policy`.

### Actuation scopes (new)
- `actuation.*` — general actuation permission.
- `actuation.home.*`, `actuation.robot.*`, `actuation.desktop.*` — finer scopes for device classes.
- For high-risk actions, store the grant/consent id in `policy_context.consent_reference` in the Action Envelope so policy/audit can trace approvals.

### POST /revoke
Revoke a consent grant.

**Request Body:**
```json
{
  "jti": "grant-id-123"
}
```

### POST /introspect
Introspect a grant token.

**Request Body:**
```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

### GET /grants/{subject}
List active grants for a subject.

### GET /health
Health check endpoint.

### GET /ready
Readiness check endpoint.

## Configuration

Environment variables:

- Copy `.env.example` to `.env` for local runs.

- `UNISON_CONSENT_SECRET`: Secret key for signing JWTs (default: consent-secret-key)
- `UNISON_CONSENT_AUDIENCE`: Default audience for grants (default: orchestrator)
- `UNISON_CONSENT_DEFAULT_TTL`: Default TTL for grants in seconds (default: 3600)
- `UNISON_CONSENT_PORT`: Service port (default: 7072)

## Grant JWT Structure

Consent grants are JWTs with the following claims:

- `sub`: Subject identifier
- `aud`: Audience (typically "orchestrator")
- `iss`: Issuer ("unison-consent")
- `iat`: Issued at timestamp
- `exp`: Expiration timestamp
- `jti`: Grant ID (UUID)
- `scopes`: List of granted scopes
- `purpose`: Purpose of the grant
- `type`: "consent_grant"

## Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run the service
python src/main.py

# Run with custom configuration
UNISON_CONSENT_PORT=7072 python src/main.py
```

## Testing

```bash
# Issue a grant
curl -X POST http://localhost:7072/grants \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "test-user",
    "scopes": ["unison.echo"],
    "purpose": "Testing"
  }'

# Introspect a grant
curl -X POST http://localhost:7072/introspect \
  -H "Content-Type: application/json" \
  -d '{"token": "YOUR_JWT_TOKEN"}'
```

### Automated Tests
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -c ../constraints.txt -r requirements.txt
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 OTEL_SDK_DISABLED=true python -m pytest
```
