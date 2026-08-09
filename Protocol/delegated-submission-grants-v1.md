# Delegated Submission Grants v1

## Status and compatibility

This is an additive companion contract to AppIntegrity protocol v1. It does not
change App Attest challenges, attestation objects, assertion client data,
session tokens, signed bytes, or the meaning of any field in `Protocol/v1.md`.
Existing v1 clients and product session policies remain compatible.

A delegated submission grant is not an App Attest assertion or product session.
It authorizes one exact, idempotent product submission from an Apple surface
that cannot run App Attest, after the supported containing app has established
trust. A backend that does not implement this contract continues to accept only
its existing product sessions.

## Trust boundary

- Only a currently valid, short-lived product session may issue or replenish a
  grant pool. A grant cannot issue another grant, session, or challenge.
- The server derives application ID, App Attest environment, and installation
  key binding from the verified session. It never accepts those values as grant
  authority merely because the client supplied them.
- Server policy owns the allowed operation, pool count, expiry, and revocation.
  Product rate limits, endpoint authorization, and cost admission remain
  independent gates after grant verification.
- Each grant has a use limit of one exact logical submission. Capacity is
  increased with a bounded pool of separate grants, not a reusable grant.
- The raw grant is at least 32 random bytes, encoded as unpadded base64url. Only
  `SHA256(rawGrant)` is stored server-side.
- Client grant material is stored in a dedicated shared-Keychain record using
  `AfterFirstUnlockThisDeviceOnly`. It is never written to app-group files,
  preferences, diagnostics, analytics, crash metadata, or logs.

## Issuance

The containing app calls the product edge with its normal scoped session:

```http
POST /v1/integrity/delegated-grants
Authorization: Bearer <short-lived-product-session>
Content-Type: application/json
```

```json
{"protocolVersion":1,"operation":"import:submit"}
```

The request contains no pool size or lifetime. The product backend chooses both
from server configuration and may return zero grants when the pool is already
sufficient, policy is disabled, the session is ineligible, or quota is
exhausted.

The shared core applies defensive interoperability ceilings of 64 grants per
stored pool and a 24-hour maximum lifetime. These are not product defaults:
each product must configure a smaller measured pool and lifetime appropriate to
its share behavior and may disable issuance entirely.

```json
{
  "protocolVersion": 1,
  "applicationID": "example-ios",
  "environment": "development",
  "operation": "import:submit",
  "grants": [
    {
      "token": "opaque-unpadded-base64url",
      "expiresAt": "2026-08-09T12:05:00Z",
      "useLimit": 1
    }
  ]
}
```

Issuance stores each token hash with the session-derived application ID,
environment, attested installation-key hash, allowed operation, expiry,
one-use limit, and revocation state. Issuance must not extend the product
session that authorized it.

## Consumption

The unsupported extension first persists its source evidence locally. It may
then submit the exact product request with these headers:

```http
Authorization: AppIntegrity-Delegated <opaque-grant>
X-App-Integrity-Submission-ID: <stable-idempotency-id>
```

The product edge computes `requestDigest = SHA256(exact received HTTP body
bytes)`. It must not trust a client-supplied digest. Before product work, one
atomic store operation verifies:

1. the grant-token hash exists;
2. the server-selected product route, environment, and operation equal the
   stored binding;
3. the bound installation key still exists and is not revoked;
4. the grant is not revoked or expired;
5. the grant is either unused or already bound to this exact submission ID and
   request digest.

On first use, the transaction binds the grant to `submissionID`,
`requestDigest`, and a server-generated stable acceptance ID, and consumes its
single logical use. Product submission remains deterministically idempotent by
that acceptance ID. If the response is lost, the same grant, submission ID,
and exact body returns the original acceptance ID and is classified as a
replay; it does not consume another use or repeat charged work.

A changed submission ID or body after consumption fails closed. Wrong product,
environment, operation, revoked or replaced installation key, expired grant,
exhausted grant, missing record, or store unavailability also fail closed. No
fallback converts any of those states into a normal product session.

## Safe error contract

Product edges may map these stable internal classes to bounded HTTP responses:

- `invalid_grant`
- `grant_binding_mismatch`
- `grant_expired`
- `grant_exhausted`
- `grant_revoked`
- `installation_revoked`
- `grant_store_unavailable`

Error bodies and logs must not contain a raw grant, token hash, session token,
key ID or key hash, submission ID, request digest, source payload, or original
request body. User-facing recovery is durable local capture followed by a
containing-app submission when fresh authority is available.

## Failure states

- Before first containing-app run, no grant exists: local capture succeeds and
  submission waits for the containing app.
- After reboot but before first unlock, Keychain access is unavailable: local
  capture succeeds and submission waits.
- Reinstall or App Attest key replacement invalidates the old installation
  binding; old grants are rejected and the containing app provisions anew.
- Unsupported App Attest hardware cannot self-assert through an extension.
  Product policy may decline grant issuance without weakening verification.
- Cross-process client races may waste a grant, but server-side atomic
  consumption prevents double authority or duplicate charged work.

## Test vectors

`Protocol/test-vectors/delegated-submission-grants-v1.json` is the shared Swift
and Python vector. It covers deterministic issuance hashes, first consumption,
same-request replay, changed-request replay, expiry, revocation, wrong product,
wrong environment, wrong operation, replaced installation key, exhaustion,
and store unavailability.
