# Delegated Submission Grants v1

## Status and compatibility

This is an additive companion contract to AppIntegrity protocol v1. It does not
change App Attest challenges, attestation objects, assertion client data,
session tokens, signed bytes, or the meaning of any field in `Protocol/v1.md`.
Existing v1 clients and product session policies remain compatible.

Cross-process storage coordination is a local-adapter hardening, not a wire
revision. It adds no HTTP field, changes no signed bytes, and preserves the
deployed delegated-pool record encoding. Products that never share a delegated
pool between processes may retain a single-process adapter. A product that shares
the pool between a containing app and an extension must use a coordinated
adapter before enabling delegated authority in production. The coordinated
adapter exposes a product-neutral, non-secret capability version so a consumer's
configuration and release preflight can fail closed rather than silently
selecting the single-process adapter. The initial coordinated-store capability
version is `1`; the legacy single-process adapter reports no coordinated
capability and must not satisfy a manifest that requires version `1` or later.

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
- Cross-process coordination may use a consumer-supplied App Group location
  only for non-secret lock/version state. It never stores a raw grant, token
  hash, reservation, submission ID, request digest, session, installation
  identifier, or product payload.

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

Product target reductions must not depend on a future replenishment call. A
product adapter that maintains an outstanding target supplies its current
monotonic policy revision to both issuance and first-use consumption. The
serializable store boundary deterministically revokes excess active unused
records before evaluating a presented unused grant. Exact replay of an already
consumed grant remains available because it returns prior acceptance rather
than authorizing new work. This policy is product-owned and does not add a wire
field.

## Client pool mutation

Every mutation of one logical pool—merge, reserve, remove, and expiry
pruning—must be linearizable across every process that can access that pool. A
Swift actor provides in-process isolation only and is not sufficient for a
containing-app/share-extension boundary.

The production coordinated adapter holds a bounded, operating-system-released
interprocess lock across the complete Keychain read/decode/mutate/write
operation and always rereads after acquiring it. Failure to acquire the lock
before mutation returns no authority. The extension then preserves its durable
capture and defers to the containing app.

Termination or a thrown error after Keychain mutation begins may make the
caller's outcome uncertain. The durable record must be either the complete
pre-operation state or the complete post-operation state—never partial,
corrupt, or missing another process's committed reservation. A later caller
reacquires the lock and rereads before deciding whether the mutation committed.
Exact reservation is idempotent by submission ID and request digest, so a
post-commit termination rediscovers the same reservation rather than selecting
a second grant. Coordination uncertainty must never cause use of an
uncommitted grant or a second grant for an existing exact reservation.

The existing deployed local pool record remains readable. Adding coordination
is an adapter/API capability with record-migration and upgrade-compatibility
tests. It does not silently reinterpret an existing product's policy or move
its raw authority out of Keychain.

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
replay; it does not consume another use, create a new product work reservation,
or reserve new cost. Provider-stage recovery remains subject to the product's
own idempotency and attempt-ledger contract.

A changed submission ID or body after consumption fails closed. Wrong product,
environment, operation, a server-confirmed inactive or revoked installation
key, expired grant, exhausted grant, missing record, or store unavailability
also fail closed. No fallback converts any of those states into a normal
product session.

## Installation key loss and revocation

App Attest key replacement, local credential deletion, and reinstall are not
server-observable revocation events. Registering a new key creates a new
installation binding; it neither proves continuity with nor changes the active
state of an older key binding.

A product that claims immediate invalidation during deliberate rotation must
use an authenticated product-owned revocation operation while the old verified
session is still available, then clear the old local session and delegated pool.
If the old key or session has already been lost, the containing app clears its
local delegated pool as soon as it detects the loss and provisions a new key,
but an old raw grant remains acceptable under its old binding until the server
explicitly revokes that binding or grant, or the grant expires. Short
server-owned lifetimes bound this residual bearer-authority window. No shared
client or product adapter may infer server revocation merely from local key
replacement.

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
- After detected reinstall or App Attest key loss, the containing app clears
  stale local authority and provisions anew. Old server authority is rejected
  only after explicit installation/grant revocation or expiry; replacement
  registration alone is not revocation.
- Unsupported App Attest hardware cannot self-assert through an extension.
  Product policy may decline grant issuance without weakening verification.
- A legacy or deliberately single-process adapter may lose availability if it
  is incorrectly shared by multiple processes; server-side atomic consumption
  still prevents double grant authority and duplicate product work reservation.
  Provider-stage retry safety remains product-owned. Production multi-process
  consumers must use the coordinated adapter so this residual safety backstop
  is not mistaken for reservation durability.

## Test vectors

`Protocol/test-vectors/delegated-submission-grants-v1.json` is the shared Swift
and Python vector. It covers deterministic issuance hashes, first consumption,
same-request replay, changed-request replay, expiry, revocation, wrong product,
wrong environment, wrong operation, replaced installation key, exhaustion,
and store unavailability. The replaced-key case means the product store has
explicitly marked the old binding inactive; it does not model automatic
revocation caused by registering a different key.

Cross-process coordination does not change those wire vectors. Shared Swift
tests separately cover two independent store instances/processes racing merge,
reserve, remove, and pruning; bounded lock failure; crash recovery; and reading
the existing deployed record without lost reservations. Crash failpoints
immediately before and after the Keychain commit prove a complete pre- or
post-operation record and reread-based resolution of uncertain completion.
