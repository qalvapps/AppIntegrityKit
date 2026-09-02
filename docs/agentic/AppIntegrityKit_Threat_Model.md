# AppIntegrityKit Threat Model

## Protected assets

- Paid or cost-bearing backend operations.
- Provider and model API credentials held by product backends.
- Per-installation session authority and entitlement scopes.
- Integrity-key public material, counters, and Apple receipts.
- User privacy, including precise locations and imported personal content.

## Trust boundaries

- The app process and network are untrusted.
- Values supplied by the app are untrusted until cryptographically bound and
  checked against server-owned configuration.
- Apple’s App Attest root and the server’s product configuration are trusted.
- Product backend storage must provide atomic challenge consumption and counter
  updates.
- Private downstream workers trust only their product edge’s cloud identity.

## Primary threats and required controls

### Extracted reusable app credential

There is no app-wide shared secret. A hardware-backed key signs assertions and
the server exchanges verified assertions for short-lived scoped sessions.

### Replay of registration or assertion traffic

Every operation uses a high-entropy, purpose-bound, expiring, one-time server
challenge. Challenge consumption and assertion-counter advancement are atomic.

### Modified client data

The client signs the SHA-256 hash of the exact bytes sent as `clientData`. The
server hashes those received bytes, verifies the assertion, then parses and
checks every security-relevant field. It never re-encodes JSON before hashing.

### Client-selected app identity

The client supplies only a routing identifier. The server owns the mapping to
allowed App ID prefix, bundle identifier, App Attest environment, validation
categories, build policy, and allowed scopes.

### Cross-product or cross-environment token use

Keys and sessions are partitioned by application ID and environment. Sessions
carry an audience and scopes selected by the product backend. Development and
production records are never interchangeable.

### Compromised installation minting excessive traffic

App Attest is one signal, not perfect device security. Product backends enforce
per-key, per-session, and coarse network rate limits and may use Apple fraud
receipts as an additional risk signal.

### Session theft

Sessions are random, short-lived, scoped, stored as hashes on the server, and
kept in Keychain client-side. Product APIs avoid placing tokens or sensitive
inputs in URLs or logs. Revocation disables a key and its sessions.

### Unsupported surface bypass

Widgets and unsupported extensions do not bootstrap App Attest. They consume
cached product data, a narrowly scoped live session, or a one-use delegated
submission grant provisioned by the containing app through an already verified
session. The server does not trust a client boolean claiming App Attest is
unsupported.

### Delegated grant theft or replay

Delegated grants are separate from product sessions, random, one-use, bound
server-side to one product, environment, attested installation key, operation,
expiry, and revocation state, and stored only as hashes on the server. The
unsupported extension keeps raw grants only in a dedicated shared-Keychain
record using `AfterFirstUnlockThisDeviceOnly`.

First consumption atomically binds the grant to an exact submission ID and the
SHA-256 digest of the received request body. An exact replay returns the stored
acceptance without another use, product work reservation, or cost reservation;
a changed request fails closed. Provider-stage recovery remains product-owned
and must not infer exactly-once execution from grant replay. The transaction
also verifies that the bound installation key remains active. Product quota and
cost admission run independently after grant verification. Grant material,
token hashes, installation hashes, submission IDs, request digests, and source
payloads never enter logs or diagnostics.

### Cross-process delegated-pool lost update

A Swift actor does not serialize a containing app and extension. Without an
interprocess boundary, each can read the same Keychain pool and a later stale
write can erase a committed exact reservation or newly merged grant. Products
sharing a delegated pool must use AppIntegrityKit's coordinated adapter, which
holds a bounded operating-system-released lock across the entire Keychain
read/decode/mutate/write operation. The consumer supplies only a non-secret App
Group coordination location; raw authority and binding metadata remain in
Keychain. Coordination failure returns no authority and preserves durable local
capture. Termination during mutation can make completion uncertain; durable
storage must be the complete pre-operation or complete post-operation record,
and the next lock owner must reread before choosing authority. Server-side
atomic consumption remains the final protection against double authority and
duplicate product work reservation; provider-stage replay safety remains a
product-owned attempt-ledger concern.

### Key loss mistaken for revocation

App Attest provides no stable cross-key installation identity. Local credential
deletion, reinstall, or registration of a replacement key does not tell the
server which older binding to revoke. Deliberate product rotation revokes the
old binding while old verified authority remains available. After involuntary
loss, the containing app clears stale local grants when it detects the loss, but
any stolen old bearer remains valid until explicit installation/grant revocation
or its original short expiry. Products must monitor and accept that bounded
residual window rather than claiming replacement itself failed closed.

### Grant-policy reduction race

An offline installation may retain raw grants issued under an older, larger
target. For target-aware products, first-use consumption as well as issuance
must reconcile active unused records under the current monotonic server policy
revision in one serializable store operation. Excess unused grants are revoked
before new use. Exact replay of already-consumed authority remains valid because
it cannot start new product work.

### Development bypass reaching production

Test implementations are dependency-injected and absent from production
defaults. There is no environment variable or request header that disables
cryptographic verification. Development App Attest is an explicitly configured
environment with separate records and policy.

## Known residual risk

- A sufficiently compromised operating system may proxy legitimate assertions.
- A stolen live session can be used until expiry or revocation.
- A stolen unused delegated grant can authorize its one bounded operation until
  first use, expiry, installation revocation, or grant revocation.
- Local App Attest key loss or replacement does not itself revoke old server
  authority; a stolen old delegated bearer remains within the preceding bounded
  window.
- An unavailable interprocess coordinator can delay delegated submission; it
  cannot authorize a request. Termination during mutation may make completion
  uncertain, but cannot produce a partial record or lose another process's
  committed reservation.
- App Attest does not prove payment, user identity, or benign intent.
- Availability depends on Apple, the product edge, and persistent storage.

These risks are addressed with entitlement verification, short sessions,
quotas, monitoring, revocation, graceful product behaviour, and optional Apple
fraud assessment—not by weakening attestation verification.
