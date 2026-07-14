# AppIntegrityKit Project Plan

## Phase 0 — repository foundation

- [x] Standalone private repository and remote.
- [x] SwiftPM, XcodeGen, Swift Testing, pytest, DocC, and XCFramework structure.
- [x] Product specification and threat model.
- [x] Versioned v1 session client-data vector.
- [x] Injectable Swift orchestration boundaries.
- [x] Fail-closed Python verifier boundaries.

## Phase 1 — complete Apple verification

- [ ] Implement all steps in Apple’s Attestation Object Validation Guide.
- [ ] Verify CBOR structure, Apple certificate chain, nonce extension, key ID,
  RP ID, AAGUID/environment, counter zero, validation category, and bundle
  version.
- [ ] Verify assertion signature, RP ID, challenge binding, extensions, and
  monotonically increasing counter.
- [ ] Add Apple’s official sample and exhaustive tamper vectors.
- [ ] Obtain an independent security review before production use.

## Phase 2 — GoodTides reference backend

- [ ] Create public `goodtides-api` Cloud Run edge with no provider keys.
- [ ] Create Firestore in the reviewed permanent location.
- [ ] Implement atomic challenge, key, counter, session, revocation, and quota
  adapters.
- [ ] Invoke private `tide-data-broker` with Google service identity.
- [ ] Change precise-coordinate forecast input from URL query to POST body.
- [ ] Add StoreKit JWS verification as a separate authorization gate.

## Phase 3 — TideTables reference client

- [ ] Enable App Attest on the iOS App ID.
- [ ] Integrate the package behind TideTables’ provider abstraction.
- [ ] Keep widgets, intents, and Live Activities cache-only.
- [ ] Add an independent watch identity only if watch live networking remains.
- [ ] Validate development on device and production through TestFlight.

## Phase 4 — Recipeez adoption

- [ ] Remove release worker-key injection.
- [ ] Protect extraction and transcript edges with product sessions.
- [ ] Provision a narrow session to the Share Extension through an approved
  Keychain access group.
- [ ] Define the first-use flow when the extension runs before the main app.

## Release sequence

- `0.1.0`: GoodTides physical-device reference implementation.
- `0.2.0`: Recipeez/Share Extension support.
- `0.3.0`: entitlement helpers and operational hardening.
- `1.0.0`: both products production-proven with stable public API.

