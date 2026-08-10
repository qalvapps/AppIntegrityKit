# AppIntegrityKit Project Plan

## Phase 0 — repository foundation

- [x] Standalone private repository and remote.
- [x] SwiftPM, XcodeGen, Swift Testing, pytest, DocC, and XCFramework structure.
- [x] Product specification and threat model.
- [x] Versioned v1 session client-data vector.
- [x] Injectable Swift orchestration boundaries.
- [x] Fail-closed Python verifier boundaries.

## Phase 1 — complete Apple verification

- [x] Implement all applicable steps in Apple’s Attestation Object Validation Guide.
- [x] Verify CBOR structure, Apple certificate chain, nonce extension, key ID,
  RP ID, AAGUID/environment, counter zero, validation category, and bundle
  version.
- [x] Verify assertion signature, RP ID, exact client-data binding, extensions, and
  monotonically increasing counter.
- [x] Add Apple’s official sample and tamper/replay vectors.
- [x] Validate current assertion signature and extension bytes from a physical
  development device, including Apple's prefixed extension schema.
- [x] Validate assertion bytes from a TestFlight production build, including
  the exact legacy grammar emitted by an Xcode 26-linked app.
- [ ] Obtain an independent security review before production use.

## Phase 2 — GoodTides reference backend

- [x] Create public `goodtides-api` Cloud Run edge with no provider keys.
- [x] Create Firestore in the reviewed permanent location.
- [x] Implement atomic challenge, key, counter, session, revocation, and quota
  adapters.
- [x] Invoke private `tide-data-broker` with Google service identity.
- [x] Change precise-coordinate forecast input from URL query to POST body.
- [x] Add StoreKit JWS verification as a separate authorization gate.

## Phase 3 — TideTables reference client

- [x] Enable App Attest on the iOS App ID.
- [x] Integrate the package behind TideTables’ provider abstraction.
- [x] Keep widgets, intents, and Live Activities cache-only.
- [ ] Add an independent watch identity only if watch live networking remains.
- [x] Validate development on a physical device through the complete GoodTides
  edge and private broker.
- [x] Validate production through TestFlight with initial registration followed
  by a fresh assertion/session that reuses the installation key.

## Priority gate — paved-road multi-app adoption

Complete the [consumer adoption plan](AppIntegrityKit_Consumer_Adoption_Plan.md)
before starting Recipeez integration. This is release-critical: GoodTides must
migrate without interruption, and new consumers must not introduce a second
configuration or release workflow that AppIntegrityKit must support indefinitely.

- [ ] Define one explicit, non-secret per-product integration manifest.
- [ ] Add a typed build policy with exact-version and minimum-plus-revocation
  modes while retaining a bounded migration path for current GoodTides policy.
- [ ] Provide generic adoption and release-preflight tooling with no
  product-specific identifiers baked into AppIntegrityKit.
- [ ] Make legacy App Attest compensation, backend storage, authorization,
  quota, revocation, and environment separation required checklist decisions.
- [ ] Add configuration, migration, and cross-product isolation tests.
- [ ] Migrate GoodTides to the new contract before Recipeez consumes it.

## Phase 4 — Recipeez adoption

- [ ] Remove release worker-key injection.
- [ ] Protect extraction and transcript edges with product sessions.
- [ ] Provision a narrow session to the Share Extension through an approved
  Keychain access group.
- [ ] Define the first-use flow when the extension runs before the main app.

## Phase 5 — unsupported-extension delegated submission

- [x] Define an additive one-use grant contract without changing v1 App Attest
  or session signed bytes.
- [x] Add a dedicated Swift shared-Keychain pool with exact local request
  reservation and lost-response replay.
- [x] Add framework-neutral Python issuance/consumption models and atomic store
  ports with shared positive and negative vectors.
- [ ] Integrate a product edge and extension, preserving independent product
  quota and cost controls.
- [ ] Verify physical development behavior and TestFlight production behavior.

## Release sequence

- `0.1.0`: GoodTides physical-device reference implementation.
- `0.2.0`: Recipeez/Share Extension support.
- `0.3.0`: entitlement helpers and operational hardening.
- `1.0.0`: both products production-proven with stable public API.
