# AppIntegrityKit Product Specification

## Product promise

Give Qalv Apple apps one audited, reusable way to prove that sensitive backend
requests originate from a legitimate installation of an allowed app, without
shipping a reusable backend credential in an app binary.

## Consumers

- TideTables/GoodTides: licensed tide forecasts and future paid entitlements.
- Recipeez: extraction/transcription workers currently protected by reusable
  build-injected worker keys.
- Future first-party Apple apps with a product backend.

## Deliverables

1. A source-distributed Swift Package named `AppIntegrityKit`.
2. A Python server-verifier package named `app-integrity-verifier`.
3. A versioned language-neutral wire protocol.
4. Cross-language positive and negative test vectors.
5. A physical-device reference app and a FastAPI reference integration.
6. Optional XCFramework and generated DocC distribution artifacts.
7. An additive delegated-submission-grant contract for unsupported extensions.

## In scope

- App Attest key generation, registration, and assertion generation.
- Server challenge lifecycle and assertion replay protection contracts.
- Short-lived product-scoped session exchange.
- Dependency-injected credential storage and networking.
- Development and production environment separation.
- Extension-safe use of sessions established by a supported host app.
- One-use delegated submission grants issued only through an already verified,
  short-lived product session and stored in a dedicated shared-Keychain pool.
- Cryptographic verification primitives and framework-neutral server ports.

## Out of scope

- Human login or account management.
- StoreKit product definitions or product-specific entitlement policy.
- Product-specific rate limits, data APIs, or provider credentials.
- Product-specific grant pool sizes, lifetimes, endpoint operations, quotas,
  cost admission, or persistence adapters.
- A shared runtime that accepts tokens for every Qalv product.
- A client-reported “unsupported device” bypass.
- Central storage shared between unrelated product backends.

## Success criteria for 1.0

- GoodTides and Recipeez both consume a tagged release.
- No release app contains a reusable backend worker credential.
- Apple’s official validation sample and the repository’s negative vectors pass.
- Physical development attestation and TestFlight production attestation pass.
- Replays, expired challenges, wrong app identities, counter rollback, unknown
  keys, altered client data, and environment crossover are rejected.
- Installation/session records can be revoked without changing app binaries.
- Delegated grants reject changed-request replay, cross-product/environment use,
  revoked installations, expiry, exhaustion, and store unavailability while
  exact lost-response replay returns the original acceptance.
