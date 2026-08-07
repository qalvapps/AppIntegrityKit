# AppIntegrityKit Agent Rules

For SMImporter integrations, first read the [SMImporter living architecture](../SMImporterWS/docs/SMIMPORTER_ARCHITECTURE.md). If AppIntegrityKit work changes a shared SMImporter protocol, policy, privileged boundary, or verified integration state, update that contract, its review metadata, and its decision log in the same change. Run `make architecture-check` from `../SMImporterWS` after changing the shared contract or its references.

Read these before changing the product:

1. `docs/agentic/AppIntegrityKit_Product_Spec.md`
2. `docs/agentic/AppIntegrityKit_Threat_Model.md`
3. `Protocol/v1.md`
4. `docs/agentic/AppIntegrityKit_Architecture.md`
5. `docs/agentic/AppIntegrityKit_Project_Plan.md`

## Security rules

- Fail closed. Test doubles and development conveniences must be explicit
  dependencies and must never be selected by production defaults.
- Never trust Team ID, App ID prefix, bundle ID, environment, build category,
  entitlement, or scopes merely because the client supplied them.
- Challenges are random, single-use, purpose-bound, stored as hashes, consumed
  atomically, and checked for expiry in application code.
- Assertions bind the exact `clientData` bytes sent to the server. Do not
  re-encode JSON before hashing it.
- Assertion counters are updated transactionally and must increase.
- Never log attestation objects, assertions, receipts, session tokens, precise
  user locations, or entitlement evidence.
- Keep App Attest key records and sessions isolated by product application ID
  and development/production environment.
- A protocol-byte change requires a new shared test vector and compatibility
  decision.

## Product rules

- Swift 6 strict concurrency; mutable orchestration state belongs in actors.
- Public Swift integration remains available through `AppIntegrity.shared`,
  with injectable isolated instances for tests.
- Use Swift Testing for Swift tests and pytest for Python tests.
- Keep the core verifier independent of FastAPI, Firestore, and product policy.
- SwiftPM is the primary source distribution. Keep XCFramework and DocC scripts
  working as secondary distribution outputs.
- GoodTides is the first reference integration; do not add tide-specific logic
  to this repository.
- Recipeez Share Extension support consumes a main-app-provisioned scoped
  session; it must not attempt unsupported App Attest bootstrapping.

## Verification

Run `scripts/verify.sh`. Do not claim production readiness without physical
development-environment attestation and TestFlight production-environment
attestation evidence.
