# Changelog

## Unreleased

- Recover once when older OS releases report a stale post-reinstall App Attest
  assertion key as `invalidInput` instead of `invalidKey`.

- Removed product-facing English error descriptions from `AppIntegrityError`.
  Consumers now receive stable error keys and optional HTTP/backend codes and
  remain solely responsible for localized user-facing copy.

### Added

- Standalone SwiftPM library with a singleton-style, actor-backed client.
- DeviceCheck, Keychain, URLSession, and dependency-injection boundaries.
- App Attest registration and short-lived session orchestration foundation.
- Versioned protocol v1 and shared Swift/Python canonical client-data vector.
- Framework-neutral, fail-closed Python verifier ports and strict parser.
- Apple-root-pinned attestation verification with strict CBOR/DER parsing,
  certificate-path, nonce, identity, environment, key, validation-category, and
  bundle-version checks.
- Assertion signature, exact client-data, Apple key-ID, RP-ID, extension, and
  increasing-counter verification.
- Apple's official validation sample plus certificate, nonce, identity, policy,
  signature, client-data, replay, and counter-rollback negative tests.
- Threat model, architecture, project plan, DocC, XCFramework packaging, and
  repository verification scripts.
- Equivalent in-flight session requests are coalesced, while requests with
  different evidence or refresh semantics run in sequence so actor reentrancy
  cannot overlap App Attest registration or assertion-counter work.
- DeviceCheck failures are normalized into stable package errors. Rejected
  attestation or assertion keys are discarded and replaced once per operation,
  while Apple's transient `serverUnavailable` result retains the pending key
  for a later retry as required by App Attest guidance.
- A server `registration_required` response now replaces a locally registered
  key once, allowing safe recovery from missing backend key state without
  weakening revocation or generic verification failures.
- Attestation parsing reports safe stage-level CBOR decoder and
  certificate-encoding classifications without logging signed payloads, key
  identifiers, or receipts.
- Assertion verification follows Apple's two-stage construction by forming the
  App Attest nonce first and then verifying ECDSA-with-SHA256 over those nonce
  bytes, with a regression test rejecting the former prehashed interpretation.
- Assertion extension validation accepts exactly one complete Apple schema:
  either the current unprefixed names or the prefixed names observed on a
  physical development device; ambiguous and partial schemas fail closed.
- Explicit per-application compatibility for the exact pre-iOS 27 App Attest
  grammar, representing unavailable category/build metadata as absent while
  retaining strict rejection of malformed or partial extension bytes.
- Additive delegated submission-grant v1 contract, shared positive/negative
  vectors, Swift 6 shared-Keychain grant pool, and framework-neutral Python
  issuance/atomic-consumption ports without changing existing session bytes.

### Not production-ready

- The verifier still requires independent review and physical-device/TestFlight
  validation.
- No product backend, persistence adapter, or StoreKit policy is included yet.
