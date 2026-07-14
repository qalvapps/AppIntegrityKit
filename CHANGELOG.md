# Changelog

## Unreleased

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

### Not production-ready

- The verifier still requires independent review and physical-device/TestFlight
  validation.
- No product backend, persistence adapter, or StoreKit policy is included yet.
