# Changelog

## Unreleased

### Added

- Standalone SwiftPM library with a singleton-style, actor-backed client.
- DeviceCheck, Keychain, URLSession, and dependency-injection boundaries.
- App Attest registration and short-lived session orchestration foundation.
- Versioned protocol v1 and shared Swift/Python canonical client-data vector.
- Framework-neutral, fail-closed Python verifier ports and strict parser.
- Threat model, architecture, project plan, DocC, XCFramework packaging, and
  repository verification scripts.

### Not production-ready

- Apple attestation-object and assertion cryptographic verification remains the
  next milestone.
- No product backend, persistence adapter, StoreKit policy, or physical-device
  validation is included yet.

