# AppIntegrityKit

AppIntegrityKit is Qalv's reusable Apple App Attest client and server-verifier
product. It gives first-party Apple apps a versioned way to register an
attested installation and exchange assertions for short-lived, product-scoped
backend sessions.

The repository has two deliverables:

- `AppIntegrityKit`: a Swift Package consumed by iOS and watchOS apps.
- `app-integrity-verifier`: a Python package consumed by product backends.

TideTables/GoodTides is the first reference integration. Recipeez is the second.
Apps share implementation and protocol, never keys, sessions, entitlements, or
backend trust stores.

## Status

The repository is in pre-release integration development. The v1 wire models,
Swift client, strict Apple attestation/assertion verifier, Apple validation
sample, and negative vectors are present. It is not yet approved for production
traffic: an independent security review, atomic persistent storage adapters,
physical-device validation, and a TestFlight production run remain release
gates.

## Swift Package

During local development:

```swift
.package(path: "../AppIntegrityKit")
```

After the first tagged release:

```swift
.package(
    url: "https://github.com/qalvapps/AppIntegrityKit.git",
    from: "0.1.0"
)
```

Apps import the single public library:

```swift
import AppIntegrityKit
```

The shared facade is `AppIntegrity.shared`. Tests and multi-backend apps may
create isolated `AppIntegrity()` instances and inject transports, App Attest
services, and credential stores.

## Repository verification

```bash
scripts/verify.sh
```

The verification script runs Swift Testing, Python tests, XcodeGen generation,
and an unsigned iOS framework build using temporary build directories.

## Security boundary

AppIntegrityKit proves app-installation integrity; it does not prove a person’s
identity or paid entitlement. Product backends remain responsible for StoreKit
verification, authorization scopes, rate limits, abuse policy, and private
downstream service access.

Read [the threat model](docs/agentic/AppIntegrityKit_Threat_Model.md) and
[protocol v1](Protocol/v1.md) before changing any signed bytes or verifier rule.
