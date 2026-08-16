# AppIntegrityKit

AppIntegrityKit is Qalv's reusable Apple App Attest client and server-verifier
product. It gives first-party Apple apps a versioned way to register an
attested installation and exchange assertions for short-lived, product-scoped
backend sessions. Its additive delegated-submission-grant contract lets a
supported containing app provision one-use authority for an unsupported
extension without making that extension an App Attest client or lengthening
normal sessions.

The repository has two deliverables:

- `AppIntegrityKit`: a Swift Package consumed by iOS and watchOS apps.
- `app-integrity-verifier`: a Python package consumed by product backends.

TideTables/GoodTides is the first reference integration. Recipeez is the second.
Apps share implementation and protocol, never keys, sessions, entitlements, or
backend trust stores.

Delegated grants are separately modelled one-use bearer values. Only an
already-verified product session may issue them; the backend stores only token
hashes, and client material lives in a dedicated shared-Keychain record. See
[the delegated grant protocol](Protocol/delegated-submission-grants-v1.md).

## Status

The repository is in pre-release integration development. The v1 wire models,
Swift client, strict Apple attestation/assertion verifier, Apple validation
sample, and negative vectors are present. The GoodTides reference integration
passes physical-device development and TestFlight production App Attest,
StoreKit Sandbox authorization, scoped-session renewal, and private-worker
access. It is not yet approved as a generally production-supported package:
independent security review, the remaining physical/TestFlight recovery matrix,
and App Store production authorization remain release gates.

## Codex integration workflow

When adopting or hardening AppIntegrityKit in another Qalv app, invoke the
personal Codex skill `$harden-ios-app-integrity`. It provides the app-integration,
fail-closed Release configuration, built-product inspection, physical-device,
and TestFlight verification workflow used by the reference implementations.

Before adding another product, follow the release-blocking
[consumer adoption plan](docs/agentic/AppIntegrityKit_Consumer_Adoption_Plan.md).
It defines the single product-neutral configuration, migration, preflight, and
cross-product isolation work required before Recipeez or future apps adopt the
package.

The skill is an execution aid, not a specification. This repository's product
specification, threat model, versioned protocol, architecture, and release
checklist remain authoritative.

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

`AppIntegrityError` is a product-neutral typed error and does not conform to
`LocalizedError`. Consumers map its stable `code`, optional `httpStatusCode`
and optional safe `backendCode` into their own localized UI. AppIntegrityKit
must never supply end-user sentences or assume how an app presents recovery.

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
