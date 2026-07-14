# AppIntegrityKit Architecture

## Repository architecture

```text
Swift app -> AppIntegrityKit -> product integrity edge
                                  | challenge/key/session store
                                  | product entitlement and quota policy
                                  v
                            private product worker
```

The Swift library and Python verifier share protocol v1 and deterministic test
vectors. They do not share runtime storage or product policy.

## Swift layers

- `AppIntegrity`: singleton-style public facade and injectable instance.
- `AppIntegrityState`: actor that serializes registration and session renewal.
- `AppAttestServicing`: hardware-backed key/attestation/assertion port.
- `AppIntegrityTransport`: versioned product-edge network port.
- `AppIntegrityCredentialStoring`: persistent key-ID/session port.
- `DeviceCheckAppAttestService`: production DeviceCheck adapter.
- `KeychainAppIntegrityCredentialStore`: production local storage adapter.
- `URLSessionAppIntegrityTransport`: JSON-over-HTTPS adapter.

The facade is immutable and `Sendable`; all mutable orchestration state is actor
isolated. Apps may use `AppIntegrity.shared`, while tests and apps with multiple
backends create separate instances.

Equivalent in-flight session requests are coalesced into one App Attest and
network operation. Requests with different entitlement evidence or refresh
semantics run in sequence. This matters because actors are reentrant at
`await`: actor isolation alone does not prevent two callers from overlapping
key registration or advancing the same App Attest assertion counter.

## Python layers

- `models`: language-neutral protocol values.
- `canonical`: strict base64url and exact-client-data parsing/binding.
- `_cbor`: bounded, duplicate-rejecting CBOR decoding for security artifacts.
- `apple`: Apple-root-pinned attestation and assertion cryptographic validation.
- `ports`: persistence, cryptographic verifier, clock, and token interfaces.
- future `service`: atomic registration and session policy orchestration.
- product adapters: FastAPI, Firestore, rate limiting, StoreKit, and cloud IAM.

The core Python package does not know about GoodTides, Recipeez, FastAPI, or
Firestore. Product backends compose those adapters and own authorization.

The attestation verifier accepts the exact `clientDataHash` bytes supplied to
Apple. For protocol v1, the service layer derives those bytes as
`SHA256(base64url_decode(challenge))`; keeping that derivation outside the
cryptographic primitive prevents accidental double hashing.

## Distribution

SwiftPM is primary. `scripts/make_xcframework.sh` creates an XCFramework for
binary consumers, and `scripts/create_docs.sh` generates DocC. Neither artifact
contains product configuration or credentials.
