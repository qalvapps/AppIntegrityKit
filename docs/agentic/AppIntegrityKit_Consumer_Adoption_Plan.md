# AppIntegrityKit Consumer Adoption Plan

## Priority

This is a release-blocking engineering task to complete before integrating a
second product. AppIntegrityKit's verifier is deliberately product-neutral, but
the complete adoption and release contract is currently distributed across
documentation, skill instructions, and the GoodTides reference integration.
Starting Recipeez in that state risks creating two operational models that must
be supported indefinitely.

The work must preserve service for existing GoodTides installations while
making the new contract the only supported path for future consumers.

## Outcome

A new Qalv app can adopt AppIntegrityKit through one documented, validated path.
Product identity and policy remain owned by the product backend; AppIntegrityKit
provides reusable types, validation, templates, and release checks without
containing GoodTides, Recipeez, or other product identifiers.

## Required work

### One consumer manifest

Define a versioned, non-secret manifest or equivalent typed configuration that
records each product's required integration inputs:

- Team ID, bundle ID, and Apple application identifier;
- stable development and production routing application IDs;
- production backend URL and protected methods or paths;
- App Attest environments and accepted validation categories;
- allowed scopes and the product authorization/entitlement policy;
- bundle-version policy;
- legacy App Attest decision and its mandatory compensating authorization;
- storage partitions, session lifetime, revocation, rate limits, and quotas;
- extension/watch behavior and any permitted delegated authority.

The manifest is configuration, never a credential. Provider secrets, reusable
tokens, StoreKit private keys, and integrity artifacts must not appear in it.

### Typed bundle-version policy

Replace the assumption that every consumer maintains an ever-growing exact
allowlist with an explicit policy type:

- exact accepted versions for controlled development or TestFlight use;
- minimum supported version plus explicit revoked versions for released apps.

Comparable versions must use a strictly validated `CFBundleVersion` grammar and
fail closed when malformed. The verifier must continue checking Apple's signed
bundle-version field whenever the extended grammar is present.

Pre-iOS 27 legacy App Attest contains no signed category or bundle version.
Enabling it must remain an explicit per-application decision and must require a
documented, server-verified compensating authorization signal. A client flag is
never sufficient.

### Generic adoption and release tooling

Provide product-neutral commands or templates that:

1. create or validate the consumer manifest;
2. report every app-specific input that the product owner must supply;
3. inspect a built `.app`, archive, or exported `.ipa` against the manifest;
4. verify signed entitlements, bundle identity, environment, category/build
   policy, Release endpoint, and absence of Debug bypasses;
5. verify that deployed backend policy accepts the build before upload;
6. fail the product archive or release workflow when required policy is absent
   or inconsistent.

Each consuming repository owns its deployment adapter and private environment
names. Shared tooling accepts explicit inputs and must not know GoodTides or
Recipeez cloud projects.

### Migration and compatibility

- Keep the current exact `allowed_bundle_versions` contract usable during a
  bounded migration window.
- Introduce the new policy additively or provide an explicit adapter; do not
  silently reinterpret existing configuration.
- Add warnings and a documented removal milestone for the old configuration.
- Deploy backend support before changing the GoodTides client release workflow.
- Migrate GoodTides and prove existing accepted builds still obtain sessions.
- Only then make the new manifest and preflight mandatory for Recipeez and
  future consumers.
- Avoid changing protocol v1 signed bytes. If a wire change becomes necessary,
  make a compatibility decision and add matching Swift/Python vectors first.

### Verification

Add automated coverage for:

- complete manifests and every missing or malformed required field;
- exact, minimum, and revoked bundle-version decisions;
- non-comparable bundle versions failing closed;
- extended App Attest category/build enforcement;
- legacy grammar rejection by default and acceptance only with the product's
  compensating authorization gate;
- development/production and product storage separation;
- GoodTides keys, sessions, entitlement evidence, and routing IDs being rejected
  by a second product policy, and vice versa;
- release artifact/backend-policy mismatches stopping before upload;
- migration from GoodTides' existing exact allowlist without downtime.

## Completion gates

- The repository README has one prominent adoption entry point.
- A developer or agent can enumerate all required product decisions without
  reading GoodTides source code.
- Missing or inconsistent policy fails during configuration or release
  preflight rather than on a user's device.
- GoodTides uses the new contract and passes two consecutive protected requests
  from development and TestFlight installations without re-registration.
- Recipeez can adopt the same contract without copying verifier, protocol,
  storage, or release-policy implementation from GoodTides.
- AppIntegrityKit's release checklist and hardening workflow reference this
  contract.
