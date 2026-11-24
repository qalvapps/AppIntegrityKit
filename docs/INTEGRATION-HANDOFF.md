# AppIntegrityKit integration handover

Updated 2026-11-24. This is an adoption guide, not a new protocol or a production
approval. The [protocol](../Protocol/v1.md), [threat model](agentic/AppIntegrityKit_Threat_Model.md),
[consumer adoption plan](agentic/AppIntegrityKit_Consumer_Adoption_Plan.md) and
[release checklist](RELEASE_CHECKLIST.md) remain authoritative.

## Portable dependencies

Both current Pawtrait consumers use AppIntegrityKit revision
`6d84b9c0af30b5ed43df6f7d4e4d741f16127e49`. This documentation update does not
require changing their runtime pin. SwiftPM requires Swift tools 6.2; the Python
verifier requires Python 3.12+ and cryptography 49.x. Package platform minimums
are not an app's deployment decision or a guarantee of hardware App Attest
support.

Use the remote Swift dependency shown in the [README](../README.md), with the
`AppIntegrityKit` library product and a committed resolution file. For Python,
resolve and lock the canonical verifier rather than copying its source:

```text
app-integrity-verifier @ git+ssh://git@github.com/qalvapps/AppIntegrityKit.git@6d84b9c0af30b5ed43df6f7d4e4d741f16127e49#subdirectory=Server/Python
```

When the app's Xcode project is generated (for example with XcodeGen) and
`*.xcodeproj/` is ignored, `Package.resolved` lives inside the ignored folder at
`<App>.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved`.
Verify that your generation/clean workflow preserves or restores this lockfile.
Git will not pick an ignored file up: add it with
`git add -f` (as Pawtrait does) and confirm with `git ls-files`.

Establish authorized private-repository access before resolving either package.
SSH is supported; for machines using GitHub CLI HTTPS credentials, the shared
backend [handoff](https://github.com/qalvapps/studio-backend/blob/1fc38fa97e6f0b8b8f7723e1c5ad74c3e967260d/docs/OTHER-APP-HANDOFF.md)
contains a tested, subshell-scoped rewrite for both Git SSH URL spellings. Do
not change global Git configuration or embed credentials in package URLs.

For server containers, resolve private dependencies in an authenticated build
step and publish verified target-platform wheels. The shared backend describes
its offline installation and dependency check; a direct VCS dependency in wheel
metadata can otherwise trigger Git access during installation. Do not copy SSH
keys into a runtime image or assume Linux wheels run on macOS.

## Implementation examples and ownership

- [Native Pawtrait](https://github.com/qalvapps/pawtraitmode-ios/tree/c2ecb9a3f8271cb1c1d5549492a7cf74e8e6b9db)
  is the portable Swift-package/shared-backend integration example. Its
  `Sources`, `project.yml`, `Backend` and deployment records show the complete
  app boundary. The older `pawtraitmode` website is a separate repository.
- [studio-backend handoff](https://github.com/qalvapps/studio-backend/blob/1fc38fa97e6f0b8b8f7723e1c5ad74c3e967260d/docs/OTHER-APP-HANDOFF.md)
  covers another-machine setup, including non-image operations. Its image
  engine v0.1.1 is pinned to `4a818712a4e27aab8fa2e30221214d166199896d`;
  that runtime pin predates the newer handoff documentation.
- GoodTides remains the original reference for development and TestFlight
  evidence. Pawtrait adds a working image-product example; it does not replace
  GoodTides' production-environment evidence or complete the shared release gates.

AppIntegrityKit owns the Swift client, versioned integrity protocol and
framework-neutral Python verification. The product backend owns atomic durable
stores, routing, allowed applications/scopes/builds, entitlement decisions,
quotas, model credentials, worker authentication and retention. App Attest
proves an installation signal, not payment or human identity.

For a text, speech or video product, reuse the integrity boundary. The shared
backend's `create_integrity_app`, `FirestoreIntegrityStore`, namespace wrappers
and `GoogleWorkerAuthorization` are adapter examples, not exports from this
verifier package. Its image `runtime_from_environment`, `DeploymentConfiguration`
and `GenerationJobs` are not generic non-image factories. Define the operation,
configuration, stages, durable outputs and cost policy separately. Any private
adapter helpers require an immutable dependency pin and compatibility tests.

## Record before integration

Record the app's routing application ID, bundle ID, actual signed Apple
application identifier, Team ID, endpoint, protected operations/scopes,
entitlement policy, App Attest environments, validation categories and accepted
bundle versions. Keep product and environment trust records isolated. Match
client routing to server-owned `AllowedApplication`; never derive permission
from client-supplied identity fields.

Decide the App Attest grammar policy together with supported OS versions and
build/distribution configurations. The verifier rejects exact legacy evidence
by default, for both attestation and assertions, because it lacks the signed
category/build metadata required by this policy. Apple describes these
extensions as additions in [iOS 27 (WWDC26, session 201)](https://developer.apple.com/videos/play/wwdc2026/201/).
Supporting devices still on iOS 26 therefore requires an explicit legacy-policy
decision; setting an app's minimum deployment target to iOS 26 does not make
those devices compatible with the default verifier policy.

Do not infer a universal OS-only or SDK-only rule. The existing GoodTides
reference records a TestFlight build made with Xcode 26.5 emitting exact legacy
attestation and assertion evidence on an iOS 27 device; see the repository's
[recorded reference status](agentic/AppIntegrityKit_Project_Plan.md#phase-1--complete-apple-verification).
That observation does not establish a controlled SDK/OS compatibility matrix.
An iOS 27 minimum alone is not proof that a particular build emits extensions.
Before release, verify registration and subsequent assertion-bound sessions for
each supported OS/build/distribution configuration. Either:

- require a verified extended-evidence configuration (Pawtrait currently uses
  iOS 27 and has development-device evidence), or
- explicitly enable `allows_legacy_app_attest=True` for that application and
  implement mandatory, independently server-verified compensating authorization
  bound to each session assertion (for example Apple-signed StoreKit evidence
  checked against the product's accepted app and distribution policy), or
- make protected features unavailable on unsupported configurations, with a
  clear product decision and appropriate app behavior.

The studio handbook's iOS 26 baseline does not resolve this choice. Shared
studio-backend v0.1.1's `policy.applications()` does not expose legacy acceptance,
and its image `GenerationScopeAuthorizer` rejects entitlement evidence. The
legacy path needs a reviewed app-owned application policy **and** authorization
adapter, with tests that deny sessions when compensating evidence is absent,
invalid or unbound. Merely setting the verifier flag is insufficient; this
handover update does not add that adapter or change shared runtime policy. Legacy results have
absent category/build metadata: configured allowlists do not restore those
signed guarantees. Document which guarantees the compensating control actually
provides and which remain unavailable.

Add the App Attest capability to the App ID and the
`com.apple.developer.devicecheck.appattest-environment` entitlement to the app.
Set its value per build configuration (Pawtrait uses
`$(PAWTRAITMODE_ATTEST_ENVIRONMENT)`: `development` for Debug, `production` for
Release) and confirm it in the signed product, for example with
`codesign -d --entitlements - <App>.app`. Keychain records are keyed by
routing application ID, so distinct development and production IDs keep their
keys apart.

Inspect the signed product: App ID prefix can differ from Team ID. Pawtrait's
verified development identifier is `8TY3Z59576.com.paulcalver.pawtraitmode`;
this is evidence for that app, not a value to copy. Copy neither its cloud
resources nor its test grants, provider secrets or installation records.

Development signing uses development App Attest. TestFlight uses production
App Attest and sandbox purchases; keep these environments independent. Follow
the Python README's category/build policy. Legacy grammar acceptance remains
explicit and requires server-verified compensating authorization. Exact build
allowlists are the current contract; minimum/revoked-version policy and a
unified consumer manifest remain adoption-plan work, not shipped features.

Use injected fixtures on Simulator and unsupported targets. Keep any development
bypass isolated from Release; inspect the actual signed Release product and
deployed policy before distribution. Optional extension/delegated-grant use
requires its own protocol, coordinated-store and release gates; Pawtrait's
normal-session evidence does not validate those features.

## Verification evidence and next-agent deliverables

Pawtrait's 2026-11-24 signed physical-device development run verified registration,
session issuance and protected catalogue/allowance access. The owner then
completed three portrait generations; backend records showed successful jobs,
asset access and three spent credits from a five-credit development grant.
This is functional consumer evidence, not a Pawtrait TestFlight/App Store
acceptance result, independent security review or full recovery/concurrency test.
No general production-readiness claim follows from it.

The next agent should leave the dependency locks, non-secret product policy,
signed-artifact inspection, deployed revision and rollback record, and separate
local/device/TestFlight evidence. Exercise renewal, replay, expiry, revocation,
product/environment isolation and the remaining recovery matrix. Do not log raw
integrity artifacts, session tokens, receipts or user content.

Run `scripts/verify.sh` for package changes and the consuming app/backend's
checks for integration changes. The script builds its virtual environment from
the `python3` on `PATH`, which must be 3.12 or newer. Some macOS installations
resolve `python3` to 3.9, which cannot satisfy this
package or the script's pip requirement. Check `python3 --version` and put a
supported interpreter first on `PATH`; `uv python install 3.12` alone installs
Python but does not guarantee that `python3` resolves to it. For example, with
`uv` available, run `uv run --python 3.12 --no-project bash scripts/verify.sh`.
Keep existing consumers pinned unless an upgrade is deliberately selected; documentation-only updates do
not establish a new runtime release or satisfy unchecked release gates.

The personal `harden-ios-app-integrity` skill mentioned in the README is
optional execution guidance and is not installed on every machine. This
handover, the protocol, threat model, adoption plan and release checklist are
sufficient to integrate without it.
