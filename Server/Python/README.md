# app-integrity-verifier

Framework-neutral Apple App Attest verification for AppIntegrityKit product
backends.

The package provides strict protocol parsing, binding validation, server-owned
application policy, Apple-root-pinned attestation verification, assertion
signature and counter verification, and persistence ports. There is no
permissive or test-mode production path.

The package also provides the additive delegated-submission-grant service and
store port. A product backend may construct `VerifiedSessionAuthority` only
after validating its existing short-lived session, supplies its own pool
policy, and implements atomic consumption with active installation-key and
revocation checks. Product endpoint, quota, and cost policy remain outside the
package.

The attestation verifier validates strict CBOR, the X.509 path and validity
period, Apple leaf purpose, nonce extension, P-256 key and Apple key ID, RP ID,
counter zero, AAGUID/environment, COSE key, macOS ACL policy where applicable,
launch validation category, and bundle version. The assertion verifier binds
the exact client-data bytes, Apple key ID, signature, RP ID, increasing counter,
validation category, and bundle version.

```python
import hashlib

from app_integrity import (
    AllowedApplication,
    AppAttestEnvironment,
    AppAttestPlatform,
    AppleAssertionObjectVerifier,
    AppleAttestationObjectVerifier,
)

application = AllowedApplication(
    application_id="goodtides-ios",
    app_id="TEAMID.com.paulcalver.TideTables",
    platform=AppAttestPlatform.IOS,
    environments=frozenset({AppAttestEnvironment.DEVELOPMENT}),
    allowed_scopes=frozenset({"tides:forecast"}),
    allowed_validation_categories=frozenset({3}),
    allowed_bundle_versions=frozenset({"1"}),
)

# The challenge store first consumes and returns the original random challenge.
# This digest must exactly match the bytes passed to DCAppAttestService.attestKey.
# The production verifier requires the protocol's 32-byte SHA-256 value by default.
client_data_hash = hashlib.sha256(challenge).digest()
attestation = AppleAttestationObjectVerifier().verify(
    attestation_object=attestation_object,
    key_id=key_id,
    client_data_hash=client_data_hash,
    application=application,
)
```

Use validation category `3` for development-signed builds, `2` for TestFlight,
and `4` for App Store builds. Keep development and production key records
separate. Add a release's exact `CFBundleVersion` to server policy before that
build reaches users.

Product backends will supply:

- atomic challenge/key/session stores;
- entitlement and scope policy;
- rate limits and revocation;
- FastAPI or other framework adapters.
- atomic delegated-grant and active-installation storage when that optional
  companion contract is enabled.

The returned Apple receipt remains an opaque artifact for the product backend
to store and independently submit to Apple's fraud-assessment service. This
package does not treat the receipt as authorization.

Run tests:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
pytest
```
