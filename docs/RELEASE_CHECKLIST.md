# AppIntegrityKit Release Checklist

## Every release

- [ ] `scripts/verify.sh` passes from a clean checkout.
- [ ] XCFramework packaging and DocC generation pass.
- [ ] Public Swift API compatibility is reviewed.
- [ ] Wire-protocol compatibility is explicitly reviewed.
- [ ] New or changed signed bytes have matching Swift/Python test vectors.
- [ ] No test verifier, bypass, secret, product credential, or customer datum is
  present in release artifacts.
- [ ] Changelog and version are updated together.
- [ ] Dependency versions and Apple validation guidance are rechecked.

## Before 0.1.0

- [x] Full Apple attestation-object validation is implemented against Apple’s
  validation guide and official sample.
- [ ] The verifier receives independent security review.
- [x] Assertion signature, RP ID, extension, counter, and exact client-data
  validation are implemented.
- [x] GoodTides persistence performs atomic challenge consumption and counter
  advancement.
- [x] A physical iPhone development-environment registration/session succeeds.
- [x] Equivalent concurrent first-session and renewal requests are coalesced,
  while non-equivalent requests run in sequence.
- [ ] Reinstall, pending-key retry, unknown-key recovery, replay, and expiry are
  verified on physical/TestFlight builds.
- [ ] A TestFlight production-environment registration/session succeeds.
- [x] TideTables contains no reusable GoodTides or provider credential.

## Before 1.0.0

- [ ] TideTables and Recipeez both consume tagged releases.
- [ ] Recipeez release builds no longer contain worker shared secrets.
- [ ] Share Extension first-use and scoped-session behaviour is verified.
- [ ] Revocation, rate limits, entitlement verification, privacy logging, and
  operational alerts are exercised in production-like environments.
- [ ] External or independent security review findings are resolved.
