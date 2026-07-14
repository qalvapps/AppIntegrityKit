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

- [ ] Full Apple attestation-object validation is implemented and independently
  reviewed against Apple’s validation guide.
- [ ] Assertion signature, RP ID, extension, counter, and challenge validation
  are complete.
- [ ] GoodTides persistence performs atomic challenge consumption and counter
  advancement.
- [ ] A physical iPhone development-environment registration/session succeeds.
- [ ] Reinstall, pending-key retry, unknown-key recovery, replay, expiry, and
  concurrent renewal cases are verified.
- [ ] A TestFlight production-environment registration/session succeeds.
- [ ] TideTables contains no reusable GoodTides or provider credential.

## Before 1.0.0

- [ ] TideTables and Recipeez both consume tagged releases.
- [ ] Recipeez release builds no longer contain worker shared secrets.
- [ ] Share Extension first-use and scoped-session behaviour is verified.
- [ ] Revocation, rate limits, entitlement verification, privacy logging, and
  operational alerts are exercised in production-like environments.
- [ ] External or independent security review findings are resolved.

