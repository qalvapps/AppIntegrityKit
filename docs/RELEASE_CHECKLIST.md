# AppIntegrityKit Release Checklist

- [ ] Public failures expose only stable machine-readable keys and safe status
  metadata. AppIntegrityKit does not conform them to `LocalizedError`, contain
  end-user sentences, or own consumer-app localization.

## Every release

- [ ] `scripts/verify.sh` passes from a clean checkout.
- [ ] XCFramework packaging and DocC generation pass.
- [ ] Public Swift API compatibility is reviewed.
- [ ] Wire-protocol compatibility is explicitly reviewed.
- [ ] Delegated-store compatibility is explicitly reviewed: existing deployed
  pool records remain readable, normal-session consumers are unaffected, and a
  multi-process consumer cannot silently select the single-process adapter for
  production delegated authority. The coordinated adapter's non-secret
  capability version is asserted by consumer configuration and release preflight.
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
- [x] Pre-iOS 27 legacy and iOS 27 extended authenticator grammars have positive
  and malformed-suffix regression coverage; legacy acceptance is application
  policy and requires a documented compensating authorization control.
- [x] GoodTides persistence performs atomic challenge consumption and counter
  advancement.
- [x] A physical iPhone development-environment registration/session succeeds.
- [x] Equivalent concurrent first-session and renewal requests are coalesced,
  while non-equivalent requests run in sequence.
- [ ] Reinstall, pending-key retry, unknown-key recovery, replay, and expiry are
  verified on physical/TestFlight builds.
- [x] Unknown server registration recovery is bounded to one replacement, while
  revoked keys and generic verification failures remain fail-closed.
- [x] A TestFlight production-environment registration and two successive
  assertion-bound sessions succeed without a second registration.
- [x] TideTables contains no reusable GoodTides or provider credential.

## Before 1.0.0

- [ ] The coordinated delegated-grant store passes independent-instance and
  process-race tests for merge, reserve, remove, expiry pruning, bounded lock
  failure, and termination immediately before and after Keychain commit. Every
  uncertain mutation leaves a complete pre- or post-operation record, and
  reread recovery preserves every committed reservation without selecting a
  second grant.
- [ ] Raw delegated authority remains Keychain-only; App Group coordination
  storage contains no grant, token hash, reservation, submission ID, body
  digest, session, installation identifier, or product payload.
- [ ] A reference product canary deliberately removes only its cached normal
  session after provisioning. Server evidence proves delegated acceptances;
  durable device evidence separately proves no-authority captures made no
  request, because the server cannot record an absent request.
- [ ] Target reduction without later replenishment is exercised at first-use
  consumption, while exact replay of prior acceptance remains available.
- [ ] Explicit old-installation revocation rejects its retained test grant.
  Reinstall/key replacement is tested separately and is not reported as the
  cause of revocation; residual authority is bounded by configured expiry.

- [ ] TideTables and Recipeez both consume tagged releases.
- [ ] Recipeez release builds no longer contain worker shared secrets.
- [ ] Share Extension first-use and scoped-session behaviour is verified.
- [ ] Revocation, rate limits, entitlement verification, privacy logging, and
  operational alerts are exercised in production-like environments.
- [ ] External or independent security review findings are resolved.
