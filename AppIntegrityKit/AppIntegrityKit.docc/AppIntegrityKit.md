# ``AppIntegrityKit``

## Overview

AppIntegrityKit registers an Apple App Attest key with a first-party product
backend and exchanges signed, challenge-bound assertions for short-lived scoped
sessions. It does not embed backend credentials and does not decide whether a
user has a paid entitlement.

For an unsupported app extension, use a separately configured
``KeychainAppIntegrityDelegatedGrantStore``. The containing app may merge
server-issued one-use grants into that shared-Keychain pool, while the extension
reserves one grant against an exact submission ID and request-body digest. This
does not make the extension an App Attest client and does not alter the normal
session lifecycle.

Use ``AppIntegrity/shared`` for the normal single-backend integration, or create
an isolated ``AppIntegrity`` instance when injecting test doubles or serving
multiple product backends.

The backend must implement the matching protocol and every Apple verification
step. A session must never be issued merely because the client supplied an
attestation-shaped payload.

Integrity failures are machine-readable, not user-facing. Map
``AppIntegrityError/code``, ``AppIntegrityError/httpStatusCode`` and
``AppIntegrityError/backendCode`` into each consuming product's own localized
copy. The package deliberately does not conform its errors to `LocalizedError`.
