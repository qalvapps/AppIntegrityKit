# ``AppIntegrityKit``

## Overview

AppIntegrityKit registers an Apple App Attest key with a first-party product
backend and exchanges signed, challenge-bound assertions for short-lived scoped
sessions. It does not embed backend credentials and does not decide whether a
user has a paid entitlement.

Use ``AppIntegrity/shared`` for the normal single-backend integration, or create
an isolated ``AppIntegrity`` instance when injecting test doubles or serving
multiple product backends.

The backend must implement the matching protocol and every Apple verification
step. A session must never be issued merely because the client supplied an
attestation-shaped payload.
