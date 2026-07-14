# app-integrity-verifier

Framework-neutral Python foundations for AppIntegrityKit product backends.

The current pre-release package provides strict protocol parsing, binding
validation, server-owned application configuration models, and cryptographic /
persistence ports. It intentionally does not contain a permissive or test-mode
attestation verifier. Until the Apple verifier milestone is complete, no
production adapter can issue a trusted session through this package.

Product backends will supply:

- Apple attestation and assertion verifier implementations;
- atomic challenge/key/session stores;
- entitlement and scope policy;
- rate limits and revocation;
- FastAPI or other framework adapters.

Run tests:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
pytest
```

