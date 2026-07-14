# Security policy

AppIntegrityKit is a security-sensitive private product. Report suspected
vulnerabilities privately to the repository owners. Do not open a public issue
that includes exploit details, attestation objects, assertions, receipts,
session tokens, backend configuration, or customer data.

No version is production-supported until a release explicitly says so. The
current `0.1.0-dev` includes a cryptographic verifier but remains pre-production
until independent review, atomic product storage, physical-device development
validation, and TestFlight production validation are complete.

Security fixes take precedence over API compatibility before 1.0. After 1.0,
an urgent security fix may still make a breaking change when preserving the old
behaviour would expose consumers.
