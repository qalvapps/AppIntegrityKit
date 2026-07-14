"""AppIntegrityKit server verification foundations."""

from .apple import (
    AppAttestVerificationError,
    AppleAssertionObjectVerifier,
    AppleAttestationObjectVerifier,
)
from .canonical import (
    ProtocolValidationError,
    b64url_decode,
    b64url_encode,
    encode_session_client_data,
    parse_session_client_data,
    sha256_b64url,
    validate_session_binding,
)
from .models import (
    AllowedApplication,
    AppAttestEnvironment,
    AppAttestPlatform,
    SessionClientData,
    VerifiedAssertion,
    VerifiedAttestation,
)

__all__ = [
    "AllowedApplication",
    "AppAttestPlatform",
    "AppAttestEnvironment",
    "AppAttestVerificationError",
    "AppleAssertionObjectVerifier",
    "AppleAttestationObjectVerifier",
    "ProtocolValidationError",
    "SessionClientData",
    "VerifiedAssertion",
    "VerifiedAttestation",
    "b64url_decode",
    "b64url_encode",
    "encode_session_client_data",
    "parse_session_client_data",
    "sha256_b64url",
    "validate_session_binding",
]
