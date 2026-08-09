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
from .delegated import (
    DelegatedGrantError,
    DelegatedGrantErrorCode,
    DelegatedGrantService,
)
from .models import (
    AllowedApplication,
    AppAttestEnvironment,
    AppAttestPlatform,
    DelegatedGrantConsumption,
    DelegatedGrantConsumptionRequest,
    DelegatedGrantConsumptionStatus,
    DelegatedGrantPolicy,
    DelegatedGrantRecord,
    IssuedDelegatedGrant,
    SessionClientData,
    VerifiedAssertion,
    VerifiedAttestation,
    VerifiedSessionAuthority,
)

__all__ = [
    "AllowedApplication",
    "AppAttestPlatform",
    "AppAttestEnvironment",
    "AppAttestVerificationError",
    "AppleAssertionObjectVerifier",
    "AppleAttestationObjectVerifier",
    "DelegatedGrantConsumption",
    "DelegatedGrantConsumptionRequest",
    "DelegatedGrantConsumptionStatus",
    "DelegatedGrantError",
    "DelegatedGrantErrorCode",
    "DelegatedGrantPolicy",
    "DelegatedGrantRecord",
    "DelegatedGrantService",
    "IssuedDelegatedGrant",
    "ProtocolValidationError",
    "SessionClientData",
    "VerifiedAssertion",
    "VerifiedAttestation",
    "VerifiedSessionAuthority",
    "b64url_decode",
    "b64url_encode",
    "encode_session_client_data",
    "parse_session_client_data",
    "sha256_b64url",
    "validate_session_binding",
]
