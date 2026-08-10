from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum


class AppAttestEnvironment(StrEnum):
    DEVELOPMENT = "development"
    PRODUCTION = "production"


class AppAttestPlatform(StrEnum):
    IOS = "ios"
    MACOS = "macos"


@dataclass(frozen=True, slots=True)
class AllowedApplication:
    """Security configuration owned by a product backend, never by its client."""

    application_id: str
    app_id: str
    platform: AppAttestPlatform
    environments: frozenset[AppAttestEnvironment]
    allowed_scopes: frozenset[str]
    allowed_validation_categories: frozenset[int]
    allowed_bundle_versions: frozenset[str]
    allows_legacy_app_attest: bool = False

    def __post_init__(self) -> None:
        if (
            not isinstance(self.application_id, str)
            or not self.application_id
            or not self.application_id.isascii()
        ):
            raise ValueError("application_id must be non-empty ASCII")
        if (
            not isinstance(self.app_id, str)
            or not self.app_id
            or not self.app_id.isascii()
        ):
            raise ValueError("app_id must be non-empty ASCII")
        if not isinstance(self.platform, AppAttestPlatform):
            raise ValueError("platform must be an AppAttestPlatform")
        if not isinstance(self.environments, frozenset):
            raise ValueError("environments must be a frozenset")
        if not all(
            isinstance(environment, AppAttestEnvironment)
            for environment in self.environments
        ):
            raise ValueError("environments contains an invalid value")
        if not self.environments:
            raise ValueError("at least one App Attest environment is required")
        if not isinstance(self.allowed_scopes, frozenset):
            raise ValueError("allowed_scopes must be a frozenset")
        if any(
            not isinstance(scope, str)
            or not scope
            or len(scope) > 128
            or not scope.isascii()
            for scope in self.allowed_scopes
        ):
            raise ValueError("allowed_scopes contains an invalid value")
        if not isinstance(self.allowed_validation_categories, frozenset):
            raise ValueError("allowed_validation_categories must be a frozenset")
        if not self.allowed_validation_categories:
            raise ValueError("at least one validation category is required")
        if any(
            type(category) is not int
            or category < 1
            or category > 10
            or category in {7, 8, 9}
            for category in self.allowed_validation_categories
        ):
            raise ValueError("allowed_validation_categories contains an unsafe value")
        if not isinstance(self.allowed_bundle_versions, frozenset):
            raise ValueError("allowed_bundle_versions must be a frozenset")
        if not self.allowed_bundle_versions or any(
            not isinstance(version, str)
            or not version
            or len(version) > 128
            or not version.isascii()
            for version in self.allowed_bundle_versions
        ):
            raise ValueError("allowed_bundle_versions is invalid")
        if type(self.allows_legacy_app_attest) is not bool:
            raise ValueError("allows_legacy_app_attest must be a bool")


@dataclass(frozen=True, slots=True)
class SessionClientData:
    protocol_version: int
    application_id: str
    challenge_id: str
    challenge: str
    key_id: str
    requested_scopes: tuple[str, ...]
    entitlement_evidence_sha256: str | None


@dataclass(frozen=True, slots=True)
class VerifiedAttestation:
    public_key_x963: bytes
    receipt: bytes
    environment: AppAttestEnvironment
    validation_category: int | None
    bundle_version: str | None


@dataclass(frozen=True, slots=True)
class VerifiedAssertion:
    counter: int
    validation_category: int | None
    bundle_version: str | None


@dataclass(frozen=True, slots=True, repr=False)
class VerifiedSessionAuthority:
    """Principal produced only after a product backend verifies a live session."""

    application_id: str
    environment: AppAttestEnvironment
    key_id_hash: bytes
    session_expires_at: datetime

    def __post_init__(self) -> None:
        _validate_ascii(self.application_id, "application_id", 128)
        if not isinstance(self.environment, AppAttestEnvironment):
            raise ValueError("environment must be an AppAttestEnvironment")
        if not isinstance(self.key_id_hash, bytes) or len(self.key_id_hash) != 32:
            raise ValueError("key_id_hash must be a SHA-256 digest")
        _validate_aware_datetime(self.session_expires_at, "session_expires_at")


@dataclass(frozen=True, slots=True)
class DelegatedGrantPolicy:
    """Server-owned pool policy; no value in this model comes from authority."""

    operation: str
    pool_size: int
    lifetime: timedelta
    use_limit: int = 1

    def __post_init__(self) -> None:
        _validate_ascii(self.operation, "operation", 128)
        if type(self.pool_size) is not int or not 1 <= self.pool_size <= 64:
            raise ValueError("pool_size must be between 1 and 64")
        if not isinstance(self.lifetime, timedelta):
            raise ValueError("lifetime must be a timedelta")
        if not timedelta(0) < self.lifetime <= timedelta(hours=24):
            raise ValueError("lifetime must be positive and no greater than 24 hours")
        if self.use_limit != 1:
            raise ValueError("delegated submission grants have a one-use limit")


@dataclass(frozen=True, slots=True, repr=False)
class DelegatedGrantRecord:
    token_hash: bytes
    application_id: str
    environment: AppAttestEnvironment
    key_id_hash: bytes
    operation: str
    issued_at: datetime
    expires_at: datetime
    use_limit: int

    def __post_init__(self) -> None:
        if not isinstance(self.token_hash, bytes) or len(self.token_hash) != 32:
            raise ValueError("token_hash must be a SHA-256 digest")
        _validate_ascii(self.application_id, "application_id", 128)
        if not isinstance(self.environment, AppAttestEnvironment):
            raise ValueError("environment must be an AppAttestEnvironment")
        if not isinstance(self.key_id_hash, bytes) or len(self.key_id_hash) != 32:
            raise ValueError("key_id_hash must be a SHA-256 digest")
        _validate_ascii(self.operation, "operation", 128)
        _validate_aware_datetime(self.issued_at, "issued_at")
        _validate_aware_datetime(self.expires_at, "expires_at")
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
        if self.use_limit != 1:
            raise ValueError("delegated submission grants have a one-use limit")


@dataclass(frozen=True, slots=True, repr=False)
class IssuedDelegatedGrant:
    token: str
    expires_at: datetime
    use_limit: int


@dataclass(frozen=True, slots=True, repr=False)
class DelegatedGrantConsumptionRequest:
    token_hash: bytes
    application_id: str
    environment: AppAttestEnvironment
    operation: str
    submission_id: str
    request_digest: bytes
    acceptance_id: str
    now: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.token_hash, bytes) or len(self.token_hash) != 32:
            raise ValueError("token_hash must be a SHA-256 digest")
        _validate_ascii(self.application_id, "application_id", 128)
        if not isinstance(self.environment, AppAttestEnvironment):
            raise ValueError("environment must be an AppAttestEnvironment")
        _validate_ascii(self.operation, "operation", 128)
        _validate_ascii(self.submission_id, "submission_id", 256)
        if not isinstance(self.request_digest, bytes) or len(self.request_digest) != 32:
            raise ValueError("request_digest must be a SHA-256 digest")
        _validate_ascii(self.acceptance_id, "acceptance_id", 256)
        _validate_aware_datetime(self.now, "now")


class DelegatedGrantConsumptionStatus(StrEnum):
    ACCEPTED = "accepted"
    REPLAYED = "replayed"


@dataclass(frozen=True, slots=True)
class DelegatedGrantConsumption:
    status: DelegatedGrantConsumptionStatus
    acceptance_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.status, DelegatedGrantConsumptionStatus):
            raise ValueError("status must be a DelegatedGrantConsumptionStatus")
        _validate_ascii(self.acceptance_id, "acceptance_id", 256)


def _validate_ascii(value: object, field: str, maximum: int) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or not value.isascii()
    ):
        raise ValueError(f"{field} must be bounded non-empty ASCII")


def _validate_aware_datetime(value: object, field: str) -> None:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ValueError(f"{field} must be timezone-aware")
