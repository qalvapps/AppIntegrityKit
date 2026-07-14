from __future__ import annotations

from dataclasses import dataclass
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
    validation_category: int
    bundle_version: str


@dataclass(frozen=True, slots=True)
class VerifiedAssertion:
    counter: int
    validation_category: int
    bundle_version: str
