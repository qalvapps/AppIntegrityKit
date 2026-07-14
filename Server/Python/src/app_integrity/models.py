from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class AppAttestEnvironment(StrEnum):
    DEVELOPMENT = "development"
    PRODUCTION = "production"


@dataclass(frozen=True, slots=True)
class AllowedApplication:
    """Security configuration owned by a product backend, never by its client."""

    application_id: str
    app_id: str
    environments: frozenset[AppAttestEnvironment]
    allowed_scopes: frozenset[str]
    allowed_validation_categories: frozenset[int]


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

