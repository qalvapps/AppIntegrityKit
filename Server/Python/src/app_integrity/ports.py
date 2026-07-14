from __future__ import annotations

from datetime import datetime
from typing import Protocol

from .models import (
    AllowedApplication,
    SessionClientData,
    VerifiedAssertion,
    VerifiedAttestation,
)


class AttestationObjectVerifier(Protocol):
    """Production implementations must perform every Apple validation step."""

    def verify(
        self,
        *,
        attestation_object: bytes,
        key_id: str,
        challenge: bytes,
        application: AllowedApplication,
    ) -> VerifiedAttestation: ...


class AssertionObjectVerifier(Protocol):
    def verify(
        self,
        *,
        assertion_object: bytes,
        exact_client_data: bytes,
        client_data: SessionClientData,
        public_key_x963: bytes,
        previous_counter: int,
        application: AllowedApplication,
    ) -> VerifiedAssertion: ...


class ChallengeStore(Protocol):
    """Consumption must atomically verify purpose, expiry, binding, and unused state."""

    async def create(
        self,
        *,
        application_id: str,
        purpose: str,
        challenge_hash: bytes,
        expires_at: datetime,
    ) -> str: ...

    async def consume(
        self,
        *,
        challenge_id: str,
        application_id: str,
        purpose: str,
        challenge_hash: bytes,
        now: datetime,
    ) -> None: ...


class IntegrityKeyStore(Protocol):
    """Counter comparison and update must be one transaction."""

    async def register_key(
        self,
        *,
        application_id: str,
        key_id_hash: bytes,
        attestation: VerifiedAttestation,
    ) -> None: ...

    async def verify_and_advance_counter(
        self,
        *,
        application_id: str,
        key_id_hash: bytes,
        assertion: VerifiedAssertion,
    ) -> None: ...


class SessionIssuer(Protocol):
    async def issue(
        self,
        *,
        application_id: str,
        key_id_hash: bytes,
        scopes: frozenset[str],
        expires_at: datetime,
    ) -> str: ...

