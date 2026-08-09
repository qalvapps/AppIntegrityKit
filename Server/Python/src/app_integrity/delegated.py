from __future__ import annotations

import hashlib
from datetime import datetime
from enum import StrEnum

from .canonical import ProtocolValidationError, b64url_decode, b64url_encode
from .models import (
    AppAttestEnvironment,
    DelegatedGrantConsumption,
    DelegatedGrantConsumptionRequest,
    DelegatedGrantPolicy,
    DelegatedGrantRecord,
    IssuedDelegatedGrant,
    VerifiedSessionAuthority,
)
from .ports import DelegatedGrantStore, OpaqueTokenGenerator


class DelegatedGrantErrorCode(StrEnum):
    INVALID_GRANT = "invalid_grant"
    GRANT_BINDING_MISMATCH = "grant_binding_mismatch"
    GRANT_EXPIRED = "grant_expired"
    GRANT_EXHAUSTED = "grant_exhausted"
    GRANT_REVOKED = "grant_revoked"
    INSTALLATION_REVOKED = "installation_revoked"
    GRANT_STORE_UNAVAILABLE = "grant_store_unavailable"
    ISSUANCE_UNAUTHORIZED = "issuance_unauthorized"


class DelegatedGrantError(RuntimeError):
    """Fail-closed error with a safe code and no integrity material."""

    def __init__(self, code: DelegatedGrantErrorCode) -> None:
        self.code = code
        super().__init__(code.value)


class DelegatedGrantService:
    """Framework-neutral issuance and exact-request consumption boundary."""

    def __init__(
        self,
        *,
        store: DelegatedGrantStore,
        token_generator: OpaqueTokenGenerator,
    ) -> None:
        self._store = store
        self._token_generator = token_generator

    async def issue(
        self,
        *,
        authority: VerifiedSessionAuthority,
        policy: DelegatedGrantPolicy,
        now: datetime,
    ) -> tuple[IssuedDelegatedGrant, ...]:
        _require_aware(now)
        if authority.session_expires_at <= now:
            raise DelegatedGrantError(DelegatedGrantErrorCode.ISSUANCE_UNAUTHORIZED)

        expires_at = now + policy.lifetime
        issued: list[IssuedDelegatedGrant] = []
        records: list[DelegatedGrantRecord] = []
        token_hashes: set[bytes] = set()
        for _ in range(policy.pool_size):
            material = self._token_generator.generate(32)
            if not isinstance(material, bytes) or len(material) < 32:
                raise DelegatedGrantError(DelegatedGrantErrorCode.INVALID_GRANT)
            token_hash = hashlib.sha256(material).digest()
            if token_hash in token_hashes:
                raise DelegatedGrantError(DelegatedGrantErrorCode.INVALID_GRANT)
            token_hashes.add(token_hash)
            token = b64url_encode(material)
            issued.append(
                IssuedDelegatedGrant(
                    token=token,
                    expires_at=expires_at,
                    use_limit=policy.use_limit,
                )
            )
            records.append(
                DelegatedGrantRecord(
                    token_hash=token_hash,
                    application_id=authority.application_id,
                    environment=authority.environment,
                    key_id_hash=authority.key_id_hash,
                    operation=policy.operation,
                    issued_at=now,
                    expires_at=expires_at,
                    use_limit=policy.use_limit,
                )
            )

        await self._store.issue(tuple(records))
        return tuple(issued)

    async def consume(
        self,
        *,
        token: str,
        application_id: str,
        environment: AppAttestEnvironment,
        operation: str,
        submission_id: str,
        exact_request_body: bytes,
        acceptance_id: str,
        now: datetime,
    ) -> DelegatedGrantConsumption:
        try:
            material = b64url_decode(token, field="delegated grant")
        except ProtocolValidationError as error:
            raise DelegatedGrantError(DelegatedGrantErrorCode.INVALID_GRANT) from error
        if len(material) < 32:
            raise DelegatedGrantError(DelegatedGrantErrorCode.INVALID_GRANT)
        if not isinstance(exact_request_body, bytes):
            raise ValueError("exact_request_body must be bytes")

        request = DelegatedGrantConsumptionRequest(
            token_hash=hashlib.sha256(material).digest(),
            application_id=application_id,
            environment=environment,
            operation=operation,
            submission_id=submission_id,
            request_digest=hashlib.sha256(exact_request_body).digest(),
            acceptance_id=acceptance_id,
            now=now,
        )
        return await self._store.consume(request)


def _require_aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
