from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from app_integrity import (
    AppAttestEnvironment,
    DelegatedGrantConsumption,
    DelegatedGrantConsumptionRequest,
    DelegatedGrantConsumptionStatus,
    DelegatedGrantError,
    DelegatedGrantErrorCode,
    DelegatedGrantPolicy,
    DelegatedGrantRecord,
    DelegatedGrantService,
    VerifiedSessionAuthority,
    b64url_decode,
    b64url_encode,
)


ROOT = Path(__file__).resolve().parents[3]
VECTOR_PATH = ROOT / "Protocol" / "test-vectors" / "delegated-submission-grants-v1.json"


def load_vector() -> dict[str, object]:
    return json.loads(VECTOR_PATH.read_text(encoding="utf-8"))


def parse_date(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class SequenceTokenGenerator:
    def __init__(self, values: list[bytes]) -> None:
        self._values = list(values)

    def generate(self, byte_count: int) -> bytes:
        assert byte_count == 32
        return self._values.pop(0)


@dataclass(slots=True)
class StoredGrant:
    record: DelegatedGrantRecord
    revoked: bool = False
    use_count: int = 0
    submission_id: str | None = None
    request_digest: bytes | None = None
    acceptance_id: str | None = None


class AtomicMemoryGrantStore:
    def __init__(self) -> None:
        self.records: dict[bytes, StoredGrant] = {}
        self.active_keys: set[tuple[str, AppAttestEnvironment, bytes]] = set()
        self.issue_quota_exhausted = False
        self.unavailable = False
        self._lock = asyncio.Lock()

    async def issue(self, records: tuple[DelegatedGrantRecord, ...]) -> None:
        async with self._lock:
            if self.unavailable:
                raise DelegatedGrantError(
                    DelegatedGrantErrorCode.GRANT_STORE_UNAVAILABLE
                )
            if self.issue_quota_exhausted:
                raise DelegatedGrantError(DelegatedGrantErrorCode.GRANT_EXHAUSTED)
            for record in records:
                if record.token_hash in self.records:
                    raise DelegatedGrantError(DelegatedGrantErrorCode.INVALID_GRANT)
            for record in records:
                self.records[record.token_hash] = StoredGrant(record=record)
                self.active_keys.add(
                    (
                        record.application_id,
                        record.environment,
                        record.key_id_hash,
                    )
                )

    async def consume(
        self,
        request: DelegatedGrantConsumptionRequest,
    ) -> DelegatedGrantConsumption:
        async with self._lock:
            if self.unavailable:
                raise DelegatedGrantError(
                    DelegatedGrantErrorCode.GRANT_STORE_UNAVAILABLE
                )
            state = self.records.get(request.token_hash)
            if state is None:
                raise DelegatedGrantError(DelegatedGrantErrorCode.INVALID_GRANT)
            record = state.record
            if (
                record.application_id != request.application_id
                or record.environment != request.environment
                or record.operation != request.operation
            ):
                raise DelegatedGrantError(
                    DelegatedGrantErrorCode.GRANT_BINDING_MISMATCH
                )
            key_binding = (
                record.application_id,
                record.environment,
                record.key_id_hash,
            )
            if key_binding not in self.active_keys:
                raise DelegatedGrantError(DelegatedGrantErrorCode.INSTALLATION_REVOKED)
            if state.revoked:
                raise DelegatedGrantError(DelegatedGrantErrorCode.GRANT_REVOKED)
            if request.now >= record.expires_at:
                raise DelegatedGrantError(DelegatedGrantErrorCode.GRANT_EXPIRED)
            if state.submission_id is not None:
                if (
                    state.submission_id != request.submission_id
                    or state.request_digest != request.request_digest
                ):
                    raise DelegatedGrantError(
                        DelegatedGrantErrorCode.GRANT_BINDING_MISMATCH
                    )
                assert state.acceptance_id is not None
                return DelegatedGrantConsumption(
                    status=DelegatedGrantConsumptionStatus.REPLAYED,
                    acceptance_id=state.acceptance_id,
                )
            if state.use_count >= record.use_limit:
                raise DelegatedGrantError(DelegatedGrantErrorCode.GRANT_EXHAUSTED)

            state.use_count += 1
            state.submission_id = request.submission_id
            state.request_digest = request.request_digest
            state.acceptance_id = request.acceptance_id
            return DelegatedGrantConsumption(
                status=DelegatedGrantConsumptionStatus.ACCEPTED,
                acceptance_id=request.acceptance_id,
            )


async def issue_fixture() -> tuple[
    dict[str, object],
    DelegatedGrantService,
    AtomicMemoryGrantStore,
]:
    vector = load_vector()
    authority_data = vector["authority"]
    policy_data = vector["policy"]
    assert isinstance(authority_data, dict)
    assert isinstance(policy_data, dict)
    token_material = vector["tokenMaterial"]
    assert isinstance(token_material, list)
    store = AtomicMemoryGrantStore()
    service = DelegatedGrantService(
        store=store,
        token_generator=SequenceTokenGenerator(
            [b64url_decode(value) for value in token_material]
        ),
    )
    authority = VerifiedSessionAuthority(
        application_id=authority_data["applicationID"],
        environment=AppAttestEnvironment(authority_data["environment"]),
        key_id_hash=b64url_decode(authority_data["keyIDHash"]),
        session_expires_at=parse_date(authority_data["sessionExpiresAt"]),
    )
    policy = DelegatedGrantPolicy(
        operation=policy_data["operation"],
        pool_size=policy_data["poolSize"],
        lifetime=timedelta(seconds=policy_data["lifetimeSeconds"]),
        use_limit=policy_data["useLimit"],
    )
    issued = await service.issue(
        authority=authority,
        policy=policy,
        now=parse_date(vector["issuedAt"]),
    )

    assert [grant.token for grant in issued] == token_material
    assert [b64url_encode(token_hash) for token_hash in store.records] == vector[
        "expectedTokenHashes"
    ]
    assert all(
        grant.expires_at == parse_date(vector["expectedExpiresAt"]) for grant in issued
    )
    assert all(grant.token not in repr(grant) for grant in issued)
    assert all(
        authority_data["keyIDHash"] not in repr(state.record)
        for state in store.records.values()
    )
    return vector, service, store


async def consume_fixture(
    vector: dict[str, object],
    service: DelegatedGrantService,
    **overrides: object,
) -> DelegatedGrantConsumption:
    data = vector["consumption"]
    assert isinstance(data, dict)
    values: dict[str, object] = {
        "token": data["token"],
        "application_id": data["applicationID"],
        "environment": AppAttestEnvironment(data["environment"]),
        "operation": data["operation"],
        "submission_id": data["submissionID"],
        "exact_request_body": b64url_decode(data["requestBody"]),
        "acceptance_id": data["acceptanceID"],
        "now": parse_date(data["consumeAt"]),
    }
    values.update(overrides)
    return await service.consume(**values)


def test_shared_vector_issue_consume_and_exact_replay() -> None:
    async def scenario() -> None:
        vector, service, _ = await issue_fixture()
        data = vector["consumption"]
        assert isinstance(data, dict)
        body = b64url_decode(data["requestBody"])
        changed_body = b64url_decode(data["changedRequestBody"])
        assert b64url_encode(hashlib.sha256(body).digest()) == data["requestDigest"]
        assert (
            b64url_encode(hashlib.sha256(changed_body).digest())
            == data["changedRequestDigest"]
        )

        accepted = await consume_fixture(vector, service)
        replayed = await consume_fixture(
            vector,
            service,
            acceptance_id="ignored-on-exact-replay",
        )
        assert accepted.status is DelegatedGrantConsumptionStatus.ACCEPTED
        assert replayed.status is DelegatedGrantConsumptionStatus.REPLAYED
        assert replayed.acceptance_id == accepted.acceptance_id

        with pytest.raises(DelegatedGrantError) as changed:
            await consume_fixture(
                vector,
                service,
                exact_request_body=changed_body,
            )
        assert changed.value.code is DelegatedGrantErrorCode.GRANT_BINDING_MISMATCH

    asyncio.run(scenario())


def test_negative_vector_bindings_expiry_revocation_key_and_exhaustion() -> None:
    async def scenario() -> None:
        vector, service, store = await issue_fixture()
        data = vector["consumption"]
        authority = vector["authority"]
        assert isinstance(data, dict)
        assert isinstance(authority, dict)

        for overrides in (
            {"application_id": "wrong-ios"},
            {"environment": AppAttestEnvironment.PRODUCTION},
            {"operation": "wrong:operation"},
        ):
            with pytest.raises(DelegatedGrantError) as caught:
                await consume_fixture(vector, service, **overrides)
            assert caught.value.code is DelegatedGrantErrorCode.GRANT_BINDING_MISMATCH

        with pytest.raises(DelegatedGrantError) as expired:
            await consume_fixture(
                vector,
                service,
                now=parse_date(vector["expectedExpiresAt"]),
            )
        assert expired.value.code is DelegatedGrantErrorCode.GRANT_EXPIRED

        token_hash = hashlib.sha256(b64url_decode(data["token"])).digest()
        store.records[token_hash].revoked = True
        with pytest.raises(DelegatedGrantError) as revoked:
            await consume_fixture(vector, service)
        assert revoked.value.code is DelegatedGrantErrorCode.GRANT_REVOKED
        store.records[token_hash].revoked = False

        key_binding = (
            authority["applicationID"],
            AppAttestEnvironment(authority["environment"]),
            b64url_decode(authority["keyIDHash"]),
        )
        store.active_keys.remove(key_binding)
        with pytest.raises(DelegatedGrantError) as replaced_key:
            await consume_fixture(vector, service)
        assert replaced_key.value.code is DelegatedGrantErrorCode.INSTALLATION_REVOKED
        store.active_keys.add(key_binding)

        store.records[token_hash].use_count = 1
        with pytest.raises(DelegatedGrantError) as exhausted:
            await consume_fixture(vector, service)
        assert exhausted.value.code is DelegatedGrantErrorCode.GRANT_EXHAUSTED

    asyncio.run(scenario())


def test_store_outage_and_issuance_quota_fail_closed() -> None:
    async def scenario() -> None:
        vector, service, store = await issue_fixture()
        store.unavailable = True
        with pytest.raises(DelegatedGrantError) as unavailable:
            await consume_fixture(vector, service)
        assert unavailable.value.code is DelegatedGrantErrorCode.GRANT_STORE_UNAVAILABLE

        vector = load_vector()
        authority_data = vector["authority"]
        policy_data = vector["policy"]
        assert isinstance(authority_data, dict)
        assert isinstance(policy_data, dict)
        token_material = vector["tokenMaterial"]
        assert isinstance(token_material, list)
        quota_store = AtomicMemoryGrantStore()
        quota_store.issue_quota_exhausted = True
        quota_service = DelegatedGrantService(
            store=quota_store,
            token_generator=SequenceTokenGenerator(
                [b64url_decode(value) for value in token_material]
            ),
        )
        authority = VerifiedSessionAuthority(
            application_id=authority_data["applicationID"],
            environment=AppAttestEnvironment(authority_data["environment"]),
            key_id_hash=b64url_decode(authority_data["keyIDHash"]),
            session_expires_at=parse_date(authority_data["sessionExpiresAt"]),
        )
        policy = DelegatedGrantPolicy(
            operation=policy_data["operation"],
            pool_size=policy_data["poolSize"],
            lifetime=timedelta(seconds=policy_data["lifetimeSeconds"]),
        )
        with pytest.raises(DelegatedGrantError) as quota:
            await quota_service.issue(
                authority=authority,
                policy=policy,
                now=parse_date(vector["issuedAt"]),
            )
        assert quota.value.code is DelegatedGrantErrorCode.GRANT_EXHAUSTED

    asyncio.run(scenario())


def test_concurrent_same_request_consumes_once_and_recovers_acceptance() -> None:
    async def scenario() -> None:
        vector, service, _ = await issue_fixture()
        first, second = await asyncio.gather(
            consume_fixture(vector, service, acceptance_id="first-acceptance"),
            consume_fixture(vector, service, acceptance_id="second-acceptance"),
        )
        assert {first.status, second.status} == {
            DelegatedGrantConsumptionStatus.ACCEPTED,
            DelegatedGrantConsumptionStatus.REPLAYED,
        }
        assert first.acceptance_id == second.acceptance_id

    asyncio.run(scenario())


def test_vector_declares_every_required_case() -> None:
    vector = load_vector()
    cases = vector["cases"]
    assert isinstance(cases, list)
    names = {case["name"] for case in cases}
    assert names == {
        "first-consume",
        "same-request-replay",
        "changed-request-replay",
        "expired",
        "revoked-grant",
        "wrong-application",
        "wrong-environment",
        "wrong-operation",
        "replaced-installation-key",
        "exhausted",
        "store-unavailable",
        "issuance-quota-exhausted",
    }
