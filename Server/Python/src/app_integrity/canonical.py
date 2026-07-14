from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
from collections.abc import Collection

from .models import SessionClientData


PROTOCOL_VERSION = 1
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_REQUIRED_FIELDS = {
    "applicationID",
    "challenge",
    "challengeID",
    "keyID",
    "protocolVersion",
    "requestedScopes",
}
_OPTIONAL_FIELDS = {"entitlementEvidenceSHA256"}


class ProtocolValidationError(ValueError):
    """A fail-closed v1 wire-protocol validation failure."""


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str, *, field: str = "binary value") -> bytes:
    if (
        not isinstance(value, str)
        or not value
        or "=" in value
        or not _BASE64URL.fullmatch(value)
    ):
        raise ProtocolValidationError(f"{field} is not unpadded base64url")
    padded = value + ("=" * (-len(value) % 4))
    try:
        decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as error:
        raise ProtocolValidationError(f"{field} cannot be decoded") from error
    if not hmac.compare_digest(b64url_encode(decoded), value):
        raise ProtocolValidationError(f"{field} is not canonical base64url")
    return decoded


def sha256_b64url(data: bytes) -> str:
    return b64url_encode(hashlib.sha256(data).digest())


def parse_session_client_data(raw: bytes) -> SessionClientData:
    try:
        decoded = raw.decode("utf-8")
        payload = json.loads(decoded, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProtocolValidationError("clientData is not UTF-8 JSON") from error

    if not isinstance(payload, dict):
        raise ProtocolValidationError("clientData must be a JSON object")
    fields = set(payload)
    missing = _REQUIRED_FIELDS - fields
    unexpected = fields - _REQUIRED_FIELDS - _OPTIONAL_FIELDS
    if missing:
        raise ProtocolValidationError(
            f"clientData is missing fields: {sorted(missing)}"
        )
    if unexpected:
        raise ProtocolValidationError(
            f"clientData has unexpected fields: {sorted(unexpected)}"
        )

    version = payload["protocolVersion"]
    if type(version) is not int or version != PROTOCOL_VERSION:
        raise ProtocolValidationError("unsupported protocolVersion")

    application_id = _bounded_ascii_string(
        payload["applicationID"], "applicationID", 128
    )
    challenge_id = _bounded_ascii_string(payload["challengeID"], "challengeID", 256)
    challenge = _bounded_ascii_string(payload["challenge"], "challenge", 256)
    if len(b64url_decode(challenge, field="challenge")) < 32:
        raise ProtocolValidationError("challenge has insufficient entropy")
    key_id = _bounded_ascii_string(payload["keyID"], "keyID", 1024)

    scopes_value = payload["requestedScopes"]
    if not isinstance(scopes_value, list) or not scopes_value:
        raise ProtocolValidationError("requestedScopes must be a non-empty array")
    if not all(
        isinstance(scope, str) and 0 < len(scope) <= 128 and scope.isascii()
        for scope in scopes_value
    ):
        raise ProtocolValidationError("requestedScopes contains an invalid scope")
    if scopes_value != sorted(set(scopes_value)):
        raise ProtocolValidationError("requestedScopes must be sorted and unique")

    evidence_hash = payload.get("entitlementEvidenceSHA256")
    if evidence_hash is not None:
        evidence_hash = _bounded_ascii_string(
            evidence_hash,
            "entitlementEvidenceSHA256",
            64,
        )
        if len(b64url_decode(evidence_hash, field="entitlementEvidenceSHA256")) != 32:
            raise ProtocolValidationError("entitlementEvidenceSHA256 is not SHA-256")

    model = SessionClientData(
        protocol_version=version,
        application_id=application_id,
        challenge_id=challenge_id,
        challenge=challenge,
        key_id=key_id,
        requested_scopes=tuple(scopes_value),
        entitlement_evidence_sha256=evidence_hash,
    )
    if not hmac.compare_digest(encode_session_client_data(model), raw):
        raise ProtocolValidationError("clientData is not canonical JSON")
    return model


def encode_session_client_data(model: SessionClientData) -> bytes:
    payload: dict[str, object] = {
        "applicationID": model.application_id,
        "challenge": model.challenge,
        "challengeID": model.challenge_id,
        "keyID": model.key_id,
        "protocolVersion": model.protocol_version,
        "requestedScopes": list(model.requested_scopes),
    }
    if model.entitlement_evidence_sha256 is not None:
        payload["entitlementEvidenceSHA256"] = model.entitlement_evidence_sha256
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def validate_session_binding(
    model: SessionClientData,
    *,
    application_id: str,
    challenge_id: str,
    challenge: str,
    key_id: str,
    allowed_scopes: Collection[str],
    entitlement_evidence: bytes | None,
) -> None:
    _constant_equal(model.application_id, application_id, "applicationID")
    _constant_equal(model.challenge_id, challenge_id, "challengeID")
    _constant_equal(model.challenge, challenge, "challenge")
    _constant_equal(model.key_id, key_id, "keyID")

    if not set(model.requested_scopes).issubset(set(allowed_scopes)):
        raise ProtocolValidationError("requestedScopes exceeds server policy")

    expected_hash = (
        sha256_b64url(entitlement_evidence)
        if entitlement_evidence is not None
        else None
    )
    if model.entitlement_evidence_sha256 is None and expected_hash is None:
        return
    if model.entitlement_evidence_sha256 is None or expected_hash is None:
        raise ProtocolValidationError("entitlement evidence binding mismatch")
    _constant_equal(
        model.entitlement_evidence_sha256,
        expected_hash,
        "entitlementEvidenceSHA256",
    )


def _bounded_ascii_string(value: object, field: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or not value.isascii()
    ):
        raise ProtocolValidationError(f"{field} is invalid")
    return value


def _constant_equal(actual: str, expected: str, field: str) -> None:
    if not hmac.compare_digest(actual.encode("utf-8"), expected.encode("utf-8")):
        raise ProtocolValidationError(f"{field} binding mismatch")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolValidationError(f"duplicate JSON field: {key}")
        result[key] = value
    return result
