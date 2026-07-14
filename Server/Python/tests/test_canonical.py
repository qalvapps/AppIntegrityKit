from __future__ import annotations

import json
from pathlib import Path

import pytest

from app_integrity import (
    ProtocolValidationError,
    b64url_decode,
    b64url_encode,
    encode_session_client_data,
    parse_session_client_data,
    sha256_b64url,
    validate_session_binding,
)


ROOT = Path(__file__).resolve().parents[3]
VECTOR_PATH = ROOT / "Protocol" / "test-vectors" / "session-client-data-v1.json"


def load_vector() -> dict[str, object]:
    return json.loads(VECTOR_PATH.read_text(encoding="utf-8"))


def test_shared_swift_python_vector() -> None:
    vector = load_vector()
    expected = vector["expected"]
    raw = expected["clientDataUTF8"].encode("utf-8")
    model = parse_session_client_data(raw)

    assert encode_session_client_data(model) == raw
    assert b64url_encode(raw) == expected["clientDataBase64URL"]
    assert sha256_b64url(raw) == expected["clientDataSHA256"]
    assert model.entitlement_evidence_sha256 == expected["entitlementEvidenceSHA256"]

    inputs = vector["inputs"]
    validate_session_binding(
        model,
        application_id=inputs["applicationID"],
        challenge_id=inputs["challengeID"],
        challenge=inputs["challenge"],
        key_id=inputs["keyID"],
        allowed_scopes={"tides:forecast", "tides:licensed-global"},
        entitlement_evidence=b64url_decode(inputs["entitlementEvidence"]),
    )


@pytest.mark.parametrize(
    "value",
    ["", "YWJj=", "YW Jj", "YWJj+", "YWJj/"],
)
def test_base64url_rejects_noncanonical_values(value: str) -> None:
    with pytest.raises(ProtocolValidationError):
        b64url_decode(value)


def test_parser_rejects_unsorted_or_duplicate_scopes() -> None:
    vector = load_vector()
    payload = json.loads(vector["expected"]["clientDataUTF8"])
    payload["requestedScopes"] = ["z", "a", "a"]
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    with pytest.raises(ProtocolValidationError, match="sorted and unique"):
        parse_session_client_data(raw)


def test_parser_rejects_noncanonical_json_and_duplicate_keys() -> None:
    vector = load_vector()
    payload = json.loads(vector["expected"]["clientDataUTF8"])
    spaced = json.dumps(payload, sort_keys=True).encode()
    with pytest.raises(ProtocolValidationError, match="not canonical JSON"):
        parse_session_client_data(spaced)

    duplicate = vector["expected"]["clientDataUTF8"].replace(
        '"applicationID":"goodtides-ios",',
        '"applicationID":"goodtides-ios","applicationID":"other",',
    ).encode()
    with pytest.raises(ProtocolValidationError, match="duplicate JSON field"):
        parse_session_client_data(duplicate)


def test_entitlement_evidence_is_cryptographically_bound() -> None:
    vector = load_vector()
    model = parse_session_client_data(vector["expected"]["clientDataUTF8"].encode())
    inputs = vector["inputs"]

    with pytest.raises(ProtocolValidationError, match="entitlementEvidenceSHA256"):
        validate_session_binding(
            model,
            application_id=inputs["applicationID"],
            challenge_id=inputs["challengeID"],
            challenge=inputs["challenge"],
            key_id=inputs["keyID"],
            allowed_scopes={"tides:forecast", "tides:licensed-global"},
            entitlement_evidence=b"altered-entitlement",
        )


def test_scope_escalation_is_rejected() -> None:
    vector = load_vector()
    model = parse_session_client_data(vector["expected"]["clientDataUTF8"].encode())
    inputs = vector["inputs"]

    with pytest.raises(ProtocolValidationError, match="exceeds server policy"):
        validate_session_binding(
            model,
            application_id=inputs["applicationID"],
            challenge_id=inputs["challengeID"],
            challenge=inputs["challenge"],
            key_id=inputs["keyID"],
            allowed_scopes={"tides:forecast"},
            entitlement_evidence=b64url_decode(inputs["entitlementEvidence"]),
        )
