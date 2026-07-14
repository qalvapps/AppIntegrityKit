from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import replace
from datetime import datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from app_integrity import (
    AllowedApplication,
    AppAttestEnvironment,
    AppAttestPlatform,
    AppAttestVerificationError,
    AppleAssertionObjectVerifier,
    AppleAttestationObjectVerifier,
    b64url_encode,
    encode_session_client_data,
    parse_session_client_data,
)
from app_integrity._cbor import CBORDecodeError, decode_cbor


ROOT = Path(__file__).resolve().parents[3]
OFFICIAL_FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "apple_attestation_object_validation_guide.json"
)
SESSION_VECTOR = ROOT / "Protocol" / "test-vectors" / "session-client-data-v1.json"


def _official_fixture() -> dict[str, object]:
    return json.loads(OFFICIAL_FIXTURE.read_text(encoding="utf-8"))


def _official_application(
    *,
    app_id: str = "1234567890.com.example.myapp",
    environments: frozenset[AppAttestEnvironment] | None = None,
    categories: frozenset[int] = frozenset({1}),
    bundle_versions: frozenset[str] = frozenset({"1"}),
) -> AllowedApplication:
    return AllowedApplication(
        application_id="official-apple-sample",
        app_id=app_id,
        platform=AppAttestPlatform.IOS,
        environments=environments or frozenset({AppAttestEnvironment.PRODUCTION}),
        allowed_scopes=frozenset(),
        allowed_validation_categories=categories,
        allowed_bundle_versions=bundle_versions,
    )


def _official_verifier() -> AppleAttestationObjectVerifier:
    fixture = _official_fixture()
    verification_time = datetime.fromisoformat(
        fixture["verificationTime"].replace("Z", "+00:00")
    )
    return AppleAttestationObjectVerifier(
        now=lambda: verification_time,
        client_data_hash_length=len(fixture["challenge"].encode("utf-8")),
    )


def _verify_official(
    *,
    attestation_object: bytes | None = None,
    key_id: str | None = None,
    challenge: bytes | None = None,
    application: AllowedApplication | None = None,
):
    fixture = _official_fixture()
    return _official_verifier().verify(
        attestation_object=attestation_object
        or base64.b64decode(fixture["attestationObjectBase64"]),
        key_id=key_id or fixture["keyID"],
        client_data_hash=challenge or fixture["challenge"].encode("utf-8"),
        application=application or _official_application(),
    )


def test_apples_official_attestation_validation_sample() -> None:
    fixture = _official_fixture()
    result = _verify_official()

    assert result.environment.value == fixture["expected"]["environment"]
    assert result.validation_category == fixture["expected"]["validationCategory"]
    assert result.bundle_version == fixture["expected"]["bundleVersion"]
    assert result.receipt
    assert (
        base64.b64encode(hashlib.sha256(result.public_key_x963).digest()).decode()
        == (fixture["keyID"])
    )


def test_attestation_rejects_wrong_challenge_key_and_app_identity() -> None:
    with pytest.raises(AppAttestVerificationError, match="nonce"):
        _verify_official(challenge=b"altered_server_challenge")
    with pytest.raises(AppAttestVerificationError, match="key identifier"):
        _verify_official(key_id=base64.b64encode(b"\x00" * 32).decode())
    with pytest.raises(AppAttestVerificationError, match="application identity"):
        _verify_official(
            application=_official_application(app_id="OTHER.com.example.myapp")
        )


def test_attestation_rejects_environment_category_and_bundle_policy() -> None:
    with pytest.raises(AppAttestVerificationError, match="environment"):
        _verify_official(
            application=_official_application(
                environments=frozenset({AppAttestEnvironment.DEVELOPMENT})
            )
        )
    with pytest.raises(AppAttestVerificationError, match="category"):
        _verify_official(application=_official_application(categories=frozenset({4})))
    with pytest.raises(AppAttestVerificationError, match="bundle version"):
        _verify_official(
            application=_official_application(bundle_versions=frozenset({"999"}))
        )


def test_attestation_rejects_expired_and_tampered_certificate_chains() -> None:
    fixture = _official_fixture()
    raw = base64.b64decode(fixture["attestationObjectBase64"])
    with pytest.raises(AppAttestVerificationError, match="certificate chain"):
        AppleAttestationObjectVerifier(
            client_data_hash_length=len(fixture["challenge"].encode("utf-8"))
        ).verify(
            attestation_object=raw,
            key_id=fixture["keyID"],
            client_data_hash=fixture["challenge"].encode(),
            application=_official_application(),
        )

    decoded = decode_cbor(raw)
    leaf = bytearray(decoded["attStmt"]["x5c"][0])
    leaf[-1] ^= 0x01
    decoded["attStmt"]["x5c"][0] = bytes(leaf)
    with pytest.raises(AppAttestVerificationError, match="certificate chain"):
        _verify_official(attestation_object=_encode_cbor(decoded))


def test_strict_cbor_rejects_duplicate_keys_and_nonminimal_lengths() -> None:
    duplicate_map = b"\xa2\x63fmt\x6fapple-appattest\x63fmt\x6fapple-appattest"
    with pytest.raises(CBORDecodeError, match="duplicate"):
        decode_cbor(duplicate_map)
    with pytest.raises(CBORDecodeError, match="minimally"):
        decode_cbor(b"\x18\x01")


def _assertion_application() -> AllowedApplication:
    return AllowedApplication(
        application_id="goodtides-ios",
        app_id="TEAMID1234.com.qalv.goodtides",
        platform=AppAttestPlatform.IOS,
        environments=frozenset({AppAttestEnvironment.PRODUCTION}),
        allowed_scopes=frozenset({"tides:forecast", "tides:licensed-global"}),
        allowed_validation_categories=frozenset({4}),
        allowed_bundle_versions=frozenset({"1"}),
    )


def _session_client_data(private_key: ec.EllipticCurvePrivateKey):
    vector = json.loads(SESSION_VECTOR.read_text(encoding="utf-8"))
    model = parse_session_client_data(
        vector["expected"]["clientDataUTF8"].encode("utf-8")
    )
    public_key_x963 = private_key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    model = replace(
        model,
        key_id=base64.b64encode(hashlib.sha256(public_key_x963).digest()).decode(),
    )
    raw = encode_session_client_data(model)
    return raw, model


def _make_assertion(
    private_key: ec.EllipticCurvePrivateKey,
    *,
    exact_client_data: bytes,
    application: AllowedApplication,
    counter: int = 1,
    category: int = 4,
    bundle_version: str = "1",
    rp_id: str | None = None,
) -> tuple[bytes, bytes]:
    extensions = {
        "validationCategory": category.to_bytes(4, "little"),
        "bundleVersion": bundle_version,
    }
    auth_data = (
        hashlib.sha256((rp_id or application.app_id).encode("utf-8")).digest()
        + b"\x80"
        + counter.to_bytes(4, "big")
        + _encode_cbor(extensions)
    )
    nonce = hashlib.sha256(
        auth_data + hashlib.sha256(exact_client_data).digest()
    ).digest()
    signature = private_key.sign(
        nonce,
        ec.ECDSA(hashes.SHA256()),
    )
    public_key_x963 = private_key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    return (
        _encode_cbor({"signature": signature, "authenticatorData": auth_data}),
        public_key_x963,
    )


def test_assertion_verifies_signature_identity_extensions_and_counter() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    exact_client_data, client_data = _session_client_data(private_key)
    application = _assertion_application()
    assertion, public_key = _make_assertion(
        private_key,
        exact_client_data=exact_client_data,
        application=application,
        counter=7,
    )

    result = AppleAssertionObjectVerifier().verify(
        assertion_object=assertion,
        exact_client_data=exact_client_data,
        client_data=client_data,
        public_key_x963=public_key,
        previous_counter=6,
        application=application,
    )

    assert result.counter == 7
    assert result.validation_category == 4
    assert result.bundle_version == "1"


def test_assertion_rejects_signature_that_treats_apple_nonce_as_prehashed() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    exact_client_data, client_data = _session_client_data(private_key)
    application = _assertion_application()
    assertion, public_key = _make_assertion(
        private_key,
        exact_client_data=exact_client_data,
        application=application,
    )
    decoded = decode_cbor(assertion)
    nonce = hashlib.sha256(
        decoded["authenticatorData"] + hashlib.sha256(exact_client_data).digest()
    ).digest()
    decoded["signature"] = private_key.sign(
        nonce,
        ec.ECDSA(utils.Prehashed(hashes.SHA256())),
    )

    with pytest.raises(AppAttestVerificationError, match="signature"):
        AppleAssertionObjectVerifier().verify(
            assertion_object=_encode_cbor(decoded),
            exact_client_data=exact_client_data,
            client_data=client_data,
            public_key_x963=public_key,
            previous_counter=0,
            application=application,
        )


@pytest.mark.parametrize(("counter", "previous"), [(0, 0), (7, 7), (6, 7)])
def test_assertion_rejects_replay_or_counter_rollback(
    counter: int, previous: int
) -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    exact_client_data, client_data = _session_client_data(private_key)
    application = _assertion_application()
    assertion, public_key = _make_assertion(
        private_key,
        exact_client_data=exact_client_data,
        application=application,
        counter=counter,
    )
    with pytest.raises(AppAttestVerificationError, match="counter"):
        AppleAssertionObjectVerifier().verify(
            assertion_object=assertion,
            exact_client_data=exact_client_data,
            client_data=client_data,
            public_key_x963=public_key,
            previous_counter=previous,
            application=application,
        )


def test_assertion_rejects_tampered_signature_and_client_data() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    exact_client_data, client_data = _session_client_data(private_key)
    application = _assertion_application()
    assertion, public_key = _make_assertion(
        private_key,
        exact_client_data=exact_client_data,
        application=application,
    )

    decoded = decode_cbor(assertion)
    signature = bytearray(decoded["signature"])
    signature[-1] ^= 0x01
    decoded["signature"] = bytes(signature)
    with pytest.raises(AppAttestVerificationError, match="signature"):
        AppleAssertionObjectVerifier().verify(
            assertion_object=_encode_cbor(decoded),
            exact_client_data=exact_client_data,
            client_data=client_data,
            public_key_x963=public_key,
            previous_counter=0,
            application=application,
        )

    unrelated_public_key = (
        ec.generate_private_key(ec.SECP256R1())
        .public_key()
        .public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
    )
    with pytest.raises(AppAttestVerificationError, match="key identifier"):
        AppleAssertionObjectVerifier().verify(
            assertion_object=assertion,
            exact_client_data=exact_client_data,
            client_data=client_data,
            public_key_x963=unrelated_public_key,
            previous_counter=0,
            application=application,
        )

    altered_model = replace(client_data, challenge=b64url_encode(b"x" * 32))
    altered_client_data = encode_session_client_data(altered_model)
    with pytest.raises(AppAttestVerificationError, match="signature"):
        AppleAssertionObjectVerifier().verify(
            assertion_object=assertion,
            exact_client_data=altered_client_data,
            client_data=altered_model,
            public_key_x963=public_key,
            previous_counter=0,
            application=application,
        )


def test_assertion_rejects_wrong_identity_category_and_bundle() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    exact_client_data, client_data = _session_client_data(private_key)
    application = _assertion_application()
    verifier = AppleAssertionObjectVerifier()

    wrong_rp, public_key = _make_assertion(
        private_key,
        exact_client_data=exact_client_data,
        application=application,
        rp_id="OTHER.com.qalv.goodtides",
    )
    with pytest.raises(AppAttestVerificationError, match="application identity"):
        verifier.verify(
            assertion_object=wrong_rp,
            exact_client_data=exact_client_data,
            client_data=client_data,
            public_key_x963=public_key,
            previous_counter=0,
            application=application,
        )

    wrong_category, public_key = _make_assertion(
        private_key,
        exact_client_data=exact_client_data,
        application=application,
        category=3,
    )
    with pytest.raises(AppAttestVerificationError, match="category"):
        verifier.verify(
            assertion_object=wrong_category,
            exact_client_data=exact_client_data,
            client_data=client_data,
            public_key_x963=public_key,
            previous_counter=0,
            application=application,
        )

    wrong_bundle, public_key = _make_assertion(
        private_key,
        exact_client_data=exact_client_data,
        application=application,
        bundle_version="999",
    )
    with pytest.raises(AppAttestVerificationError, match="bundle version"):
        verifier.verify(
            assertion_object=wrong_bundle,
            exact_client_data=exact_client_data,
            client_data=client_data,
            public_key_x963=public_key,
            previous_counter=0,
            application=application,
        )


def _encode_cbor(value: object) -> bytes:
    if type(value) is int:
        if value >= 0:
            return _encode_cbor_argument(0, value)
        return _encode_cbor_argument(1, -1 - value)
    if isinstance(value, bytes):
        return _encode_cbor_argument(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return _encode_cbor_argument(3, len(encoded)) + encoded
    if type(value) is list:
        return _encode_cbor_argument(4, len(value)) + b"".join(
            _encode_cbor(item) for item in value
        )
    if type(value) is dict:
        return _encode_cbor_argument(5, len(value)) + b"".join(
            _encode_cbor(key) + _encode_cbor(item) for key, item in value.items()
        )
    raise TypeError(f"unsupported CBOR test value: {type(value)!r}")


def _encode_cbor_argument(major_type: int, value: int) -> bytes:
    prefix = major_type << 5
    if value < 24:
        return bytes([prefix | value])
    if value <= 0xFF:
        return bytes([prefix | 24, value])
    if value <= 0xFFFF:
        return bytes([prefix | 25]) + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return bytes([prefix | 26]) + value.to_bytes(4, "big")
    return bytes([prefix | 27]) + value.to_bytes(8, "big")
