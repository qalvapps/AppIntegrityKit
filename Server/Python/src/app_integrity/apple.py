from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from collections.abc import Callable
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID, ObjectIdentifier
from cryptography.x509.verification import (
    ExtensionPolicy,
    PolicyBuilder,
    Store,
    VerificationError,
)

from ._cbor import CBORDecodeError, decode_cbor, decode_cbor_prefix
from .canonical import ProtocolValidationError, parse_session_client_data
from .models import (
    AllowedApplication,
    AppAttestEnvironment,
    AppAttestPlatform,
    SessionClientData,
    VerifiedAssertion,
    VerifiedAttestation,
)


_APPLE_APP_ATTEST_ROOT_CA_PEM = b"""-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----
"""

_ATTESTATION_NONCE_OID = ObjectIdentifier("1.2.840.113635.100.8.2")
_MACOS_ACL_OID = ObjectIdentifier("1.2.840.113635.100.8.6")
_APP_ATTEST_LEAF_EKU = ObjectIdentifier("1.2.840.113635.100.4.24")
_DEVELOPMENT_AAGUID = b"appattestdevelop"
_PRODUCTION_AAGUID = b"appattest" + (b"\x00" * 7)
_MACOS_ACL_BLOB = base64.b64decode(
    "MEAMAjExMDowCQwCb2uhAwEB/zAJDAJvYaEDAQH/MAsMBG9kZWyhAwEB/"
    "zAVDARvc2duoAYMBHJzZWMwBaYDAgEB"
)


class AppAttestVerificationError(ValueError):
    """A fail-closed Apple App Attest cryptographic validation failure."""


class AppleAttestationObjectVerifier:
    """Validates Apple App Attest registration objects against a pinned root."""

    def __init__(
        self,
        *,
        root_certificate_pem: bytes = _APPLE_APP_ATTEST_ROOT_CA_PEM,
        now: Callable[[], datetime] | None = None,
        client_data_hash_length: int = 32,
    ) -> None:
        try:
            self._root = x509.load_pem_x509_certificate(root_certificate_pem)
        except (TypeError, ValueError) as error:
            raise ValueError("root_certificate_pem is not a certificate") from error
        if now is not None and not callable(now):
            raise ValueError("now must be callable")
        self._now = now or (lambda: datetime.now(timezone.utc))
        if type(client_data_hash_length) is not int or not (
            16 <= client_data_hash_length <= 64
        ):
            raise ValueError("client_data_hash_length must be between 16 and 64")
        self._client_data_hash_length = client_data_hash_length
        _validate_root_certificate(self._root)

    def verify(
        self,
        *,
        attestation_object: bytes,
        key_id: str,
        client_data_hash: bytes,
        application: AllowedApplication,
    ) -> VerifiedAttestation:
        if (
            not isinstance(client_data_hash, bytes)
            or len(client_data_hash) != self._client_data_hash_length
        ):
            raise AppAttestVerificationError("attestation client data hash is invalid")
        if not isinstance(attestation_object, bytes) or not (
            1 <= len(attestation_object) <= 262_144
        ):
            raise AppAttestVerificationError("attestation object size is invalid")

        try:
            decoded = decode_cbor(attestation_object)
            top = _exact_map(decoded, {"fmt", "attStmt", "authData"}, "attestation")
            if top["fmt"] != "apple-appattest":
                raise AppAttestVerificationError("attestation format is invalid")

            statement = _exact_map(
                top["attStmt"],
                {"x5c", "receipt"},
                "attestation statement",
            )
            certificate_values = statement["x5c"]
            if type(certificate_values) is not list or not (
                2 <= len(certificate_values) <= 4
            ):
                raise AppAttestVerificationError("certificate chain is invalid")
            if not all(
                isinstance(value, bytes) and 1 <= len(value) <= 16_384
                for value in certificate_values
            ):
                raise AppAttestVerificationError("certificate chain is invalid")

            receipt = statement["receipt"]
            if not isinstance(receipt, bytes) or not (1 <= len(receipt) <= 131_072):
                raise AppAttestVerificationError("attestation receipt is invalid")
            auth_data = top["authData"]
            if not isinstance(auth_data, bytes) or not (55 <= len(auth_data) <= 16_384):
                raise AppAttestVerificationError(
                    "attestation authenticator data is invalid"
                )

            certificates = [
                x509.load_der_x509_certificate(value) for value in certificate_values
            ]
            verification_time = _aware_utc(self._now())
            _validate_certificate_chain(certificates, self._root, verification_time)
            leaf = certificates[0]
            public_key = _p256_public_key(leaf.public_key())
            public_key_x963 = public_key.public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )

            nonce = hashlib.sha256(auth_data + client_data_hash).digest()
            certificate_nonce = _extract_octet_extension(leaf, _ATTESTATION_NONCE_OID)
            if not hmac.compare_digest(certificate_nonce, nonce):
                raise AppAttestVerificationError("attestation nonce is invalid")

            key_id_bytes = _decode_apple_key_id(key_id)
            if not hmac.compare_digest(
                hashlib.sha256(public_key_x963).digest(), key_id_bytes
            ):
                raise AppAttestVerificationError(
                    "attestation key identifier is invalid"
                )

            parsed = _parse_attestation_authenticator_data(auth_data)
            expected_rp_id = hashlib.sha256(application.app_id.encode("utf-8")).digest()
            if not hmac.compare_digest(parsed.rp_id_hash, expected_rp_id):
                raise AppAttestVerificationError(
                    "attestation application identity is invalid"
                )
            if parsed.counter != 0:
                raise AppAttestVerificationError("attestation counter is invalid")

            environment = _environment_for_aaguid(parsed.aaguid)
            if environment not in application.environments:
                raise AppAttestVerificationError(
                    "attestation environment is not allowed"
                )
            if not hmac.compare_digest(parsed.credential_id, key_id_bytes):
                raise AppAttestVerificationError("attestation credential is invalid")
            if not hmac.compare_digest(parsed.cose_public_key_x963, public_key_x963):
                raise AppAttestVerificationError("attestation public keys do not match")

            if application.platform is AppAttestPlatform.MACOS:
                acl_blob = _extract_octet_extension(leaf, _MACOS_ACL_OID)
                if not hmac.compare_digest(acl_blob, _MACOS_ACL_BLOB):
                    raise AppAttestVerificationError(
                        "macOS attestation access policy is invalid"
                    )

            category, bundle_version = _validate_extensions(
                parsed.extensions,
                category_key="apple_validation_category_01",
                bundle_key="apple_bundle_version_01",
                application=application,
            )
            return VerifiedAttestation(
                public_key_x963=public_key_x963,
                receipt=receipt,
                environment=environment,
                validation_category=category,
                bundle_version=bundle_version,
            )
        except AppAttestVerificationError:
            raise
        except (
            CBORDecodeError,
            ProtocolValidationError,
            UnsupportedAlgorithm,
            ValueError,
            TypeError,
        ) as error:
            raise AppAttestVerificationError("attestation object is invalid") from error


class AppleAssertionObjectVerifier:
    """Validates signed App Attest assertions for an already-attested key."""

    def verify(
        self,
        *,
        assertion_object: bytes,
        exact_client_data: bytes,
        client_data: SessionClientData,
        public_key_x963: bytes,
        previous_counter: int,
        application: AllowedApplication,
    ) -> VerifiedAssertion:
        if not isinstance(assertion_object, bytes) or not (
            1 <= len(assertion_object) <= 65_536
        ):
            raise AppAttestVerificationError("assertion object size is invalid")
        if not isinstance(exact_client_data, bytes) or not (
            1 <= len(exact_client_data) <= 65_536
        ):
            raise AppAttestVerificationError("assertion client data size is invalid")
        if type(previous_counter) is not int or not (
            0 <= previous_counter <= 0xFFFFFFFF
        ):
            raise AppAttestVerificationError("previous assertion counter is invalid")

        try:
            decoded = decode_cbor(assertion_object, maximum_size=65_536)
            assertion = _exact_map(
                decoded,
                {"signature", "authenticatorData"},
                "assertion",
            )
            signature = assertion["signature"]
            auth_data = assertion["authenticatorData"]
            if not isinstance(signature, bytes) or not (8 <= len(signature) <= 144):
                raise AppAttestVerificationError("assertion signature is invalid")
            if not isinstance(auth_data, bytes) or not (38 <= len(auth_data) <= 16_384):
                raise AppAttestVerificationError(
                    "assertion authenticator data is invalid"
                )

            reparsed_client_data = parse_session_client_data(exact_client_data)
            if reparsed_client_data != client_data:
                raise AppAttestVerificationError(
                    "assertion client data binding is invalid"
                )
            if not hmac.compare_digest(
                client_data.application_id.encode("utf-8"),
                application.application_id.encode("utf-8"),
            ):
                raise AppAttestVerificationError(
                    "assertion application binding is invalid"
                )
            if not set(client_data.requested_scopes).issubset(
                application.allowed_scopes
            ):
                raise AppAttestVerificationError(
                    "assertion scopes exceed server policy"
                )

            public_key = _p256_public_key_from_x963(public_key_x963)
            key_id_bytes = _decode_apple_key_id(client_data.key_id)
            if not hmac.compare_digest(
                hashlib.sha256(public_key_x963).digest(),
                key_id_bytes,
            ):
                raise AppAttestVerificationError("assertion key identifier is invalid")
            client_data_hash = hashlib.sha256(exact_client_data).digest()
            nonce = hashlib.sha256(auth_data + client_data_hash).digest()
            try:
                public_key.verify(
                    signature,
                    nonce,
                    ec.ECDSA(hashes.SHA256()),
                )
            except InvalidSignature as error:
                raise AppAttestVerificationError(
                    "assertion signature is invalid"
                ) from error

            rp_id_hash = auth_data[:32]
            counter = int.from_bytes(auth_data[33:37], "big")
            expected_rp_id = hashlib.sha256(application.app_id.encode("utf-8")).digest()
            if not hmac.compare_digest(rp_id_hash, expected_rp_id):
                raise AppAttestVerificationError(
                    "assertion application identity is invalid"
                )
            if counter <= previous_counter or counter == 0:
                raise AppAttestVerificationError("assertion counter did not advance")

            extensions, end = decode_cbor_prefix(
                auth_data,
                offset=37,
                maximum_size=16_384,
            )
            if end != len(auth_data) or type(extensions) is not dict:
                raise AppAttestVerificationError("assertion extensions are invalid")
            category, bundle_version = _validate_extensions(
                extensions,
                category_key="validationCategory",
                bundle_key="bundleVersion",
                application=application,
            )
            return VerifiedAssertion(
                counter=counter,
                validation_category=category,
                bundle_version=bundle_version,
            )
        except AppAttestVerificationError:
            raise
        except (
            CBORDecodeError,
            ProtocolValidationError,
            UnsupportedAlgorithm,
            ValueError,
            TypeError,
        ) as error:
            raise AppAttestVerificationError("assertion object is invalid") from error


class _AttestationAuthenticatorData:
    __slots__ = (
        "rp_id_hash",
        "counter",
        "aaguid",
        "credential_id",
        "cose_public_key_x963",
        "extensions",
    )

    def __init__(
        self,
        *,
        rp_id_hash: bytes,
        counter: int,
        aaguid: bytes,
        credential_id: bytes,
        cose_public_key_x963: bytes,
        extensions: dict[object, object],
    ) -> None:
        self.rp_id_hash = rp_id_hash
        self.counter = counter
        self.aaguid = aaguid
        self.credential_id = credential_id
        self.cose_public_key_x963 = cose_public_key_x963
        self.extensions = extensions


def _parse_attestation_authenticator_data(data: bytes) -> _AttestationAuthenticatorData:
    if len(data) < 133:
        raise AppAttestVerificationError("attestation authenticator data is truncated")
    flags = data[32]
    if flags & 0x40 == 0:
        raise AppAttestVerificationError("attested credential data is missing")
    counter = int.from_bytes(data[33:37], "big")
    aaguid = data[37:53]
    credential_length = int.from_bytes(data[53:55], "big")
    if credential_length != 32 or 55 + credential_length >= len(data):
        raise AppAttestVerificationError("attestation credential length is invalid")
    credential_id = data[55 : 55 + credential_length]

    cose_key, offset = decode_cbor_prefix(
        data,
        offset=55 + credential_length,
        maximum_size=16_384,
    )
    if type(cose_key) is not dict or set(cose_key) != {1, 3, -1, -2, -3}:
        raise AppAttestVerificationError("attestation COSE key is invalid")
    if cose_key[1] != 2 or cose_key[3] != -7 or cose_key[-1] != 1:
        raise AppAttestVerificationError("attestation COSE algorithm is invalid")
    x_coordinate = cose_key[-2]
    y_coordinate = cose_key[-3]
    if not isinstance(x_coordinate, bytes) or len(x_coordinate) != 32:
        raise AppAttestVerificationError("attestation COSE x-coordinate is invalid")
    if not isinstance(y_coordinate, bytes) or len(y_coordinate) != 32:
        raise AppAttestVerificationError("attestation COSE y-coordinate is invalid")
    cose_public_key_x963 = b"\x04" + x_coordinate + y_coordinate
    _p256_public_key_from_x963(cose_public_key_x963)

    extensions, end = decode_cbor_prefix(data, offset=offset, maximum_size=16_384)
    if end != len(data) or type(extensions) is not dict:
        raise AppAttestVerificationError("attestation extensions are invalid")
    return _AttestationAuthenticatorData(
        rp_id_hash=data[:32],
        counter=counter,
        aaguid=aaguid,
        credential_id=credential_id,
        cose_public_key_x963=cose_public_key_x963,
        extensions=extensions,
    )


def _validate_extensions(
    extensions: dict[object, object],
    *,
    category_key: str,
    bundle_key: str,
    application: AllowedApplication,
) -> tuple[int, str]:
    if category_key not in extensions or bundle_key not in extensions:
        known_keys = sorted(
            key
            for key in {
                "validationCategory",
                "bundleVersion",
                "apple_validation_category_01",
                "apple_bundle_version_01",
            }
            if key in extensions
        )
        schema = ",".join(known_keys) if known_keys else "none"
        raise AppAttestVerificationError(
            f"required App Attest extensions are missing; known keys present: {schema}"
        )
    category_value = extensions[category_key]
    if isinstance(category_value, bytes) and len(category_value) == 4:
        category = int.from_bytes(category_value, "little")
    elif type(category_value) is int and 0 <= category_value <= 0xFFFFFFFF:
        category = category_value
    else:
        raise AppAttestVerificationError("validation category is invalid")
    if (
        category in {0, 7, 8, 9}
        or category not in application.allowed_validation_categories
    ):
        raise AppAttestVerificationError("validation category is not allowed")

    bundle_version = extensions[bundle_key]
    if (
        not isinstance(bundle_version, str)
        or not bundle_version
        or len(bundle_version) > 128
        or not bundle_version.isascii()
    ):
        raise AppAttestVerificationError("bundle version is invalid")
    if bundle_version not in application.allowed_bundle_versions:
        raise AppAttestVerificationError("bundle version is not allowed")
    return category, bundle_version


def _exact_map(value: object, fields: set[str], name: str) -> dict[object, object]:
    if type(value) is not dict or set(value) != fields:
        raise AppAttestVerificationError(f"{name} structure is invalid")
    return value


def _decode_apple_key_id(key_id: str) -> bytes:
    if (
        not isinstance(key_id, str)
        or not key_id
        or len(key_id) > 128
        or not key_id.isascii()
    ):
        raise AppAttestVerificationError("attestation key identifier is invalid")
    try:
        value = base64.b64decode(key_id, validate=True)
    except (binascii.Error, ValueError) as error:
        raise AppAttestVerificationError(
            "attestation key identifier is invalid"
        ) from error
    if len(value) != 32 or not hmac.compare_digest(
        base64.b64encode(value).decode("ascii"),
        key_id,
    ):
        raise AppAttestVerificationError("attestation key identifier is invalid")
    return value


def _environment_for_aaguid(aaguid: bytes) -> AppAttestEnvironment:
    if hmac.compare_digest(aaguid, _DEVELOPMENT_AAGUID):
        return AppAttestEnvironment.DEVELOPMENT
    if hmac.compare_digest(aaguid, _PRODUCTION_AAGUID):
        return AppAttestEnvironment.PRODUCTION
    raise AppAttestVerificationError("attestation AAGUID is invalid")


def _p256_public_key(key: object) -> ec.EllipticCurvePublicKey:
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
        key.curve,
        ec.SECP256R1,
    ):
        raise AppAttestVerificationError("App Attest public key is invalid")
    return key


def _p256_public_key_from_x963(value: bytes) -> ec.EllipticCurvePublicKey:
    if not isinstance(value, bytes) or len(value) != 65 or value[0] != 0x04:
        raise AppAttestVerificationError("App Attest public key encoding is invalid")
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), value)
    except ValueError as error:
        raise AppAttestVerificationError(
            "App Attest public key encoding is invalid"
        ) from error


def _validate_root_certificate(root: x509.Certificate) -> None:
    if root.subject != root.issuer:
        raise ValueError("root certificate must be self-issued")
    try:
        constraints = _certificate_extension(root, ExtensionOID.BASIC_CONSTRAINTS)
        if not isinstance(constraints, x509.BasicConstraints) or not constraints.ca:
            raise AppAttestVerificationError("root certificate must be a CA")
        usage = _certificate_extension(root, ExtensionOID.KEY_USAGE)
        if not isinstance(usage, x509.KeyUsage) or not usage.key_cert_sign:
            raise AppAttestVerificationError("root certificate key usage is invalid")
        _verify_certificate_signature(root, root)
    except AppAttestVerificationError as error:
        raise ValueError("root certificate is invalid") from error


def _validate_certificate_chain(
    certificates: list[x509.Certificate],
    root: x509.Certificate,
    now: datetime,
) -> None:
    root_fingerprint = root.fingerprint(hashes.SHA256())
    if any(
        hmac.compare_digest(certificate.fingerprint(hashes.SHA256()), root_fingerprint)
        for certificate in certificates
    ):
        raise AppAttestVerificationError("certificate chain must not include its root")

    try:
        verifier = (
            PolicyBuilder()
            .store(Store([root]))
            .time(now)
            .max_chain_depth(3)
            .extension_policies(
                ca_policy=ExtensionPolicy.webpki_defaults_ca(),
                ee_policy=ExtensionPolicy.permit_all(),
            )
            .build_client_verifier()
        )
        verifier.verify(certificates[0], certificates[1:])
    except VerificationError as error:
        raise AppAttestVerificationError(
            "certificate chain validation failed"
        ) from error

    leaf = certificates[0]
    leaf_constraints = _certificate_extension(leaf, ExtensionOID.BASIC_CONSTRAINTS)
    if not isinstance(leaf_constraints, x509.BasicConstraints) or leaf_constraints.ca:
        raise AppAttestVerificationError(
            "credential certificate constraints are invalid"
        )
    leaf_usage = _certificate_extension(leaf, ExtensionOID.KEY_USAGE)
    if not isinstance(leaf_usage, x509.KeyUsage) or not leaf_usage.digital_signature:
        raise AppAttestVerificationError("credential certificate key usage is invalid")
    leaf_eku = _certificate_extension(leaf, ExtensionOID.EXTENDED_KEY_USAGE)
    if (
        not isinstance(leaf_eku, x509.ExtendedKeyUsage)
        or _APP_ATTEST_LEAF_EKU not in leaf_eku
    ):
        raise AppAttestVerificationError("credential certificate purpose is invalid")
    _p256_public_key(leaf.public_key())


def _certificate_extension(
    certificate: x509.Certificate,
    oid: ObjectIdentifier,
) -> x509.ExtensionType:
    try:
        return certificate.extensions.get_extension_for_oid(oid).value
    except x509.ExtensionNotFound as error:
        raise AppAttestVerificationError(
            "required certificate extension is missing"
        ) from error


def _verify_certificate_signature(
    certificate: x509.Certificate,
    issuer: x509.Certificate,
) -> None:
    issuer_key = issuer.public_key()
    signature_hash = certificate.signature_hash_algorithm
    if not isinstance(issuer_key, ec.EllipticCurvePublicKey) or signature_hash is None:
        raise AppAttestVerificationError("certificate signature algorithm is invalid")
    try:
        issuer_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            ec.ECDSA(signature_hash),
        )
    except InvalidSignature as error:
        raise AppAttestVerificationError("certificate signature is invalid") from error


def _extract_octet_extension(
    certificate: x509.Certificate,
    oid: ObjectIdentifier,
) -> bytes:
    extension = _certificate_extension(certificate, oid)
    if not isinstance(extension, x509.UnrecognizedExtension):
        raise AppAttestVerificationError("certificate extension encoding is invalid")
    sequence, sequence_end = _read_der_tlv(extension.value, 0, 0x30)
    if sequence_end != len(extension.value):
        raise AppAttestVerificationError("certificate extension has trailing data")
    explicit_value, explicit_end = _read_der_tlv(sequence, 0, 0xA1)
    if explicit_end != len(sequence):
        raise AppAttestVerificationError("certificate extension sequence is invalid")
    octets, octet_end = _read_der_tlv(explicit_value, 0, 0x04)
    if octet_end != len(explicit_value):
        raise AppAttestVerificationError(
            "certificate extension octet string is invalid"
        )
    return octets


def _read_der_tlv(data: bytes, offset: int, expected_tag: int) -> tuple[bytes, int]:
    if offset >= len(data) or data[offset] != expected_tag:
        raise AppAttestVerificationError("certificate extension DER tag is invalid")
    offset += 1
    if offset >= len(data):
        raise AppAttestVerificationError("certificate extension DER is truncated")
    first_length = data[offset]
    offset += 1
    if first_length < 0x80:
        length = first_length
    else:
        count = first_length & 0x7F
        if count == 0 or count > 4 or offset + count > len(data):
            raise AppAttestVerificationError(
                "certificate extension DER length is invalid"
            )
        length_bytes = data[offset : offset + count]
        if length_bytes[0] == 0:
            raise AppAttestVerificationError(
                "certificate extension DER length is not minimal"
            )
        length = int.from_bytes(length_bytes, "big")
        if length < 0x80:
            raise AppAttestVerificationError(
                "certificate extension DER length is not minimal"
            )
        offset += count
    end = offset + length
    if end > len(data):
        raise AppAttestVerificationError("certificate extension DER is truncated")
    return data[offset:end], end


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise AppAttestVerificationError("verification clock must be timezone-aware")
    return value.astimezone(timezone.utc)
