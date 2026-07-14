from __future__ import annotations

from dataclasses import dataclass


class CBORDecodeError(ValueError):
    """Raised when security-sensitive CBOR is malformed or ambiguous."""


@dataclass(slots=True)
class _Decoder:
    data: bytes
    maximum_items: int
    offset: int = 0
    item_count: int = 0

    def read_item(self, *, depth: int = 0) -> object:
        if depth > 16:
            raise CBORDecodeError("CBOR nesting is too deep")
        self.item_count += 1
        if self.item_count > self.maximum_items:
            raise CBORDecodeError("CBOR contains too many items")
        if self.offset >= len(self.data):
            raise CBORDecodeError("CBOR is truncated")

        initial = self.data[self.offset]
        self.offset += 1
        major_type = initial >> 5
        additional = initial & 0x1F

        if major_type == 7:
            if additional == 20:
                return False
            if additional == 21:
                return True
            if additional == 22:
                return None
            raise CBORDecodeError("unsupported CBOR simple or floating-point value")

        value = self._read_argument(additional)
        if major_type == 0:
            return value
        if major_type == 1:
            return -1 - value
        if major_type == 2:
            return self._read_bytes(value)
        if major_type == 3:
            try:
                return self._read_bytes(value).decode("utf-8")
            except UnicodeDecodeError as error:
                raise CBORDecodeError("CBOR text is not UTF-8") from error
        if major_type == 4:
            if value > self.maximum_items:
                raise CBORDecodeError("CBOR array is too large")
            return [self.read_item(depth=depth + 1) for _ in range(value)]
        if major_type == 5:
            if value > self.maximum_items:
                raise CBORDecodeError("CBOR map is too large")
            result: dict[object, object] = {}
            seen: set[tuple[type[object], object]] = set()
            for _ in range(value):
                key = self.read_item(depth=depth + 1)
                if type(key) not in {int, str, bytes}:
                    raise CBORDecodeError("CBOR map key has an unsupported type")
                fingerprint = (type(key), key)
                if fingerprint in seen:
                    raise CBORDecodeError("CBOR map contains a duplicate key")
                seen.add(fingerprint)
                result[key] = self.read_item(depth=depth + 1)
            return result
        if major_type == 6:
            raise CBORDecodeError("CBOR tags are not permitted")
        raise CBORDecodeError("unsupported CBOR major type")

    def _read_argument(self, additional: int) -> int:
        if additional < 24:
            return additional
        if additional == 24:
            return self._read_uint(1, minimum=24)
        if additional == 25:
            return self._read_uint(2, minimum=1 << 8)
        if additional == 26:
            return self._read_uint(4, minimum=1 << 16)
        if additional == 27:
            return self._read_uint(8, minimum=1 << 32)
        raise CBORDecodeError("indefinite or reserved CBOR length")

    def _read_uint(self, length: int, *, minimum: int) -> int:
        value = int.from_bytes(self._read_bytes(length), "big")
        if value < minimum:
            raise CBORDecodeError("CBOR integer or length is not minimally encoded")
        return value

    def _read_bytes(self, length: int) -> bytes:
        end = self.offset + length
        if end > len(self.data):
            raise CBORDecodeError("CBOR is truncated")
        value = self.data[self.offset : end]
        self.offset = end
        return value


def decode_cbor(data: bytes, *, maximum_size: int = 262_144) -> object:
    value, offset = decode_cbor_prefix(data, maximum_size=maximum_size)
    if offset != len(data):
        raise CBORDecodeError("CBOR has trailing data")
    return value


def decode_cbor_prefix(
    data: bytes,
    *,
    offset: int = 0,
    maximum_size: int = 262_144,
) -> tuple[object, int]:
    if not isinstance(data, bytes) or not data or len(data) > maximum_size:
        raise CBORDecodeError("CBOR input size is invalid")
    if offset < 0 or offset >= len(data):
        raise CBORDecodeError("CBOR offset is invalid")
    decoder = _Decoder(data=data, maximum_items=1_024, offset=offset)
    value = decoder.read_item()
    return value, decoder.offset
