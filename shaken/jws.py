"""JWS compact serialisation and ES256 (RFC 7515, RFC 7518 sec. 3.4).

This is the only module that imports ``cryptography``. It supplies ECDSA P-256 with SHA-256 and
nothing else: the signature wire format (RFC 7518 sec. 3.4: R and S as two 32-octet big-endian
integers, 64 octets, not DER), the strict base64url alphabet, and one signer and one verifier
class that the rest of the package reaches through the small ``Signer`` and ``Verifier`` protocols.
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

__all__ = [
    "P256_ORDER",
    "SIGNATURE_OCTETS",
    "Es256Signer",
    "Es256Verifier",
    "JwsError",
    "Signer",
    "Verifier",
    "b64url_decode",
    "b64url_encode",
    "es256_der_to_raw",
    "es256_raw_to_der",
]

SIGNATURE_OCTETS = 64
"""RFC 7518 sec. 3.4 para 10: the ES256 JWS Signature MUST be a 64-octet sequence."""

P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
"""The order n of the NIST P-256 base point (FIPS 186-4 D.1.2.3; RFC 9180 sec. 7.1.3 also prints it)."""

_B64URL = re.compile(r"[A-Za-z0-9_-]*")


class JwsError(ValueError):
    """A JWS value is malformed. The message says which rule it broke."""


class Signer(Protocol):
    """Produces the raw 64-octet ES256 signature over a JWS Signing Input."""

    def sign(self, signing_input: bytes) -> bytes: ...


class Verifier(Protocol):
    """Answers whether a raw 64-octet ES256 signature matches a JWS Signing Input."""

    def verify(self, signing_input: bytes, signature: bytes) -> bool: ...


def b64url_encode(data: bytes) -> str:
    """BASE64URL(data): RFC 7515 sec. 2, no padding, no line breaks."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    """Decode strict, unpadded base64url (RFC 7515 sec. 2 and Appendix C).

    Refuses ``+``, ``/``, ``=``, whitespace and anything non-ASCII, and a length that no
    unpadded encoding can have. RFC 8224 erratum 6499 is the reason ``+`` and ``/`` matter: the
    Identity header grammar printed them, and the PASSporT it carries never uses them.
    """
    if not isinstance(text, str):
        raise TypeError("b64url_decode takes str")
    if _B64URL.fullmatch(text) is None:
        raise JwsError("not base64url: only A-Z a-z 0-9 - _ are allowed, with no padding")
    if len(text) % 4 == 1:
        raise JwsError("not base64url: a length of 4n+1 cannot be an unpadded encoding")
    try:
        data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as error:  # pragma: no cover - the regex rules these out
        raise JwsError(f"not base64url: {error}") from error
    # Non-canonical trailing bits decode without error; they would let two texts name one value.
    if b64url_encode(data) != text:
        raise JwsError("not base64url: non-zero trailing bits")
    return data


def es256_raw_to_der(raw: bytes) -> bytes:
    """Turn the 64-octet JWS signature into the DER ECDSA-Sig-Value that libraries expect.

    RFC 7518 sec. 3.4 para 10-11: anything but 64 octets fails; R is the first 32, S the second.
    R or S equal to zero, or not below the group order, can never verify and is refused here.
    High-S is accepted: JWS signers do not canonicalise S.
    """
    if len(raw) != SIGNATURE_OCTETS:
        raise JwsError(f"ES256 signature must be {SIGNATURE_OCTETS} octets, got {len(raw)}")
    r = int.from_bytes(raw[:32], "big")
    s = int.from_bytes(raw[32:], "big")
    if not (0 < r < P256_ORDER and 0 < s < P256_ORDER):
        raise JwsError("ES256 signature has R or S outside 1..n-1")
    return encode_dss_signature(r, s)


def es256_der_to_raw(der: bytes) -> bytes:
    """Turn a DER ECDSA-Sig-Value into R || S, each left-padded to 32 octets (RFC 7518 sec. 3.4 para 5).

    Leading zero octets are kept: the RFC says the octet sequences MUST NOT be shortened.
    """
    try:
        r, s = decode_dss_signature(der)
    except ValueError as error:
        raise JwsError(f"not a DER ECDSA-Sig-Value: {error}") from error
    if not (0 < r < P256_ORDER and 0 < s < P256_ORDER):
        raise JwsError("ECDSA signature has R or S outside 1..n-1")
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _require_p256(key: object) -> None:
    if not isinstance(key, ec.EllipticCurvePublicKey | ec.EllipticCurvePrivateKey):
        raise JwsError("not an elliptic-curve key")
    if key.curve.name != "secp256r1":
        raise JwsError(f"ES256 needs P-256 (secp256r1), the key is {key.curve.name}")


class Es256Verifier:
    """ES256 verification against one P-256 public key."""

    def __init__(self, key: ec.EllipticCurvePublicKey) -> None:
        _require_p256(key)
        self._key = key

    @classmethod
    def from_spki_der(cls, spki: bytes) -> Es256Verifier:
        """Load a DER SubjectPublicKeyInfo, which is what a certificate carries (asn1core:
        ``Certificate.subject_public_key_info``)."""
        try:
            key = serialization.load_der_public_key(spki)
        except ValueError as error:
            raise JwsError(f"not a SubjectPublicKeyInfo: {error}") from error
        if not isinstance(key, ec.EllipticCurvePublicKey):
            raise JwsError("the SubjectPublicKeyInfo is not an elliptic-curve key")
        return cls(key)

    @classmethod
    def from_pem(cls, pem: bytes) -> Es256Verifier:
        try:
            key = serialization.load_pem_public_key(pem)
        except ValueError as error:
            raise JwsError(f"not a PEM public key: {error}") from error
        if not isinstance(key, ec.EllipticCurvePublicKey):
            raise JwsError("the PEM key is not an elliptic-curve key")
        return cls(key)

    def verify(self, signing_input: bytes, signature: bytes) -> bool:
        """True only for a valid signature. A malformed one (wrong length, R or S out of range)
        is False, never an exception: the caller learns nothing from the difference."""
        try:
            der = es256_raw_to_der(signature)
        except JwsError:
            return False
        try:
            self._key.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return False
        return True


class Es256Signer:
    """ES256 signing with one P-256 private key.

    Signatures are deterministic ECDSA (RFC 6979), which RFC 8225 sec. 4.2 para 3 says SHOULD be
    used when supported, so the same key and input always give the same token.
    """

    def __init__(self, key: ec.EllipticCurvePrivateKey) -> None:
        _require_p256(key)
        self._key = key

    @classmethod
    def generate(cls) -> Es256Signer:
        return cls(ec.generate_private_key(ec.SECP256R1()))

    @classmethod
    def from_pem(cls, pem: bytes, password: bytes | None = None) -> Es256Signer:
        try:
            key = serialization.load_pem_private_key(pem, password)
        except (ValueError, TypeError) as error:
            raise JwsError(f"not a PEM private key: {error}") from error
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise JwsError("the PEM key is not an elliptic-curve key")
        return cls(key)

    def verifier(self) -> Es256Verifier:
        return Es256Verifier(self._key.public_key())

    def public_spki_der(self) -> bytes:
        return self._key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def public_spki_pem(self) -> bytes:
        return self._key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def sign(self, signing_input: bytes) -> bytes:
        der = self._key.sign(signing_input, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
        return es256_der_to_raw(der)
