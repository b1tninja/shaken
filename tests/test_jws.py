"""ES256 and base64url (RFC 7515, RFC 7518 sec. 3.4)."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from hypothesis import given
from hypothesis import strategies as st
from vectors import TEST_KEY_PEM

from shaken import jws


@given(st.binary(max_size=200))
def test_b64url_round_trip(data):
    text = jws.b64url_encode(data)
    assert "=" not in text
    assert jws.b64url_decode(text) == data


@pytest.mark.parametrize(
    "text",
    ["ab=", "a+b/", "ab cd", "ab\n", "café", "a", "abcde", "AB" + chr(0x661)],
    ids=[
        "padding",
        "std-alphabet",
        "space",
        "newline",
        "non-ascii",
        "len1",
        "len5",
        "unicode-digit",
    ],
)
def test_b64url_decode_strict(text):
    with pytest.raises(jws.JwsError):
        jws.b64url_decode(text)


def test_b64url_refuses_nonzero_trailing_bits():
    # "QR" decodes to b"A" but only "QQ" is the canonical text for it.
    assert jws.b64url_decode("QQ") == b"A"
    with pytest.raises(jws.JwsError, match="trailing"):
        jws.b64url_decode("QR")


@given(st.integers(1, jws.P256_ORDER - 1), st.integers(1, jws.P256_ORDER - 1))
def test_raw_der_conversion(r, s):
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    der = jws.es256_raw_to_der(raw)
    assert der == encode_dss_signature(r, s)  # the oracle: cryptography's own DER encoder
    assert decode_dss_signature(der) == (r, s)
    assert jws.es256_der_to_raw(der) == raw


def test_raw_conversion_keeps_leading_zero_octets():
    raw = (1).to_bytes(32, "big") + (2).to_bytes(32, "big")
    assert jws.es256_der_to_raw(jws.es256_raw_to_der(raw)) == raw


@pytest.mark.parametrize("size", [0, 63, 65, 96])
def test_raw_length_must_be_64(size):
    with pytest.raises(jws.JwsError, match="64"):
        jws.es256_raw_to_der(b"\x01" * size)


def test_zero_and_out_of_range_scalars_refused():
    one = (1).to_bytes(32, "big")
    for bad in (bytes(32), jws.P256_ORDER.to_bytes(32, "big"), b"\xff" * 32):
        with pytest.raises(jws.JwsError):
            jws.es256_raw_to_der(bad + one)
        with pytest.raises(jws.JwsError):
            jws.es256_raw_to_der(one + bad)


def test_high_s_is_accepted():
    high = jws.P256_ORDER - 1
    raw = (1).to_bytes(32, "big") + high.to_bytes(32, "big")
    assert jws.es256_der_to_raw(jws.es256_raw_to_der(raw)) == raw


@pytest.mark.parametrize(
    "der",
    [
        b"",
        b"\x30\x00",
        b"\x30\x80\x02\x01\x01\x02\x01\x01\x00\x00",
        b"\x31\x06\x02\x01\x01\x02\x01\x01",
    ],
    ids=["empty", "empty-seq", "indefinite", "wrong-tag"],
)
def test_der_to_raw_refuses_bad_der(der):
    with pytest.raises(jws.JwsError):
        jws.es256_der_to_raw(der)


def test_sign_then_verify_and_reject_tampering():
    signer = jws.Es256Signer.from_pem(TEST_KEY_PEM.encode())
    verifier = signer.verifier()
    signature = signer.sign(b"message")
    assert len(signature) == 64
    assert verifier.verify(b"message", signature)
    assert not verifier.verify(b"messagf", signature)
    flipped = bytes([signature[0] ^ 1]) + signature[1:]
    assert not verifier.verify(b"message", flipped)


def test_verifier_returns_false_for_malformed_signatures():
    verifier = jws.Es256Signer.generate().verifier()
    assert verifier.verify(b"m", b"") is False
    assert verifier.verify(b"m", bytes(64)) is False


def test_signing_is_deterministic():
    signer = jws.Es256Signer.from_pem(TEST_KEY_PEM.encode())
    assert signer.sign(b"x") == signer.sign(b"x")


def test_only_p256_keys_are_accepted():
    with pytest.raises(jws.JwsError, match="P-256"):
        jws.Es256Signer(ec.generate_private_key(ec.SECP384R1()))
    other = ec.generate_private_key(ec.SECP384R1()).public_key()
    with pytest.raises(jws.JwsError, match="P-256"):
        jws.Es256Verifier(other)


def test_spki_loader_round_trips():
    signer = jws.Es256Signer.generate()
    verifier = jws.Es256Verifier.from_spki_der(signer.public_spki_der())
    assert verifier.verify(b"m", signer.sign(b"m"))
    with pytest.raises(jws.JwsError):
        jws.Es256Verifier.from_spki_der(b"not der")
