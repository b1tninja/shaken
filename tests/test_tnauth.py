"""TN Authorization List (RFC 8226 sec. 9, Appendix A) read through asn1core."""

from __future__ import annotations

import pytest
from vectors import CERT_PEM, SHAKEN_TOKEN, TN_AUTH_LIST_DER

from shaken import credentials, jws, passport, tnauth
from shaken.tnauth import (
    ServiceProviderCode,
    TelephoneNumber,
    TelephoneNumberRange,
    TNAuthListError,
)


def test_vector_list_is_read():
    """The DER was written by hand in tools/make_vectors.py, not by tnauth."""
    entries = tnauth.parse_tn_auth_list(bytes.fromhex(TN_AUTH_LIST_DER))
    assert entries == (
        ServiceProviderCode("1234"),
        TelephoneNumberRange("2125550100", 100),
        TelephoneNumber("12155551212"),
    )


def test_certificate_carries_the_extension():
    (cert,) = credentials.load_certificates(CERT_PEM.encode())
    entries = tnauth.from_certificate(cert)
    assert entries is not None
    assert TelephoneNumber("12155551212") in entries
    extension = cert.extension(tnauth.ID_PE_TNAUTHLIST)
    assert extension is not None
    assert extension.critical is False  # RFC 8226 sec. 9 para 1: non-critical


def test_certificate_without_the_extension_gives_none():
    # A bare self-signed certificate made on the fly, with no TN list.
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "plain")])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(7)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    (parsed,) = credentials.load_certificates(cert.public_bytes(serialization.Encoding.DER))
    assert tnauth.from_certificate(parsed) is None


def test_certificate_key_verifies_the_pinned_token():
    (cert,) = credentials.load_certificates(CERT_PEM.encode())
    assert passport.verify(SHAKEN_TOKEN, credentials.signer_verifier(cert)).ppt == "shaken"


def test_a_non_p256_certificate_key_is_refused():
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "p384")])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(8)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA384())
    )
    (parsed,) = credentials.load_certificates(cert.public_bytes(serialization.Encoding.DER))
    with pytest.raises(credentials.CredentialError, match="P-256"):
        credentials.signer_verifier(parsed)
    assert isinstance(jws.Es256Signer.generate().verifier(), jws.Es256Verifier)


def explicit(tag, body):
    return bytes([tag, len(body)]) + body


def ia5(text):
    return explicit(0x16, text.encode())


@pytest.mark.parametrize(
    "der",
    [
        b"",
        explicit(0x30, b""),  # SIZE (1..MAX)
        explicit(0x30, explicit(0x80, b"1234")),  # IMPLICIT [0]: the module is EXPLICIT TAGS
        explicit(0x30, explicit(0xA2, ia5("1" * 16))),  # TelephoneNumber is 1..15 characters
        explicit(0x30, explicit(0xA2, ia5("12a45"))),  # outside 0-9 # *
        explicit(0x30, explicit(0xA2, ia5(""))),
        explicit(0x30, explicit(0xA3, ia5("1"))),  # no such alternative
        explicit(0x30, explicit(0xA1, explicit(0x30, ia5("2125550100")))),  # no count
        explicit(0x30, explicit(0xA1, explicit(0x30, ia5("2125550100") + explicit(0x02, b"\x01")))),
        explicit(0x30, explicit(0xA1, explicit(0x30, ia5("10") + explicit(0x02, b"\x5b")))),
        explicit(0x30, explicit(0xA1, explicit(0x30, ia5("12*") + explicit(0x02, b"\x05")))),
        explicit(0x30, explicit(0xA2, ia5("1"))) + b"\x00",  # trailing byte
        explicit(0x04, b"x"),  # not a SEQUENCE
    ],
    ids=[
        "empty",
        "no-entries",
        "implicit-tag",
        "too-long",
        "bad-char",
        "empty-number",
        "unknown-alternative",
        "range-without-count",
        "count-below-2",
        "range-lengthens-number",
        "range-with-star",
        "trailing",
        "not-a-sequence",
    ],
)
def test_malformed_lists_are_refused(der):
    with pytest.raises(TNAuthListError):
        tnauth.parse_tn_auth_list(der)


def test_covers():
    entries = (TelephoneNumber("12155551212"), TelephoneNumberRange("2125550100", 100))
    assert tnauth.covers(entries, "12155551212") is True
    assert tnauth.covers(entries, "2125550100") is True
    assert tnauth.covers(entries, "2125550199") is True
    assert tnauth.covers(entries, "2125550200") is False  # one past the range
    assert tnauth.covers(entries, "12155551213") is False


def test_covers_reports_when_an_spc_makes_the_answer_unknowable_here():
    entries = (ServiceProviderCode("1234"), TelephoneNumber("12155551212"))
    assert tnauth.covers(entries, "12155551212") is True
    assert tnauth.covers(entries, "19995551212") is None


def test_load_certificates_refuses_garbage_and_empty_pem():
    with pytest.raises(credentials.CredentialError):
        credentials.load_certificates(b"\x00\x01\x02")
    with pytest.raises(credentials.CredentialError):
        credentials.load_certificates(
            b"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"
        )
