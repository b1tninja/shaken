"""Chain validation to an STI trust anchor through pkix (RFC 8226 sec. 4, RFC 5280 sec. 6).

Provenance: every certificate is minted here with ``cryptography`` and carries a genuine ECDSA
P-256 signature by its issuer (root -> intermediate -> signer), so the signature check is real, not
bypassed. Names, validity and the cA bit are varied one at a time. ``TNAuthList`` is not needed
here and is not set.
"""

from __future__ import annotations

import datetime

import pytest
from asn1core.cert import parse_certificate
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from shaken.credentials import CredentialError, validate_chain

NOW = datetime.datetime(2026, 6, 1, tzinfo=datetime.UTC)


def key():
    return ec.generate_private_key(ec.SECP256R1())


def name(common_name):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def mint(subject, issuer, subject_key, issuer_key, *, ca, days=(-30, 365), key_for_sig=None):
    builder = (
        x509.CertificateBuilder()
        .subject_name(name(subject))
        .issuer_name(name(issuer))
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW + datetime.timedelta(days=days[0]))
        .not_valid_after(NOW + datetime.timedelta(days=days[1]))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    der = builder.sign(key_for_sig or issuer_key, hashes.SHA256()).public_bytes(
        serialization.Encoding.DER
    )
    return parse_certificate(der)


ROOT_KEY, MID_KEY, SIGNER_KEY = key(), key(), key()
ROOT = mint("STI Root", "STI Root", ROOT_KEY, ROOT_KEY, ca=True)
MID = mint("STI Intermediate", "STI Root", MID_KEY, ROOT_KEY, ca=True)
SIGNER = mint("Signer", "STI Intermediate", SIGNER_KEY, MID_KEY, ca=False)


def test_chain_to_anchor():
    result = validate_chain(SIGNER, (MID,), (ROOT,), NOW)
    assert result.path == (SIGNER, MID)
    assert result.anchor is ROOT
    assert any("signature" in item for item in result.checked)
    # the signer issued directly by the anchor
    direct = mint("Direct", "STI Root", SIGNER_KEY, ROOT_KEY, ca=False)
    assert validate_chain(direct, (), (ROOT,), NOW).path == (direct,)
    # the pool order and unrelated certificates do not matter
    other = mint("Other", "Other Root", key(), key(), ca=True)
    assert validate_chain(SIGNER, (other, MID), (ROOT,), NOW).path == (SIGNER, MID)


def test_chain_refusals():
    with pytest.raises(CredentialError, match="no certification path"):
        validate_chain(SIGNER, (), (ROOT,), NOW)  # intermediate not supplied
    stranger = mint("Stranger Root", "Stranger Root", key(), key(), ca=True)
    with pytest.raises(CredentialError, match="no certification path"):
        validate_chain(SIGNER, (MID,), (stranger,), NOW)  # not pinned
    # right names, wrong key: the signature check must bite
    forged = mint("STI Intermediate", "STI Root", MID_KEY, ROOT_KEY, ca=True, key_for_sig=key())
    with pytest.raises(CredentialError, match="signature"):
        validate_chain(SIGNER, (forged,), (ROOT,), NOW)
    # a certificate that is not a CA cannot issue
    plain = mint("STI Intermediate", "STI Root", MID_KEY, ROOT_KEY, ca=False)
    with pytest.raises(CredentialError):
        validate_chain(SIGNER, (plain,), (ROOT,), NOW)
    # validity is judged at ``at``, on every certificate and the anchor
    later = NOW + datetime.timedelta(days=400)
    with pytest.raises(CredentialError, match="not valid"):
        validate_chain(SIGNER, (MID,), (ROOT,), later)
    earlier = NOW - datetime.timedelta(days=60)
    with pytest.raises(CredentialError, match="not valid"):
        validate_chain(SIGNER, (MID,), (ROOT,), earlier)
    short = mint("Signer", "STI Intermediate", SIGNER_KEY, MID_KEY, ca=False, days=(-30, 10))
    with pytest.raises(CredentialError, match="not valid"):
        validate_chain(short, (MID,), (ROOT,), NOW + datetime.timedelta(days=11))
