"""JWT Claim Constraints, RFC 8226 sec. 8 and RFC 9118.

Provenance: ``RFC9118_CERT`` is the certificate printed in RFC 9118 Figure 1 (copied through
rfclib), whose extension value Figure 2 dumps. Every other vector is built here from the ASN.1 of
RFC 9118 sec. 3 (``EXPLICIT TAGS``) with a four-line TLV helper that shares no code with asn1core.
"""

from __future__ import annotations

import pytest
from asn1core import pem
from asn1core.cert import parse_certificate

from shaken.claimconstraints import (
    ClaimConstraintsError,
    JwtClaimConstraints,
    check_claims,
    from_certificate,
    parse_constraints,
)

RFC9118_CERT = """-----BEGIN CERTIFICATE-----
MIICpzCCAk2gAwIBAgIUH7Zd3rQ5AsvOlzLnzUHhrVhDSlswCgYIKoZIzj0EAwIw
KTELMAkGA1UEBhMCVVMxGjAYBgNVBAMMEUJPR1VTIFNIQUtFTiBST09UMB4XDTIx
MDcxNTIxNTIxNVoXDTIyMDcxNTIxNTIxNVowbDELMAkGA1UEBhMCVVMxCzAJBgNV
BAgMAlZBMRAwDgYDVQQHDAdIZXJuZG9uMR4wHAYDVQQKDBVCb2d1cyBFeGFtcGxl
IFRlbGVjb20xDTALBgNVBAsMBFZvSVAxDzANBgNVBAMMBlNIQUtFTjBZMBMGByqG
SM49AgEGCCqGSM49AwEHA0IABNR6C6nBWRA/fXTglV03aXkXy8hx9oBttVLhsTZ1
IYVRBao4OZhVf/Xv1a3xLsZ6KfdhuylSeAKuCoSbVGojYDGjggEOMIIBCjAMBgNV
HRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUDlG3dxHyzKL/FZfS
PI7rpuueRbswHwYDVR0jBBgwFoAUlToKtrQeFrwwyXpMj1qu3TQEeoEwQgYJYIZI
AYb4QgENBDUWM1RoaXMgY2VydGlmaWNhdGUgY2Fubm90IGJlIHRydXN0ZWQgZm9y
IGFueSBwdXJwb3NlLjAWBggrBgEFBQcBGgQKMAigBhYEMTIzNDBOBggrBgEFBQcB
IQRCMECgDjAMFgpjb25maWRlbmNloSAwHjAcFgpjb25maWRlbmNlMA4MBGhpZ2gM
Bm1lZGl1baIMMAoWCHByaW9yaXR5MAoGCCqGSM49BAMCA0gAMEUCIQCbNR4QK1um
+0vq2CE1B1/W3avYeREsPi/7RKHffL+5eQIgarHot+X9Rl7SOyNBq5X5JyEMx0SQ
hRLkCY3Zoz2OCNQ=
-----END CERTIFICATE-----
"""

BASE = {"iat": 1, "orig": {"tn": "1"}, "dest": {"tn": ["2"]}}


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag, len(content)]) + content


def ia5(text: str) -> bytes:
    return tlv(0x16, text.encode())


def utf8(text: str) -> bytes:
    return tlv(0x0C, text.encode())


def seq(*items: bytes) -> bytes:
    return tlv(0x30, b"".join(items))


def names(*claims: str) -> bytes:
    return seq(*(ia5(c) for c in claims))


def values(claim: str, *permitted: str) -> bytes:
    return seq(seq(ia5(claim), seq(*(utf8(p) for p in permitted))))


def ext(*, include=None, permitted=None, exclude=None) -> bytes:
    parts = []
    if include is not None:
        parts.append(tlv(0xA0, names(*include)))
    if permitted is not None:
        parts.append(tlv(0xA1, values(*permitted)))
    if exclude is not None:
        parts.append(tlv(0xA2, names(*exclude)))
    return seq(*parts)


def test_claim_constraints():
    der = pem.certificates(RFC9118_CERT.encode())[0].der
    constraints = from_certificate(parse_certificate(der))
    # RFC 9118 sec. 5: confidence must be present, "high" or "medium", and priority excluded
    assert constraints == JwtClaimConstraints(
        must_include=("confidence",),
        permitted_values=(("confidence", ("high", "medium")),),
        must_exclude=("priority",),
        enhanced=True,
    )
    assert check_claims(constraints, BASE | {"confidence": "high"}) == ()
    assert check_claims(constraints, BASE | {"confidence": "medium"}) == ()
    assert check_claims(constraints, BASE)  # mustInclude
    assert check_claims(constraints, BASE | {"confidence": "low"})  # permittedValues
    assert check_claims(constraints, BASE | {"confidence": ["high"]})  # exact match, not a list
    assert check_claims(constraints, BASE | {"confidence": "high", "priority": "x"})  # mustExclude
    # the baseline claims are required whatever the extension says
    assert check_claims(None, {"iat": 1}) == ("dest must appear", "orig must appear")


def test_rfc8226_form_and_malformed_values():
    legacy = parse_constraints(ext(include=["a"], permitted=("b", "x", "y")), enhanced=False)
    assert legacy.must_include == ("a",)
    assert legacy.enhanced is False
    # permittedValues alone: an absent claim is fine (RFC 9118 sec. 4, second bullet)
    only = parse_constraints(ext(permitted=("b", "x")), enhanced=False)
    assert check_claims(only, BASE) == ()
    assert check_claims(only, BASE | {"b": "y"})
    bad = [
        seq(),  # WITH COMPONENTS: at least one field
        ext(include=["a"], exclude=["b"]),  # mustExclude does not exist in RFC 8226
        seq(tlv(0xA0, names()[:0] + seq())),  # an empty JWTClaimNames is SIZE (1..MAX)
        seq(tlv(0xA1, values("c", "v")), tlv(0xA0, names("a"))),  # out of order
        ext(include=["a"]) + b"\x00",  # trailing byte
        seq(tlv(0xA0, seq(utf8("a")))),  # JWTClaimName is an IA5String
        seq(tlv(0xA1, seq(seq(ia5("c"), seq())))),  # values is SIZE (1..MAX)
        seq(tlv(0x80, names("a"))),  # IMPLICIT where the module is EXPLICIT
    ]
    for der in bad:
        with pytest.raises(ClaimConstraintsError):
            parse_constraints(der, enhanced=False)
    with pytest.raises(ClaimConstraintsError):
        parse_constraints(seq(tlv(0xA0, seq(tlv(0x16, b"\xc3\xa9")))), enhanced=True)  # not ASCII


def test_baseline_claim_in_must_exclude_means_extension_is_ignored():
    # RFC 9118 sec. 3 item 3: treated as if the extension was not present
    constraints = parse_constraints(ext(include=["x"], exclude=["orig"]), enhanced=True)
    assert constraints.ignored
    assert check_claims(constraints, BASE) == ()
    assert check_claims(constraints, {"iat": 1})  # the baseline is still required
    # a baseline name in mustInclude is allowed but flagged: SHOULD NOT
    flagged = parse_constraints(ext(include=["iat", "x"]), enhanced=True)
    assert flagged.redundant_baseline == ("iat",)
