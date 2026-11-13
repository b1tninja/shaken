"""Measured findings about the RFCs' own examples. Each test pins a fact about the published text.

If one of these ever fails, the RFC Editor corrected the document (or rfclib's text changed):
read the new text, then update the finding and the ROADMAP.md row that cites it. None of these
examples is used as a positive test vector anywhere in this project.
"""

from __future__ import annotations

import base64
import json

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from shaken import passport

# RFC 8225 Appendix A (lines 1261-1381 of the text rfclib serves).
APPENDIX_A_HEADER = (
    "eyJhbGciOiJFUzI1NiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cHM6Ly9j"
    "ZXJ0LmV4YW1wbGUub3JnL3Bhc3Nwb3J0LmNlciJ9"
)
APPENDIX_A_PAYLOAD = (
    "eyJkZXN0Ijp7InVyaSI6WyJzaXA6YWxpY2VAZXhhbXBsZS5jb20iXX0sImlhdCI"
    "6MTQ3MTM3NTQxOCwib3JpZyI6eyJ0biI6IjEyMTU1NTUxMjEyIn19"
)
APPENDIX_A_SIGNATURE = (
    "VLBCIVDCaeK6M4hLJb6SHQvacAQVvoiiEOWQ_iUkqk79UD81fHQ0E1b3_GluIkba7UWYRM47ZbNFdOJquE35cw"
)
APPENDIX_A_1_PRIVATE_KEY = b"""-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgi7q2TZvN9VDFg8Vy
qCP06bETrR2v8MRvr89rn4i+UAahRANCAAQWfaj1HUETpoNCrOtp9KA8o0V79IuW
ARKt9C1cFPkyd3FBP4SeiNZxQhDrD0tdBHls3/wFe8++K2FrPyQF9vuh
-----END PRIVATE KEY-----
"""
APPENDIX_A_2_PUBLIC_KEY = b"""-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8HNbQd/TmvCKwPKHkMF9fScavGeH
78YTU8qLS8I5HLHSSmlATLcslQMhNC/OhlWBYC626nIlo7XeebYS7Sb37g==
-----END PUBLIC KEY-----
"""


def _b64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _verifies(public_key: ec.EllipticCurvePublicKey) -> bool:
    raw = _b64(APPENDIX_A_SIGNATURE)
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    message = f"{APPENDIX_A_HEADER}.{APPENDIX_A_PAYLOAD}".encode("ascii")
    try:
        public_key.verify(der, message, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


def test_rfc8225_appendix_a_keys_are_not_a_pair():
    private = serialization.load_pem_private_key(APPENDIX_A_1_PRIVATE_KEY, None)
    public = serialization.load_pem_public_key(APPENDIX_A_2_PUBLIC_KEY)
    assert isinstance(private, ec.EllipticCurvePrivateKey)
    assert isinstance(public, ec.EllipticCurvePublicKey)
    assert private.public_key().public_numbers() != public.public_numbers()


def test_rfc8225_appendix_a_signature_verifies_under_neither_printed_key():
    private = serialization.load_pem_private_key(APPENDIX_A_1_PRIVATE_KEY, None)
    public = serialization.load_pem_public_key(APPENDIX_A_2_PUBLIC_KEY)
    assert isinstance(private, ec.EllipticCurvePrivateKey)
    assert isinstance(public, ec.EllipticCurvePublicKey)
    assert len(_b64(APPENDIX_A_SIGNATURE)) == 64
    assert not _verifies(private.public_key())
    assert not _verifies(public)


def test_rfc8225_appendix_a_encoding_steps_are_correct():
    """The encoding is right even though the signature is not: the vector's use is only this."""
    header = {"alg": "ES256", "typ": "passport", "x5u": "https://cert.example.org/passport.cer"}
    payload = {
        "dest": {"uri": ["sip:alice@example.com"]},
        "iat": 1471375418,
        "orig": {"tn": "12155551212"},
    }
    assert passport.signing_input(header, payload) == (
        f"{APPENDIX_A_HEADER}.{APPENDIX_A_PAYLOAD}".encode("ascii")
    )


# RFC 8225 section 9.1 para 15, the printed "final constructed" form, lines joined.
SECTION_9_1_PRINTED = (
    '{"dest":{"uri":["sip:alice@example.com"],"iat":1443208345,"mky":'
    '[{"alg":"sha-256","dig":"021ACC5427ABEB9C533F3E4B652E7D463F5442CD5'
    '4F17A03A27DF9B07F4619B2"},{"alg":"sha-256","dig":"4AADB9B13F82183B5'
    '40212DF3E5D496B19E57CAB3E4B652E7D463F5442CD54F1"}],'
    '"orig":{"tn":"12155551212"}}'
)


def test_rfc8225_section_9_1_printed_result_is_not_valid_json():
    with pytest.raises(json.JSONDecodeError):
        json.loads(SECTION_9_1_PRINTED)


def test_rfc8225_section_9_1_with_the_missing_brace_matches_canonical_json():
    payload = {
        "dest": {"uri": ["sip:alice@example.com"]},
        "orig": {"tn": "12155551212"},
        "iat": 1443208345,
        "mky": [
            {
                "dig": "021ACC5427ABEB9C533F3E4B652E7D463F5442CD54F17A03A27DF9B07F4619B2",
                "alg": "sha-256",
            },
            {
                "alg": "sha-256",
                "dig": "4AADB9B13F82183B540212DF3E5D496B19E57CAB3E4B652E7D463F5442CD54F1",
            },
        ],
    }
    repaired = SECTION_9_1_PRINTED.replace(
        '["sip:alice@example.com"],', '["sip:alice@example.com"]},'
    )
    assert passport.canonical_json(payload).decode() == repaired


# RFC 8225 section 7.1 payload (lines joined): decodes with "iat" as a string (erratum 5985).
SECTION_7_1_PAYLOAD = (
    "eyJkZXN0Ijp7InVyaSI6WyJzaXA6YWxpY2VAZXhhbXBsZS5jb20iXX0sImlhdCI"
    "6IjE0NDMyMDgzNDUiLCJvcmlnIjp7InRuIjoiMTIxNTU1NTEyMTIifX0"
)


def test_rfc8225_section_7_1_example_has_a_string_iat():
    assert json.loads(_b64(SECTION_7_1_PAYLOAD))["iat"] == "1443208345"


def test_a_string_iat_is_refused_by_parse():
    header = "eyJhbGciOiJFUzI1NiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cHM6Ly9jZXJ0LmV4YW1wbGUub3JnL3Bhc3Nwb3J0LmNlciJ9"
    token = f"{header}.{SECTION_7_1_PAYLOAD}.{APPENDIX_A_SIGNATURE}"
    with pytest.raises(passport.PassportError, match="iat"):
        passport.parse(token)


# RFC 8588 section 6, as printed: no commas after "attest" and "dest", and a string "iat".
RFC8588_SECTION_6_PRINTED = """{
      "attest":"A"
      "dest":{"tn":["12155550131"]}
      "iat":"1443208345",
      "orig":{"tn":"12155550121"},
      "origid":"123e4567-e89b-12d3-a456-426655440000"
   }"""


def test_rfc8588_section_6_example_is_not_valid_json():
    with pytest.raises(json.JSONDecodeError):
        json.loads(RFC8588_SECTION_6_PRINTED)


# RFC 8225 section 7.1 (and RFC 8224 section 4.1.1): the same header, the string-iat payload above
# and this signature.
SECTION_7_1_SIGNATURE = (
    "rq3pjT1hoRwakEGjHCnWSwUnshd0-zJ6F1VOgFWSjHBr8Qjpjlk-cpFYpFYsojNCpTzO3QfPOlckGaS6hEck7w"
)


def test_rfc8225_section_7_1_signature_does_verify_under_the_a2_key_for_its_string_iat_payload():
    """Measured: the A.2 public key belongs to the section 7.1 example, not to Appendix A.

    The signature covers the payload with the string iat, so erratum 5985's corrected payload
    would no longer match it: the example cannot be both fixed and signed as printed.
    """
    public = serialization.load_pem_public_key(APPENDIX_A_2_PUBLIC_KEY)
    assert isinstance(public, ec.EllipticCurvePublicKey)
    token = f"{APPENDIX_A_HEADER}.{SECTION_7_1_PAYLOAD}.{SECTION_7_1_SIGNATURE}"
    parsed_signature = _b64(SECTION_7_1_SIGNATURE)
    from shaken import jws

    assert jws.Es256Verifier(public).verify(
        token.rsplit(".", 1)[0].encode("ascii"), parsed_signature
    )
    corrected = (
        "eyJkZXN0Ijp7InVyaSI6WyJzaXA6YWxpY2VAZXhhbXBsZS5jb20iXX0sImlhdCI6MTQ0MzIwODM0NSwib3Jp"
        "ZyI6eyJ0biI6IjEyMTU1NTUxMjEyIn19"
    )
    assert json.loads(_b64(corrected))["iat"] == 1443208345
    assert not jws.Es256Verifier(public).verify(
        f"{APPENDIX_A_HEADER}.{corrected}".encode("ascii"), parsed_signature
    )
