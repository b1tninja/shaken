"""PASSporT create, parse and verify (RFC 8225, RFC 8588, RFC 7515)."""

from __future__ import annotations

import json

import pytest
from vectors import SHAKEN_TOKEN, TEST_KEY_PEM, X5U

from shaken import claims, jws, passport


@pytest.fixture(scope="module")
def signer():
    return jws.Es256Signer.from_pem(TEST_KEY_PEM.encode())


def good_claims():
    return claims.shaken_claims(
        "+1 (215) 555-1212",
        ["12155550131"],
        iat=1443208345,
        attest="A",
        origid="123e4567-e89b-12d3-a456-426655440000",
    )


def test_deterministic_json_rules():
    obj = {"b": {"z": [3, {"y": True, "x": None}], "a": False}, "a": "é", "A": 0}
    assert passport.canonical_json(obj) == (
        '{"A":0,"a":"é","b":{"a":false,"z":[3,{"x":null,"y":true}]}}'.encode()
    )


def test_canonical_json_orders_by_code_point():
    # U+1F600 sorts after U+FF5E by code point, though UTF-16 order would put it first.
    tilde, smile = chr(0xFF5E), chr(0x1F600)
    assert passport.canonical_json({smile: 1, tilde: 2}) == (
        f'{{"{tilde}":2,"{smile}":1}}'.encode()
    )


@pytest.mark.parametrize(
    "bad", [{"x": 1.0}, {"x": 1.5}, {1: "a"}, {"x": {"y": object()}}, {"x": float("nan")}]
)
def test_canonical_json_refuses_non_integers_and_non_json(bad):
    with pytest.raises(passport.PassportError):
        passport.canonical_json(bad)


def test_canonical_json_refuses_lone_surrogates():
    with pytest.raises(passport.PassportError):
        passport.canonical_json({"x": "\ud800"})


def test_signing_input_matches_manual_composition():
    header = claims.shaken_header(X5U)
    payload = good_claims()
    parts = (passport.canonical_json(header), passport.canonical_json(payload))
    expected = ".".join(jws.b64url_encode(part) for part in parts).encode("ascii")
    assert passport.signing_input(header, payload) == expected


def test_create_matches_the_pinned_vector(signer):
    """tests/vectors.py SHAKEN_TOKEN came from tools/make_vectors.py; ES256 here is deterministic."""
    assert passport.create(good_claims(), claims.shaken_header(X5U), signer) == SHAKEN_TOKEN


def test_pinned_vector_verifies_with_an_independent_library(signer):
    jwt = pytest.importorskip("jwt")
    decoded = jwt.decode(
        SHAKEN_TOKEN,
        signer.public_spki_pem(),
        algorithms=["ES256"],
        options={"verify_iat": False},
    )
    assert decoded == good_claims()


def test_verify_accepts_the_pinned_vector(signer):
    parsed = passport.verify(SHAKEN_TOKEN, signer.verifier())
    assert parsed.payload == good_claims()
    assert parsed.header == claims.shaken_header(X5U)
    assert parsed.canonical is True
    assert parsed.ppt == "shaken"


def test_verify_rejects_a_changed_payload_and_a_changed_key(signer):
    head, _body, sig = SHAKEN_TOKEN.split(".")
    other = claims.shaken_claims(
        "12155551212",
        ["12155550132"],
        iat=1443208345,
        attest="A",
        origid="123e4567-e89b-12d3-a456-426655440000",
    )
    forged = ".".join([head, jws.b64url_encode(passport.canonical_json(other)), sig])
    with pytest.raises(passport.InvalidSignature):
        passport.verify(forged, signer.verifier())
    with pytest.raises(passport.InvalidSignature):
        passport.verify(SHAKEN_TOKEN, jws.Es256Signer.generate().verifier())


def test_verify_rejects_a_flipped_signature_bit(signer):
    head, body, sig = SHAKEN_TOKEN.split(".")
    raw = bytearray(jws.b64url_decode(sig))
    raw[10] ^= 0x01
    forged = ".".join([head, body, jws.b64url_encode(bytes(raw))])
    with pytest.raises(passport.InvalidSignature):
        passport.verify(forged, signer.verifier())


def test_create_and_verify_round_trip_with_a_fresh_key():
    key = jws.Es256Signer.generate()
    token = passport.create(good_claims(), claims.shaken_header(X5U), key)
    assert passport.verify(token, key.verifier()).payload == good_claims()


def test_create_refuses_bad_header_or_claims(signer):
    header = claims.shaken_header(X5U)
    broken_headers = (
        dict(header, alg="HS256"),
        dict(header, typ="JWT"),
        {k: v for k, v in header.items() if k != "x5u"},
    )
    for broken in broken_headers:
        with pytest.raises(passport.PassportError):
            passport.create(good_claims(), broken, signer)
    bad = good_claims()
    bad["iat"] = "1443208345"
    with pytest.raises(passport.PassportError, match="iat"):
        passport.create(bad, header, signer)


def test_create_refuses_a_signer_that_returns_the_wrong_length():
    class Short:
        def sign(self, signing_input):
            return b"\x01" * 63

    with pytest.raises(passport.PassportError, match="64"):
        passport.create(good_claims(), claims.shaken_header(X5U), Short())


def swap(token, index, value):
    parts = token.split(".")
    parts[index] = value
    return ".".join(parts)


def test_parse_refuses_malformed_tokens():
    head, body, sig = SHAKEN_TOKEN.split(".")
    cases = [
        SHAKEN_TOKEN + ".AAAA",  # four parts
        f"{head}.{body}",  # two parts
        f"..{sig}",  # compact form given to the full-form parser
        swap(SHAKEN_TOKEN, 1, body + "+/"),  # standard base64 alphabet
        swap(SHAKEN_TOKEN, 2, sig + "="),  # padding
        swap(SHAKEN_TOKEN, 2, jws.b64url_encode(b"\x01" * 63)),  # short signature
        "a" * (passport.MAX_TOKEN_CHARS + 1),  # oversized
    ]
    for token in cases:
        with pytest.raises(passport.PassportError):
            passport.parse(token)


def encode_parts(header, payload):
    return ".".join(
        [
            jws.b64url_encode(json.dumps(header).encode()),
            jws.b64url_encode(json.dumps(payload).encode()),
            jws.b64url_encode(b"\x01" * 64),
        ]
    )


def test_typ_alg_ppt_checked():
    header = claims.shaken_header(X5U)
    payload = good_claims()
    for broken in (
        dict(header, typ="JWT"),
        dict(header, alg="none"),
        dict(header, alg="HS256"),
        dict(header, ppt="div"),
        dict(header, ppt=5),
        dict(header, crit=["exp"]),
        {k: v for k, v in header.items() if k != "x5u"},
    ):
        with pytest.raises(passport.PassportError):
            passport.parse(encode_parts(broken, payload))
    assert passport.parse(encode_parts(header, payload)).payload == payload


def test_unsupported_ppt_is_refused_unless_the_caller_supports_it():
    header = {"alg": "ES256", "ppt": "div", "typ": "passport", "x5u": X5U}
    payload = {"dest": {"tn": ["12155550131"]}, "iat": 1, "orig": {"tn": "12155550121"}}
    with pytest.raises(passport.PassportError, match="ppt"):
        passport.parse(encode_parts(header, payload))
    assert passport.parse(encode_parts(header, payload), supported_ppt=frozenset({"div"}))


def test_payload_number_not_string_iat_and_dest_not_array_of_objects():
    header = claims.shaken_header(X5U)
    for key, value in (
        ("iat", "1443208345"),
        ("iat", 1443208345.0),
        ("dest", [{"tn": "12155550131"}]),
    ):
        with pytest.raises(passport.PassportError):
            passport.parse(encode_parts(header, dict(good_claims(), **{key: value})))


def test_duplicate_members_and_nan_and_non_utf8_are_refused():
    header = claims.shaken_header(X5U)
    sig = jws.b64url_encode(b"\x01" * 64)
    head = jws.b64url_encode(json.dumps(header).encode())
    for raw in (
        b'{"iat":1,"iat":2,"orig":{"tn":"1"},"dest":{"tn":["2"]}}',
        b'{"iat":NaN,"orig":{"tn":"1"},"dest":{"tn":["2"]}}',
        b"\xff\xfe",
        b"[1]",
        b"[" * 5000,
    ):
        with pytest.raises(passport.PassportError):
            passport.parse(f"{head}.{jws.b64url_encode(raw)}.{sig}")


def test_parse_reports_whether_the_wire_form_was_canonical(signer):
    header = claims.shaken_header(X5U)
    payload = good_claims()
    spaced = ".".join(
        [
            jws.b64url_encode(json.dumps(header, sort_keys=True).encode()),  # has spaces
            jws.b64url_encode(passport.canonical_json(payload)),
        ]
    )
    token = spaced + "." + jws.b64url_encode(signer.sign(spaced.encode()))
    parsed = passport.verify(token, signer.verifier())  # a verifier checks what was sent
    assert parsed.canonical is False


def test_compact_form_round_trip(signer):
    compact = passport.to_compact(SHAKEN_TOKEN)
    header = claims.shaken_header(X5U)
    assert compact == ".." + SHAKEN_TOKEN.split(".")[2]
    passport.verify_compact(compact, header, good_claims(), signer.verifier())
    other = dict(good_claims(), attest="B")
    with pytest.raises(passport.InvalidSignature):
        passport.verify_compact(compact, header, other, signer.verifier())
    with pytest.raises(passport.PassportError):
        passport.verify_compact("x" + compact, header, good_claims(), signer.verifier())
