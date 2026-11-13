"""SHAKEN claims (RFC 8588) and the base claims shape (RFC 8225 sec. 5)."""

from __future__ import annotations

import uuid

import pytest

from shaken import claims, numbers, passport

ORIGID = "123e4567-e89b-12d3-a456-426655440000"


def build(**override):
    args = {
        "orig_tn": "12155550121",
        "dest_tn": ["12155550131"],
        "iat": 1443208345,
        "attest": "A",
        "origid": ORIGID,
    }
    args.update(override)
    return claims.shaken_claims(**args)


def test_rfc8588_section_6_payload_with_errata_applied():
    # RFC 8588 section 6 with erratum 6656 (iat a number) and the commas the printed text lacks.
    expected = {
        "attest": "A",
        "dest": {"tn": ["12155550131"]},
        "iat": 1443208345,
        "orig": {"tn": "12155550121"},
        "origid": ORIGID,
    }
    assert build() == expected
    assert passport.canonical_json(build()) == (
        b'{"attest":"A","dest":{"tn":["12155550131"]},"iat":1443208345,'
        b'"orig":{"tn":"12155550121"},"origid":"123e4567-e89b-12d3-a456-426655440000"}'
    )


def test_header_key_order():
    header = claims.shaken_header("https://cert.example.org/passport.cer")
    assert list(header) == ["alg", "ppt", "typ", "x5u"]
    assert passport.canonical_json(header) == (
        b'{"alg":"ES256","ppt":"shaken","typ":"passport",'
        b'"x5u":"https://cert.example.org/passport.cer"}'
    )


def test_dest_shape_is_object_with_arrays():
    """RFC 8224 erratum 5715: an object of arrays, never an array of objects."""
    dest = build()["dest"]
    assert isinstance(dest, dict)
    assert dest == {"tn": ["12155550131"]}
    bad = build()
    bad["dest"] = [{"tn": "12155550131"}]
    with pytest.raises(claims.ClaimsError, match="dest"):
        claims.validate_shaken_claims(bad)


def test_dest_sorted_lexicographically_with_tn_before_uri():
    built = build(
        dest_tn=["12155550199", "12155550131"],
        dest_uri=["sip:bob@example.net", "sip:alice@example.com"],
    )
    assert built["dest"] == {
        "tn": ["12155550131", "12155550199"],
        "uri": ["sip:alice@example.com", "sip:bob@example.net"],
    }
    assert list(built["dest"]) == ["tn", "uri"]


@pytest.mark.parametrize("iat", ["1443208345", 1443208345.0, True, None, -1])
def test_iat_must_be_a_non_negative_integer(iat):
    with pytest.raises(claims.ClaimsError, match="iat"):
        build(iat=iat)


@pytest.mark.parametrize("attest", ["a", "D", "", "AB", None])
def test_attest_values(attest):
    with pytest.raises(claims.ClaimsError, match="attest"):
        build(attest=attest)


def test_attest_levels_are_a_b_c():
    assert {level: build(attest=level)["attest"] for level in "ABC"} == {
        "A": "A",
        "B": "B",
        "C": "C",
    }
    assert set(claims.ATTEST_LEVELS) == {"A", "B", "C"}


def test_origid_is_a_uuid_string():
    assert build(origid=uuid.UUID(ORIGID))["origid"] == ORIGID
    assert build(origid=ORIGID.upper())["origid"] == ORIGID
    with pytest.raises(claims.ClaimsError, match="origid"):
        build(origid="not-a-uuid")


def test_tn_is_canonicalised():
    built = build(orig_tn="+1 (215) 555-0121", dest_tn=["+1-215-555-0131"])
    assert built["orig"] == {"tn": "12155550121"}
    assert built["dest"] == {"tn": ["12155550131"]}


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("+12155551212", "12155551212"),
        ("(215) 555-1212", "2155551212"),
        ("*67#", "*67#"),
        ("911", "911"),
    ],
)
def test_tn_canonical_digits_only(text, expected):
    assert numbers.canonicalize_tn(text) == expected
    assert numbers.is_tn_spec(expected)


def test_tn_with_nothing_left_is_refused():
    with pytest.raises(ValueError, match="nothing to canonicalise"):
        numbers.canonicalize_tn("+-() ")
    assert not numbers.is_tn_spec("")
    assert not numbers.is_tn_spec("+1215")
    assert not numbers.is_tn_spec("١٢")  # Arabic-Indic digits are not tn-char


def test_validate_claims_orig_has_exactly_one_identity():
    base = build()
    for orig in ({}, {"tn": "1", "uri": "sip:a@b"}, {"mail": "a"}, "12155550121", {"tn": ""}):
        broken = dict(base, orig=orig)
        with pytest.raises(claims.ClaimsError, match="orig"):
            claims.validate_claims(broken)


def test_validate_claims_requires_iat():
    base = build()
    del base["iat"]
    with pytest.raises(claims.ClaimsError, match="iat"):
        claims.validate_claims(base)
