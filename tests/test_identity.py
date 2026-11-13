"""The Identity header field value (RFC 8224 sec. 4, with erratum 6499)."""

from __future__ import annotations

import pytest
from vectors import SHAKEN_TOKEN, X5U

from shaken import claims, identity

# RFC 8224 sec. 4.1.1 para 6, the compact example, with the folding backslashes removed.
RFC_COMPACT = (
    "..rq3pjT1hoRwakEGjHCnWSwUnshd0-zJ6F1VOgFWSjHBr8Qjpjlk-cpFYpFYsojNCpTzO3QfPOlckGaS6hEck7w;"
    "info=<https://biloxi.example.org/biloxi.cert>"
)
# Sec. 4.1.1 para 4, the full example, folding removed. Its payload carries a string "iat"
# (the same misprint as RFC 8225 sec. 7.1), so only its header grammar is used here.
RFC_FULL = (
    "eyJhbGciOiJFUzI1NiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cHM6Ly9jZXJ0LmV4YW1wbGUub3JnL3Bhc3Nwb3J0LmNlciJ9"
    ".eyJkZXN0Ijp7InVyaSI6WyJzaXA6YWxpY2VAZXhhbXBsZS5jb20iXX0sImlhdCI6IjE0NDMyMDgzNDUiLCJvcmlnIjp7InRuIjoiMTIxNTU1NTEyMTIifX0"
    ".rq3pjT1hoRwakEGjHCnWSwUnshd0-zJ6F1VOgFWSjHBr8Qjpjlk-cpFYpFYsojNCpTzO3QfPOlckGaS6hEck7w"
    ";info=<https://biloxi.example.org/biloxi.cert>"
)


def test_full_and_compact_forms():
    full = identity.parse_header(RFC_FULL)
    compact = identity.parse_header(RFC_COMPACT)
    assert full.compact is False
    assert compact.compact is True
    assert full.info == compact.info == "https://biloxi.example.org/biloxi.cert"
    assert compact.digest.startswith("..")
    assert full.digest.count(".") == 2
    assert full.alg is None
    assert full.ppt is None


def test_alg_default_applied_not_invented():
    parsed = identity.parse_header(RFC_COMPACT)
    assert parsed.alg is None
    assert parsed.effective_alg == "ES256"
    assert identity.parse_header(RFC_COMPACT + ";alg=ES256").alg == "ES256"


@pytest.mark.parametrize("char", ["+", "/", "=", " ", "é"])
def test_base64_alphabet_refused(char):
    """RFC 8224 erratum 6499: the digest is base64url, so '+' and '/' are not allowed."""
    digest = f"..abc{char}def"
    with pytest.raises(identity.IdentityError):
        identity.parse_header(f"{digest};info=<https://a.example/c>")


@pytest.mark.parametrize(
    "info",
    ["info=https://a.example/c", "info=<>", "info=<not a uri>", "info=<//a.example/c>", "info=<x"],
)
def test_info_requires_angle_brackets_and_absolute_uri(info):
    with pytest.raises(identity.IdentityError):
        identity.parse_header(f"..abc;{info}")


def test_info_is_required_and_not_repeated():
    with pytest.raises(identity.IdentityError, match="info"):
        identity.parse_header("..abc")
    with pytest.raises(identity.IdentityError, match="twice"):
        identity.parse_header("..abc;info=<https://a.example/c>;info=<https://b.example/c>")


def test_a_semicolon_inside_the_uri_does_not_split_it():
    parsed = identity.parse_header("..abc;info=<https://a.example/c;v=1>;ppt=shaken")
    assert parsed.info == "https://a.example/c;v=1"
    assert parsed.ppt == "shaken"


def test_digest_shape_full_or_compact_only():
    for digest in ("abc", "a.b", "a.b.c.d", ".b.c", "a..c", "..", "a.b."):
        with pytest.raises(identity.IdentityError):
            identity.parse_header(f"{digest};info=<https://a.example/c>")


def test_param_case_insensitivity_and_quoted_ppt():
    parsed = identity.parse_header('..abc;INFO=<https://a.example/c>;PPT="shaken";Alg=ES256')
    assert parsed.ppt == "shaken"
    assert parsed.alg == "ES256"


def test_whitespace_around_separators_is_tolerated():
    parsed = identity.parse_header("..abc ; info = <https://a.example/c> ; ppt = shaken")
    assert (parsed.info, parsed.ppt) == ("https://a.example/c", "shaken")


def test_unknown_params_preserved_in_order():
    parsed = identity.parse_header("..abc;info=<https://a.example/c>;x-b=2;flag;x-a=1")
    assert parsed.extra == (("x-b", "2"), ("flag", None), ("x-a", "1"))


def test_duplicate_alg_or_ppt_refused():
    for dup in (";alg=ES256;alg=ES256", ";ppt=shaken;ppt=shaken"):
        with pytest.raises(identity.IdentityError, match="twice"):
            identity.parse_header("..abc;info=<https://a.example/c>" + dup)


def test_multiple_identity_headers():
    parsed = identity.parse_all([RFC_COMPACT, RFC_FULL + ";ppt=shaken"])
    assert [p.compact for p in parsed] == [True, False]
    assert parsed[1].ppt == "shaken"


@pytest.mark.parametrize("ppt_quote", [False, True])
def test_roundtrip_build_parse(ppt_quote):
    built = identity.build_header(
        SHAKEN_TOKEN, X5U, alg="ES256", ppt="shaken", extra=[("x-n", "1")], quote_ppt=ppt_quote
    )
    parsed = identity.parse_header(built)
    assert parsed.digest == SHAKEN_TOKEN
    assert (parsed.info, parsed.alg, parsed.ppt, parsed.extra) == (
        X5U,
        "ES256",
        "shaken",
        (("x-n", "1"),),
    )
    assert ('ppt="shaken"' in built) is ppt_quote


@pytest.mark.parametrize(
    "kwargs",
    [
        {"info": "https://a.example/c\r\nHost: evil"},
        {"info": "https://a.example/c>;x=<"},
        {"info": "https://a.example/c", "ppt": "shaken\nX: y"},
        {"info": "https://a.example/c", "alg": "ES256;ppt=x"},
        {"info": "https://a.example/c", "extra": [("x\x00", "1")]},
    ],
)
def test_header_injection(kwargs):
    with pytest.raises(identity.IdentityError):
        identity.build_header("..abc", **kwargs)
    with pytest.raises(identity.IdentityError):
        identity.build_header("..abc\r\nX: y", "https://a.example/c")


def test_oversized_digest_refused():
    big = "." + "a" * identity.MAX_DIGEST_CHARS + ".c"
    with pytest.raises(identity.IdentityError):
        identity.parse_header(big + ";info=<https://a.example/c>")


def test_control_characters_refused():
    with pytest.raises(identity.IdentityError):
        identity.parse_header("..abc;info=<https://a.example/c>\r\n")
    with pytest.raises(identity.IdentityError):
        identity.parse_header("..abc;info=<https://a.example/c>\x00")


def test_header_must_mirror_the_identity_parameters():
    header = claims.shaken_header(X5U)
    good = identity.parse_header(identity.build_header("..abc", X5U, ppt="shaken"))
    identity.check_mirrors(good, header)
    for bad in (
        dict(header, x5u="https://evil.example/x.cer"),
        dict(header, alg="ES384"),
        dict(header, ppt="div"),
        {k: v for k, v in header.items() if k != "ppt"},
    ):
        with pytest.raises(identity.IdentityError):
            identity.check_mirrors(good, bad)
    no_ppt = identity.parse_header(identity.build_header("..abc", X5U))
    with pytest.raises(identity.IdentityError):
        identity.check_mirrors(no_ppt, header)  # header says shaken, Identity says nothing
