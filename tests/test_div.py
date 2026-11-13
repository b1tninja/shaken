"""Diverted calls, RFC 8946: claims, shape checks and chain linking.

Provenance: ``DIV_TOKEN`` and ``OPT_TOKEN`` are printed in RFC 8946 sec. 3 and sec. 5 (copied
through rfclib); ``APPENDIX_A_PUBLIC_KEY`` is its Appendix A. The chain tests use claims sets
written here from the sec. 3 and sec. 4.2 rules. None of the RFC's printed tokens is used as a
positive vector for ``div_claims``: the examples carry a typo (see the finding test).
"""

# ruff: noqa: S105

from __future__ import annotations

import base64
import json

import pytest

from shaken import passport
from shaken.claims import ClaimsError
from shaken.div import (
    ChainError,
    div_claims,
    div_header,
    div_o_claims,
    link_chains,
    validate_div_claims,
)
from shaken.jws import Es256Verifier

APPENDIX_A_PUBLIC_KEY = b"""-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmzGM1VsO+3IqbMF54rQMaYKQftO4
hUYm9wv5wutLgEd9FsiTy3+4+Wa2O7pffOXPC0QzO+yD8hGEXGP/2mZo6w==
-----END PUBLIC KEY-----
"""
DIV_TOKEN = (
    "eyJhbGciOiJFUzI1NiIsInBwdCI6ImRpdiIsInR5cCI6InBhc3Nwb3J0IiwieDV1Ij"
    "oiaHR0cHM6Ly93d3cuZXhhbXBsZS5jb20vY2VydC5jZXIifQ.eyJkZXN0Ijp7InRuI"
    "jpbIjEyMTU1NTUxMjE0Il19LCJkaXYiOnsidG4iOiIxMjE1NTU1NTEyMTMifSwiaWF"
    "0IjoxNDQzMjA4MzQ1LCJvcmlnIjp7InRuIjoiMTIxNTU1NTEyMTIifX0.xBHWipDEE"
    "J8a6TsdX6xUXAnblsFiGUiAxwLiv0HLC9IICj6eG9jQd6WzeSSjHRBwxmChHhVIiMT"
    "SqIlk3yCNkg"
)
OPT_TOKEN = (
    "eyJhbGciOiJFUzI1NiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cHM6Ly93d3cuZXhhbXBsZS5jb20vY2VydC5jZXIifQ."
    "eyJkZXN0Ijp7InRuIjpbIjEyMTU1NTUxMjEzIl19LCJpYXQiOjE0NDMyMDgzNDUsIm9yaWciOnsidG4iOiIxMjE1NTUxMjEyIn19."
    "1bEzkzcNbKvgz4QoMx0_DJ2T8qFMDC1sPqHPXl1WvbauzRJRvYlZqQ0qgGTlS8tJ_wXjVe07Z3wvDrdApHhhYw"
)

ORIGINAL = {
    "dest": {"tn": ["12155551213", "19995551234"]},
    "iat": 1443208345,
    "orig": {"tn": "12155551212"},
}


def b64(part: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def test_div_claims_follow_rfc_8946_section_3():
    claims = div_claims(
        ORIGINAL, diverted_from=("tn", "12155551213"), new_dest={"tn": ["12155551214"]}
    )
    assert claims == {
        "dest": {"tn": ["12155551214"]},
        "div": {"tn": "12155551213"},
        "iat": 1443208345,
        "orig": {"tn": "12155551212"},
    }
    # sec. 3 para 13: one identifier of a multi-valued dest; the other one gives another PASSporT
    other = div_claims(ORIGINAL, diverted_from=("tn", "19995551234"), new_dest={"tn": ["1"]})
    assert other["div"] == {"tn": "19995551234"}
    # sec. 3 para 6: the iat may be replaced when the signalling date changed
    assert (
        div_claims(ORIGINAL, diverted_from=("tn", "12155551213"), new_dest={"tn": ["1"]}, iat=5)[
            "iat"
        ]
        == 5
    )
    assert div_header("https://example.org/c.cer") == {
        "alg": "ES256",
        "ppt": "div",
        "typ": "passport",
        "x5u": "https://example.org/c.cer",
    }
    with pytest.raises(ClaimsError):  # not one of the original dest identifiers
        div_claims(ORIGINAL, diverted_from=("tn", "1"), new_dest={"tn": ["12155551214"]})
    with pytest.raises(ClaimsError):  # sec. 3 para 2: dest unchanged, no div PASSporT
        div_claims(ORIGINAL, diverted_from=("tn", "12155551213"), new_dest=ORIGINAL["dest"])


def test_div_shape_rules_and_div_o():
    good = div_claims(ORIGINAL, diverted_from=("tn", "12155551213"), new_dest={"tn": ["1"]})
    validate_div_claims(good, "div")
    for bad in (
        good | {"opt": OPT_TOKEN},  # sec. 3 para 16
        good | {"attest": "A"},  # no other claims
        good | {"div": {}},
        good | {"div": {"tn": "1", "uri": "sip:a@b"}},
        {k: v for k, v in good.items() if k != "div"},
    ):
        with pytest.raises(ClaimsError):
            validate_div_claims(bad, "div")
    validate_div_claims(good | {"div": {"tn": "1", "history-info": "x"}}, "div")  # sec. 3 para 14
    claims = div_o_claims(
        ORIGINAL, OPT_TOKEN, diverted_from=("tn", "12155551213"), new_dest={"tn": ["1"]}
    )
    assert claims["opt"] == OPT_TOKEN
    with pytest.raises(ClaimsError):  # sec. 6 para 2: a compact form is refused
        div_o_claims(ORIGINAL, "a..c", diverted_from=("tn", "12155551213"), new_dest={"tn": ["1"]})
    with pytest.raises(ClaimsError):
        validate_div_claims(good, "div-o")  # div-o MUST carry opt
    assert div_header("https://x.example/c", original=True)["ppt"] == "div-o"


def test_chains_link_div_passports_to_their_originals():
    first = div_claims(
        ORIGINAL, diverted_from=("tn", "12155551213"), new_dest={"tn": ["12155551214"]}
    )
    second = div_claims(
        first, diverted_from=("tn", "12155551214"), new_dest={"tn": ["12155551215"]}
    )
    # header order carries no meaning (sec. 3 para 15): any permutation links the same way
    for order in ([ORIGINAL, first, second], [second, ORIGINAL, first], [first, second, ORIGINAL]):
        (chain,) = link_chains(order)
        assert chain.claims == (second, first, ORIGINAL)
        assert chain.outermost_dest == {"tn": ["12155551215"]}
        assert chain.orig == {"tn": "12155551212"}
    # a div whose original is missing cannot complete (sec. 4.2 para 2)
    with pytest.raises(ChainError):
        link_chains([second, ORIGINAL])
    with pytest.raises(ChainError):
        link_chains([ORIGINAL])  # nothing to link
    # an earlier PASSporT with the right dest but another orig is not a parent (step 3)
    stranger = ORIGINAL | {"orig": {"tn": "19995550000"}}
    with pytest.raises(ChainError):
        link_chains([stranger, first])
    # one div retargeting from two innermost PASSporTs gives two chains (step 5)
    twin = ORIGINAL | {"iat": 1443208999}
    assert len(link_chains([ORIGINAL, twin, first])) == 2


def test_rfc8946_example_findings():
    """Measured facts about the printed examples; if one fails the RFC text changed."""
    header, payload, _ = DIV_TOKEN.split(".")
    claims = b64(payload)
    assert b64(header)["ppt"] == "div"
    # sec. 3: the diverted-from number is 12155551213 (11 digits), the example prints 12 digits
    assert claims["div"] == {"tn": "121555551213"}
    assert claims["dest"] == {"tn": ["12155551214"]}
    assert claims["div"]["tn"] != "12155551213"
    # the div token's signature does verify under the Appendix A key, typo included
    verifier = Es256Verifier.from_pem(APPENDIX_A_PUBLIC_KEY)
    passport.verify(DIV_TOKEN, verifier, supported_ppt=frozenset({"div"}))
    # the sec. 5 "opt" token (the original PASSporT) does not verify under that key
    with pytest.raises(passport.InvalidSignature):
        passport.verify(OPT_TOKEN, verifier, supported_ppt=frozenset({None}))
