"""The registered claims and the SHAKEN extension set (RFC 8225, RFC 8588).

A claims set is a plain ``dict``; ``passport.canonical_json`` turns it into bytes. The builder
here makes the shape RFC 8225 sec. 5.2.1 shows (and RFC 8224 erratum 5715 confirms): ``dest`` is
an object holding arrays, ``{"tn": [...]}``, never an array of objects, and ``iat`` is a JSON
number, never a string (RFC 8588 erratum 6656; RFC 8225 erratum 5985 on the sec. 7.1 example).
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any, Literal

from .numbers import canonicalize_tn, is_tn_spec

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

__all__ = [
    "ATTEST_LEVELS",
    "ClaimsError",
    "shaken_claims",
    "shaken_header",
    "validate_claims",
    "validate_shaken_claims",
]

ATTEST_LEVELS = {"A": "Full Attestation", "B": "Partial Attestation", "C": "Gateway Attestation"}
"""RFC 8588 sec. 4 para 1: the three values of "attest" and what they stand for."""

Claims = dict[str, Any]


class ClaimsError(ValueError):
    """A claims set does not have the shape RFC 8225 or RFC 8588 requires."""


def _check_iat(iat: object) -> int:
    # bool is an int subclass: True would otherwise serialise as the literal `true` or as 1.
    if isinstance(iat, bool) or not isinstance(iat, int):
        raise ClaimsError(f'"iat" must be a JSON number (an int), got {type(iat).__name__}')
    if iat < 0:
        raise ClaimsError('"iat" is a NumericDate and cannot be negative')
    return iat


def shaken_claims(
    orig_tn: str,
    dest_tn: Sequence[str],
    *,
    iat: int,
    attest: Literal["A", "B", "C"],
    origid: uuid.UUID | str,
    dest_uri: Sequence[str] = (),
) -> Claims:
    """Build the payload of a "shaken" PASSporT (RFC 8588 sec. 4 and 5; RFC 8225 sec. 5).

    Telephone numbers are canonicalised per RFC 8224 sec. 8.3 and the ``dest`` identity strings
    are put in lexicographic order, ``tn`` array before ``uri`` array (RFC 8225 sec. 5.2.1 para 4).
    ``origid`` must be a UUID (RFC 8588 sec. 5) and is written in its canonical lower-case form.
    """
    if attest not in ATTEST_LEVELS:
        raise ClaimsError(f'"attest" must be one of A, B, C, got {attest!r}')
    try:
        origid_text = str(origid if isinstance(origid, uuid.UUID) else uuid.UUID(origid))
    except (ValueError, AttributeError, TypeError) as error:
        raise ClaimsError(f'"origid" must be a UUID: {error}') from error
    dest: dict[str, list[str]] = {}
    if dest_tn:
        dest["tn"] = sorted(canonicalize_tn(number) for number in dest_tn)
    if dest_uri:
        dest["uri"] = sorted(dest_uri)
    claims: Claims = {
        "attest": attest,
        "dest": dest,
        "iat": _check_iat(iat),
        "orig": {"tn": canonicalize_tn(orig_tn)},
        "origid": origid_text,
    }
    validate_shaken_claims(claims)
    return claims


def shaken_header(x5u: str) -> dict[str, str]:
    """The protected header of a "shaken" PASSporT (RFC 8225 sec. 4; RFC 8588 sec. 6 shows it)."""
    return {"alg": "ES256", "ppt": "shaken", "typ": "passport", "x5u": x5u}


def _identity_strings(value: object, where: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ClaimsError(f"{where} must be a non-empty array of strings")
    if not all(isinstance(item, str) and item for item in value):
        raise ClaimsError(f"{where} must hold non-empty strings only")
    return value


def validate_claims(claims: Mapping[str, Any]) -> None:
    """Check the base PASSporT claims (RFC 8225 sec. 5): ``iat``, ``orig`` and ``dest``.

    ``iat`` is a number (RFC 8225 sec. 5.1.1 para 1; this library refuses a float too, because
    sec. 9 para 6 says numbers are encoded as integers). ``orig`` carries exactly one identity
    claim, ``tn`` or ``uri`` (sec. 5.2.1 para 2). ``dest`` is an object of arrays (erratum 5715).
    Telephone numbers must match ``tn-spec`` (RFC 8224 sec. 8.3).
    """
    if "iat" not in claims:
        raise ClaimsError('"iat" is required (RFC 8225 sec. 5.1.1)')
    _check_iat(claims["iat"])

    orig = claims.get("orig")
    if not isinstance(orig, dict) or len(orig) != 1 or next(iter(orig)) not in ("tn", "uri"):
        raise ClaimsError('"orig" must be an object with exactly one of "tn" or "uri"')
    kind, value = next(iter(orig.items()))
    if not isinstance(value, str) or not value:
        raise ClaimsError(f'"orig" {kind} must be a non-empty string')
    if kind == "tn" and not is_tn_spec(value):
        raise ClaimsError('"orig" tn is not a canonical number string (RFC 8224 sec. 8.3)')

    dest = claims.get("dest")
    if not isinstance(dest, dict) or not dest:
        raise ClaimsError('"dest" must be an object holding "tn" and/or "uri" arrays')
    if not set(dest) <= {"tn", "uri"}:
        raise ClaimsError(f'"dest" has unknown identity types: {sorted(set(dest) - {"tn", "uri"})}')
    for kind, entries in dest.items():
        strings = _identity_strings(entries, f'"dest" {kind}')
        if kind == "tn" and not all(is_tn_spec(item) for item in strings):
            raise ClaimsError('"dest" tn holds a non-canonical number string (RFC 8224 sec. 8.3)')


def validate_shaken_claims(claims: Mapping[str, Any]) -> None:
    """The base claims, plus "attest" (A, B or C) and "origid" (a UUID) per RFC 8588 sec. 4-5."""
    validate_claims(claims)
    if claims.get("attest") not in ATTEST_LEVELS:
        raise ClaimsError('"attest" must be one of "A", "B", "C" (RFC 8588 sec. 4)')
    origid = claims.get("origid")
    if not isinstance(origid, str):
        raise ClaimsError('"origid" is required and must be a UUID string (RFC 8588 sec. 5)')
    try:
        uuid.UUID(origid)
    except ValueError as error:
        raise ClaimsError(f'"origid" is not a UUID: {error}') from error
