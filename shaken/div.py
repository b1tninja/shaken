"""Diverted calls: the "div" and "div-o" PASSporT types and the ``opt`` claim (RFC 8946).

Everything here works on claims sets (plain ``dict``) and compact tokens as strings. Building
and shape-checking the claims, and linking a set of "div" PASSporTs into the chains RFC 8946
sec. 4.2 asks a verifier to build, are done. Checking signatures, freshness and the authority of
the signing credential over the ``div`` identity are not: they are ``verify``'s rows
(``verify.freshness``, ``verify.tn-authority``) and need the credential and the clock.

RFC 8946 has no verified erratum. Its sec. 3 and sec. 5 examples print ``"div":{"tn":"121555551213"}``
for a call diverted from ``12155551213``: one digit too many, in the text and in the encoded token
alike. ``tests/test_div.py`` pins that as a finding, not as something this module copies.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .claims import ClaimsError, validate_claims

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

__all__ = [
    "PPT_DIV",
    "PPT_DIV_O",
    "ChainError",
    "DivChain",
    "div_claims",
    "div_header",
    "div_o_claims",
    "link_chains",
    "validate_div_claims",
]

PPT_DIV = "div"
PPT_DIV_O = "div-o"
_ALLOWED_DIV = frozenset({"orig", "dest", "iat", "div"})
_ALLOWED_DIV_O = _ALLOWED_DIV | {"opt"}
_TOKEN_PARTS = 3
_MAX_CHAIN = 16  # a bound on the walk, not a protocol limit: real chains are one to three long


class ChainError(ValueError):
    """The PASSporTs of a request do not link into a chain RFC 8946 sec. 4.2 accepts."""


def div_header(x5u: str, *, original: bool = False) -> dict[str, str]:
    """The protected header of a "div" (or, with ``original``, "div-o") PASSporT (RFC 8946 sec. 3, 5)."""
    return {
        "alg": "ES256",
        "ppt": PPT_DIV_O if original else PPT_DIV,
        "typ": "passport",
        "x5u": x5u,
    }


def _identifier(identifier: tuple[str, str], where: str) -> dict[str, str]:
    kind, value = identifier
    if kind not in {"tn", "uri"} or not isinstance(value, str) or not value:
        raise ClaimsError(f'{where} must be ("tn" | "uri", non-empty string)')
    return {kind: value}


def _sorted_dest(dest: Mapping[str, Sequence[str]]) -> dict[str, list[str]]:
    return {kind: sorted(values) for kind, values in sorted(dest.items())}


def div_claims(
    original: Mapping[str, Any],
    *,
    diverted_from: tuple[str, str],
    new_dest: Mapping[str, Sequence[str]],
    iat: int | None = None,
) -> dict[str, Any]:
    """The claims set of a "div" PASSporT made from the ``original`` claims (RFC 8946 sec. 3).

    ``diverted_from`` is the one identifier of the original ``dest`` that this retargeting entity
    is diverting from, as ``("tn", "12155551213")`` or ``("uri", ...)``: "Every "div" PASSporT is
    diverting from only one identifier" (sec. 3 para 13), so a ``dest`` with several must be
    narrowed by the caller to one it holds a credential for. ``orig`` is copied and ``iat`` is
    retained unless ``iat`` is given (the SIP date changed, sec. 3 para 6); nothing else is copied,
    and in particular not ``opt``.

    Raises:
        ClaimsError: ``original`` is not a valid claims set, ``diverted_from`` is not in its
            ``dest``, or ``new_dest`` leaves the canonical ``dest`` unchanged (sec. 3 para 2:
            then a "div" PASSporT MUST NOT be produced).
    """
    validate_claims(original)
    kind, value = diverted_from
    if value not in original["dest"].get(kind, ()):
        raise ClaimsError("diverted_from is not one of the original PASSporT's dest identifiers")
    fresh = _sorted_dest(new_dest)
    if fresh == _sorted_dest(original["dest"]):
        raise ClaimsError(
            '"dest" did not change: a "div" PASSporT MUST NOT be produced (RFC 8946 sec. 3)'
        )
    claims = {
        "dest": fresh,
        "div": _identifier(diverted_from, "diverted_from"),
        "iat": original["iat"] if iat is None else iat,
        "orig": dict(original["orig"]),
    }
    validate_div_claims(claims, PPT_DIV)
    return claims


def div_o_claims(
    original: Mapping[str, Any],
    original_token: str,
    *,
    diverted_from: tuple[str, str],
    new_dest: Mapping[str, Sequence[str]],
    iat: int | None = None,
) -> dict[str, Any]:
    """The claims set of a "div-o" PASSporT: the "div" claims plus ``opt`` (RFC 8946 sec. 5).

    ``original_token`` is the full-form PASSporT the claims ``original`` came from; it is embedded
    as ``opt`` and must be full form (RFC 8946 sec. 6 para 2).
    """
    claims = div_claims(original, diverted_from=diverted_from, new_dest=new_dest, iat=iat)
    claims["opt"] = original_token
    validate_div_claims(claims, PPT_DIV_O)
    return claims


def validate_div_claims(claims: Mapping[str, Any], ppt: str) -> None:
    """Check the shape of a "div" or "div-o" claims set (RFC 8946 sec. 3, 5, 6).

    The base claims must be valid; ``div`` is an object with exactly one of ``tn`` or ``uri`` as a
    non-empty string (other members are allowed: sec. 3 para 14 mentions a History-Info
    indicator); no claim outside ``orig``, ``dest``, ``iat``, ``div`` (and ``opt`` for "div-o") may
    appear (sec. 3 para 6, sec. 5 para 4); "div" MUST NOT carry ``opt`` (sec. 3 para 16), and
    "div-o" MUST, holding a full-form token (sec. 6 para 2).
    """
    if ppt not in {PPT_DIV, PPT_DIV_O}:
        raise ClaimsError(f'ppt must be "div" or "div-o", got {ppt!r}')
    validate_claims(claims)
    div = claims.get("div")
    if not isinstance(div, dict):
        raise ClaimsError('"div" must be an object (RFC 8946 sec. 3 para 1)')
    identities = [k for k in ("tn", "uri") if k in div]
    if len(identities) != 1 or not isinstance(div[identities[0]], str) or not div[identities[0]]:
        raise ClaimsError('"div" must hold exactly one of "tn" or "uri", as a non-empty string')
    allowed = _ALLOWED_DIV_O if ppt == PPT_DIV_O else _ALLOWED_DIV
    extra = sorted(set(claims) - allowed)
    if extra:
        raise ClaimsError(f"claims {extra} do not belong in a {ppt!r} PASSporT")
    if ppt == PPT_DIV_O:
        opt = claims.get("opt")
        if not isinstance(opt, str):
            raise ClaimsError('"div-o" MUST contain "opt" holding the original PASSporT (sec. 5)')
        parts = opt.split(".")
        if len(parts) != _TOKEN_PARTS or not all(parts):
            raise ClaimsError('"opt" must be a full-form PASSporT, never compact (sec. 6 para 2)')


@dataclass(frozen=True, slots=True)
class DivChain:
    """One chain of retargeting, outermost "div" PASSporT first, innermost last.

    ``claims`` are the claims sets as given. A chain whose innermost member is itself a "div"
    PASSporT with no parent is incomplete, and ``link_chains`` raises instead of returning it.
    """

    claims: tuple[Mapping[str, Any], ...]

    @property
    def outermost_dest(self) -> Mapping[str, Any]:
        """The ``dest`` the verifier compares to the call target (sec. 4.2 step 1)."""
        return self.claims[0]["dest"]

    @property
    def orig(self) -> Mapping[str, Any]:
        return self.claims[-1]["orig"]


def _is_div(claims: Mapping[str, Any]) -> bool:
    return "div" in claims


def _holds(dest: Mapping[str, Any], div: Mapping[str, Any]) -> bool:
    kind = "tn" if "tn" in div else "uri"
    return div[kind] in dest.get(kind, ())


def link_chains(passports: Sequence[Mapping[str, Any]]) -> tuple[DivChain, ...]:
    """Link the claims sets of one request into retargeting chains (RFC 8946 sec. 4.2).

    For each "div" PASSporT the verifier "MUST find an earlier PASSporT that contains a "dest"
    claim with a value equivalent to the "div" claim", which may itself be "div" and chain further.
    This finds every such parent (a single "div" may retarget from several innermost PASSporTs,
    sec. 4.2 step 5) and returns one chain per outermost "div" PASSporT per innermost one: an
    outermost PASSporT is a "div" that no other "div" refers to. A parent must share ``orig``
    (step 3), so a PASSporT with the same ``dest`` but another ``orig`` is not a parent.

    Signatures and freshness are not looked at. Order of ``passports`` is not significant, because
    Identity header fields are not ordered (sec. 3 para 15).

    Raises:
        ChainError: a "div" PASSporT has no parent, a chain loops or is implausibly long, or there
            is no "div" PASSporT at all.
    """
    divs = [i for i, claims in enumerate(passports) if _is_div(claims)]
    if not divs:
        raise ChainError("no div PASSporT in the request")

    def parents(index: int) -> list[int]:
        me = passports[index]
        return [
            j
            for j, other in enumerate(passports)
            if j != index
            and other.get("orig") == me.get("orig")
            and _holds(other.get("dest", {}), me["div"])
        ]

    referred = {p for i in divs for p in parents(i)}
    outermost = [i for i in divs if i not in referred]
    if not outermost:
        raise ChainError("the div PASSporTs refer to one another in a loop")
    chains: list[DivChain] = []

    def walk(path: list[int]) -> None:
        if len(path) > _MAX_CHAIN:
            raise ChainError("div chain is longer than the bound")
        tail = path[-1]
        if not _is_div(passports[tail]):
            chains.append(DivChain(tuple(passports[i] for i in path)))
            return
        found = [p for p in parents(tail) if p not in path]
        if not found:
            raise ChainError("a div PASSporT has no earlier PASSporT whose dest holds its div")
        for parent in found:
            walk([*path, parent])

    for start in outermost:
        walk([start])
    return tuple(chains)
