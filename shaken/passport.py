"""Token construction, canonicalisation and signature (RFC 8225, RFC 7515, RFC 7518).

``create`` and ``verify`` work on the full form of a PASSporT, which is the only form SHAKEN uses
(RFC 8588 sec. 3 para 3). The compact form (RFC 8225 sec. 7) is handled by ``to_compact`` and
``verify_compact``: the verifier rebuilds the header and claims from the SIP request and the
signature is checked over their deterministic serialisation.

Nothing here decides whether a signer may be trusted. ``verify`` proves that the bytes were
signed by the key it was given and that the token has the shape RFC 8225 and RFC 8588 describe.
Which key to use (a certificate fetched from ``x5u``, validated to an STI trust anchor and
authorised for the calling number) and whether the token is fresh are the verification
policy's job, and are not done here.
"""

from __future__ import annotations

import contextlib
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .claims import ClaimsError, validate_claims, validate_shaken_claims
from .jws import (
    SIGNATURE_OCTETS,
    JwsError,
    Signer,
    Verifier,
    b64url_decode,
    b64url_encode,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

__all__ = [
    "MAX_TOKEN_CHARS",
    "InvalidSignature",
    "ParsedToken",
    "PassportError",
    "canonical_json",
    "create",
    "parse",
    "signing_input",
    "to_compact",
    "verify",
    "verify_compact",
]

MAX_TOKEN_CHARS = 16384
"""Longest token ``parse`` reads. A convention of this library, not an RFC limit: a SHAKEN token is
a few hundred octets, and a verifier should not hand attacker-sized text to a JSON parser."""


class PassportError(ValueError):
    """A token or its inputs are malformed. The message says which rule broke."""


class InvalidSignature(PassportError):  # noqa: N818 - the name is the protocol's own term
    """The token is well formed but its signature does not verify under the key given."""


def _canonicalise(value: Any, where: str) -> Any:
    if value is None or isinstance(value, bool | str | int):
        return value
    if isinstance(value, float):
        raise PassportError(f"{where}: floats are refused, RFC 8225 sec. 9 rule 4 wants integers")
    if isinstance(value, dict):
        out = {}
        for key in value:
            if not isinstance(key, str):
                raise PassportError(f"{where}: object member names must be strings")
            out[key] = _canonicalise(value[key], f"{where}.{key}")
        return out
    if isinstance(value, list | tuple):
        return [_canonicalise(item, f"{where}[]") for item in value]
    raise PassportError(f"{where}: {type(value).__name__} is not a JSON value")


def canonical_json(obj: Mapping[str, Any]) -> bytes:
    """Serialise ``obj`` by the deterministic rules of RFC 8225 sec. 9.

    No whitespace (rule 1); member names ordered by Unicode code point, at every depth (rules 2
    and 5); lower-case literals (rule 3); integers only (rule 4). Text is UTF-8, with only the
    characters JSON itself requires escaped; RFC 8225 names no other escape policy, so this one is
    a convention. Array order is the caller's: sec. 5.2.1 asks for sorted identity arrays and
    ``claims.shaken_claims`` sorts them.
    """
    if not isinstance(obj, dict):
        raise PassportError("canonical_json takes an object")
    clean = _canonicalise(obj, "$")
    try:
        text = json.dumps(
            clean, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        )
        return text.encode("utf-8")
    except (ValueError, UnicodeEncodeError) as error:
        raise PassportError(f"not serialisable as UTF-8 JSON: {error}") from error


def signing_input(header: Mapping[str, Any], payload: Mapping[str, Any]) -> bytes:
    """The JWS Signing Input: ``ASCII(BASE64URL(header) || "." || BASE64URL(payload))``.

    RFC 8225 Appendix A para 17; RFC 7515 sec. 5.1 steps 2 to 5.
    """
    head = b64url_encode(canonical_json(header))
    body = b64url_encode(canonical_json(payload))
    return f"{head}.{body}".encode("ascii")


def _check_header(header: Mapping[str, Any]) -> None:
    if header.get("typ") != "passport":
        raise PassportError('"typ" must be "passport" (RFC 8225 sec. 4.1)')
    if header.get("alg") != "ES256":
        raise PassportError('only "ES256" is supported (RFC 8225 sec. 4.2 makes it mandatory)')
    x5u = header.get("x5u")
    if not isinstance(x5u, str) or not x5u:
        raise PassportError('"x5u" must be a non-empty string (RFC 8225 sec. 4.3)')
    ppt = header.get("ppt")
    if ppt is not None and not isinstance(ppt, str):
        raise PassportError('"ppt" must be a string (RFC 8225 sec. 8.1)')
    if "crit" in header:
        # RFC 7515 sec. 4.1.11 para 1: a JWS is invalid if a listed critical extension is not
        # understood and supported. No extension is, so any "crit" makes the token invalid.
        raise PassportError('"crit" lists extensions this library does not understand (RFC 7515)')


def _check_claims(header: Mapping[str, Any], claims: Mapping[str, Any]) -> None:
    try:
        if header.get("ppt") == "shaken":
            validate_shaken_claims(claims)
        else:
            validate_claims(claims)
    except ClaimsError as error:
        raise PassportError(str(error)) from error


def create(claims: Mapping[str, Any], header: Mapping[str, Any], signer: Signer) -> str:
    """Build a full-form PASSporT and sign it (RFC 8225 sec. 6; RFC 7515 sec. 5.1).

    ``header`` is the protected header (``claims.shaken_header`` builds the SHAKEN one) and must be
    ES256 with ``typ`` "passport" and an ``x5u``. ``claims`` is checked for the shape RFC 8225
    sec. 5 and, when ``ppt`` is "shaken", RFC 8588 sec. 4 and 5 require. Returns
    ``header.payload.signature``, every part base64url without padding.
    """
    _check_header(header)
    _check_claims(header, claims)
    message = signing_input(header, claims)
    signature = signer.sign(message)
    if len(signature) != SIGNATURE_OCTETS:
        raise PassportError(f"the signer returned {len(signature)} octets, ES256 needs 64")
    return f"{message.decode('ascii')}.{b64url_encode(signature)}"


@dataclass(frozen=True, slots=True)
class ParsedToken:
    """A full-form PASSporT taken apart. Nothing here is trusted until ``verify`` passed.

    ``signing_input`` is the received text, not a re-serialisation: the signature covers what was
    sent. ``canonical`` says whether header and payload happen to be in the deterministic form of
    RFC 8225 sec. 9, which sec. 7 para 5 asks for but a verifier of the full form does not need.
    """

    header: dict[str, Any]
    payload: dict[str, Any]
    signature: bytes
    signing_input: bytes
    canonical: bool

    @property
    def ppt(self) -> str | None:
        value = self.header.get("ppt")
        return value if isinstance(value, str) else None


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise PassportError(f"duplicate member name {key!r} (RFC 8225 sec. 9 para 8)")
        out[key] = value
    return out


def _refuse_constant(name: str) -> Any:
    raise PassportError(f"{name} is not a JSON value")


def _load_object(raw: bytes, what: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_no_duplicates,
            parse_constant=_refuse_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise PassportError(f"the {what} is not valid UTF-8 JSON: {error}") from error
    if not isinstance(value, dict):
        raise PassportError(f"the {what} must be a JSON object")
    return value


def parse(token: str, *, supported_ppt: frozenset[str] = frozenset({"shaken"})) -> ParsedToken:
    """Take apart a full-form PASSporT without verifying the signature (RFC 7515 sec. 5.2).

    Refuses: a token that is not exactly three base64url parts; a header that is not ES256 with
    ``typ`` "passport"; a ``ppt`` this caller does not support (RFC 8225 sec. 8.1 para 1: relying
    parties MUST fail to validate those); a signature that is not 64 octets; and claims of the
    wrong shape, such as a string ``iat`` or an array of objects for ``dest``.
    """
    if not isinstance(token, str):
        raise TypeError("parse takes str")
    if len(token) > MAX_TOKEN_CHARS:
        raise PassportError(f"token is longer than {MAX_TOKEN_CHARS} characters")
    parts = token.split(".")
    if len(parts) != 3:
        raise PassportError(f"a full-form PASSporT has 3 dot-separated parts, got {len(parts)}")
    head_text, body_text, sig_text = parts
    if not head_text or not body_text:
        raise PassportError("empty header or payload: this is the compact form, use verify_compact")
    try:
        head_raw = b64url_decode(head_text)
        body_raw = b64url_decode(body_text)
        signature = b64url_decode(sig_text)
    except JwsError as error:
        raise PassportError(str(error)) from error
    header = _load_object(head_raw, "header")
    payload = _load_object(body_raw, "payload")
    _check_header(header)
    ppt = header.get("ppt")
    if ppt is not None and ppt not in supported_ppt:
        raise PassportError(f'unsupported "ppt" {ppt!r} (RFC 8225 sec. 8.1 para 1)')
    _check_claims(header, payload)
    if len(signature) != SIGNATURE_OCTETS:
        raise PassportError(f"the signature is {len(signature)} octets, ES256 needs 64")
    canonical = False
    with contextlib.suppress(PassportError):
        canonical = canonical_json(header) == head_raw and canonical_json(payload) == body_raw
    return ParsedToken(
        header=header,
        payload=payload,
        signature=signature,
        signing_input=f"{head_text}.{body_text}".encode("ascii"),
        canonical=canonical,
    )


def verify(
    token: str, verifier: Verifier, *, supported_ppt: frozenset[str] = frozenset({"shaken"})
) -> ParsedToken:
    """Parse a full-form PASSporT and check its signature under ``verifier`` (RFC 8225 sec. 6; RFC 7515 sec. 5.2).

    Returns the parsed token, or raises ``PassportError`` for a malformed one and
    ``InvalidSignature`` for a signature that does not match. This is a signature check, not a
    verification outcome: see the module docstring for what it leaves to the caller.
    """
    parsed = parse(token, supported_ppt=supported_ppt)
    if not verifier.verify(parsed.signing_input, parsed.signature):
        raise InvalidSignature("the ES256 signature does not verify under the given key")
    return parsed


def to_compact(token: str) -> str:
    """The compact form of a full-form token: ``".." || BASE64URL(signature)`` (RFC 8225 sec. 7)."""
    return ".." + b64url_encode(parse(token).signature)


def verify_compact(
    compact: str, header: Mapping[str, Any], claims: Mapping[str, Any], verifier: Verifier
) -> None:
    """Verify the compact form against a header and claims rebuilt from the SIP request.

    RFC 8225 sec. 7 para 2-3: the destination reconstructs the header and claims, serialises them
    deterministically and checks the signature over that. Raises ``InvalidSignature`` on mismatch.
    """
    if not compact.startswith(".."):
        raise PassportError('the compact form starts with ".." (RFC 8225 sec. 7)')
    try:
        signature = b64url_decode(compact[2:])
    except JwsError as error:
        raise PassportError(str(error)) from error
    if len(signature) != SIGNATURE_OCTETS:
        raise PassportError(f"the signature is {len(signature)} octets, ES256 needs 64")
    _check_header(header)
    _check_claims(header, claims)
    if not verifier.verify(signing_input(header, claims), signature):
        raise InvalidSignature("the ES256 signature does not verify under the given key")
