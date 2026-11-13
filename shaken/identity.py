"""The SIP Identity header field value: build and parse (RFC 8224 sec. 4).

Only the field *value* is handled, the text after ``Identity:``. A SIP message, its folding and
its other headers belong to a SIP stack, which this package is not.

The grammar is RFC 8224 sec. 4 with erratum 6499 applied: ``signed-identity-digest`` is
``1*(base64url-char / ".")``, where ``base64url-char = ALPHA / DIGIT / "-" / "_"``. The RFC as
printed says ``"/" / "+"``, which is the standard base64 alphabet and not the one a PASSporT
uses (RFC 8225 sec. 6 and RFC 7515 sec. 2). Parameter names are case-insensitive (RFC 3261
sec. 7.3.1 para 21); ``alg`` and ``ppt`` values are compared case-sensitively when they are
checked against the PASSporT header, because the JSON strings they mirror are.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

__all__ = [
    "MAX_DIGEST_CHARS",
    "Identity",
    "IdentityError",
    "build_header",
    "check_mirrors",
    "parse_all",
    "parse_header",
]

MAX_DIGEST_CHARS = 8192
"""Longest signed-identity-digest accepted. A convention of this library, not an RFC limit."""

_DIGEST = re.compile(r"[A-Za-z0-9_.-]+")
_TOKEN = re.compile(r"[A-Za-z0-9\-.!%*_+`'~]+")
_ABSOLUTE_URI = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:[^\s<>\"]+")
_FORBIDDEN = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")
_QUOTED = re.compile(r'"(?:[^"\\\x00-\x1f\x7f]|\\[^\x00-\x1f\x7f])*"')


class IdentityError(ValueError):
    """An Identity header value is malformed, or does not match its PASSporT."""


@dataclass(frozen=True, slots=True)
class Identity:
    """One Identity header field value.

    ``alg`` is ``None`` when the parameter is absent: the default of ``ES256`` (RFC 8224 sec. 4.1
    para 3) is reported by ``effective_alg``, never written into the field. ``extra`` keeps
    unknown ``generic-param`` entries in order, as ``(name, value)`` with ``value`` ``None`` for a
    bare name.
    """

    digest: str
    info: str
    alg: str | None = None
    ppt: str | None = None
    extra: tuple[tuple[str, str | None], ...] = ()

    @property
    def compact(self) -> bool:
        """True when the digest is the compact form ``..signature`` (RFC 8225 sec. 7)."""
        return self.digest.startswith("..")

    @property
    def effective_alg(self) -> str:
        return self.alg if self.alg is not None else "ES256"


def _split_params(text: str) -> list[str]:
    """Split on ``;`` outside ``<...>`` and ``"..."``: a URI may itself contain a semicolon."""
    parts: list[str] = []
    current: list[str] = []
    in_angle = in_quote = escaped = False
    for char in text:
        if in_quote:
            current.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_quote = False
            continue
        if in_angle:
            current.append(char)
            if char == ">":
                in_angle = False
            continue
        if char == ";":
            parts.append("".join(current))
            current = []
            continue
        if char == "<":
            in_angle = True
        elif char == '"':
            in_quote = True
        current.append(char)
    if in_angle or in_quote:
        raise IdentityError("unterminated < > or quoted string")
    parts.append("".join(current))
    return parts


def _value(text: str) -> str:
    """A ``token`` or a ``quoted-string`` (RFC 3261 sec. 25.1 ``gen-value``), unquoted."""
    if _TOKEN.fullmatch(text):
        return text
    if _QUOTED.fullmatch(text):
        return re.sub(r"\\(.)", r"\1", text[1:-1])
    raise IdentityError(f"parameter value {text!r} is neither a token nor a quoted string")


def parse_header(value: str) -> Identity:
    """Parse the value of one Identity header field (RFC 8224 sec. 4).

    Refuses: a digest outside ``base64url-char / "."`` (erratum 6499: a ``+`` or ``/`` is an
    error, not a variant); a digest that is not three dot-separated parts with the first two both
    empty or both non-empty (RFC 8224 sec. 4.1.1 para 2: full or compact PASSporT); a missing or
    repeated ``info``, ``alg`` or ``ppt``; an ``info`` that is not ``<absoluteURI>``; control
    characters.
    """
    if not isinstance(value, str):
        raise TypeError("parse_header takes str")
    if _FORBIDDEN.search(value):
        raise IdentityError("control characters in an Identity header value")
    pieces = _split_params(value.strip())
    digest = pieces[0].strip()
    if not digest or len(digest) > MAX_DIGEST_CHARS:
        raise IdentityError(f"signed-identity-digest is empty or over {MAX_DIGEST_CHARS} chars")
    if _DIGEST.fullmatch(digest) is None:
        raise IdentityError(
            "signed-identity-digest holds a character outside base64url and '.' "
            "(RFC 8224 erratum 6499: '+' and '/' are not allowed)"
        )
    segments = digest.split(".")
    if len(segments) != 3 or not segments[2] or bool(segments[0]) != bool(segments[1]):
        raise IdentityError(
            "signed-identity-digest must be a full (h.p.s) or compact (..s) PASSporT (RFC 8224 sec. 4.1.1)"
        )
    info: str | None = None
    alg: str | None = None
    ppt: str | None = None
    extra: list[tuple[str, str | None]] = []
    for piece in pieces[1:]:
        name, equals, rest = (part.strip() for part in piece.partition("="))
        if not name or _TOKEN.fullmatch(name) is None:
            raise IdentityError(f"bad parameter name in {piece!r}")
        lowered = name.lower()
        if lowered == "info":
            if info is not None:
                raise IdentityError('"info" appears twice')
            if not (rest.startswith("<") and rest.endswith(">")):
                raise IdentityError('"info" must be <absoluteURI> (RFC 8224 sec. 4)')
            uri = rest[1:-1]
            if _ABSOLUTE_URI.fullmatch(uri) is None:
                raise IdentityError(f'"info" is not an absoluteURI: {uri!r}')
            info = uri
        elif lowered in ("alg", "ppt"):
            if not equals:
                raise IdentityError(f'"{lowered}" needs a value')
            parsed = _value(rest)
            if lowered == "alg":
                if alg is not None:
                    raise IdentityError('"alg" appears twice')
                alg = parsed
            else:
                if ppt is not None:
                    raise IdentityError('"ppt" appears twice')
                ppt = parsed
        else:
            extra.append((name, _value(rest) if equals else None))
    if info is None:
        raise IdentityError('"info" is required (RFC 8224 sec. 4)')
    return Identity(digest=digest, info=info, alg=alg, ppt=ppt, extra=tuple(extra))


def parse_all(values: Sequence[str]) -> list[Identity]:
    """Parse each Identity field of one request: RFC 8224 sec. 4 para 1 allows more than one."""
    return [parse_header(value) for value in values]


def build_header(
    token: str,
    info: str,
    *,
    alg: str | None = None,
    ppt: str | None = None,
    extra: Sequence[tuple[str, str | None]] = (),
    quote_ppt: bool = False,
) -> str:
    """Build an Identity header field value from a PASSporT and its ``info`` URI (RFC 8224 sec. 4).

    ``token`` is a full-form PASSporT or the compact form. ``quote_ppt`` writes ``ppt="shaken"``;
    the grammar as printed has a bare token, and erratum 6519 (held, not verified) asks for the
    quotes, so the default follows the printed grammar and a caller can opt in. The result is
    parsed again before it is returned, so what leaves this function is what ``parse_header``
    accepts, and a CR, LF or ``>`` smuggled into any component is refused.
    """
    parts = [token, f"info=<{info}>"]
    if alg is not None:
        parts.append(f"alg={alg}")
    if ppt is not None:
        parts.append(f'ppt="{ppt}"' if quote_ppt else f"ppt={ppt}")
    for name, extra_value in extra:
        parts.append(name if extra_value is None else f"{name}={extra_value}")
    built = ";".join(parts)
    expected = Identity(
        digest=token,
        info=info,
        alg=alg,
        ppt=ppt,
        extra=tuple((name, extra_value) for name, extra_value in extra),
    )
    if parse_header(built) != expected:
        raise IdentityError("the components do not survive a round trip; refusing to build")
    return built


def check_mirrors(identity: Identity, header: Mapping[str, object]) -> None:
    """Check the PASSporT header mirrors the Identity parameters (RFC 8224 sec. 4.1 para 3-5).

    ``x5u`` must equal ``info`` by simple string comparison (RFC 3986 sec. 6.2.1); ``alg`` must
    equal the Identity ``alg`` (``ES256`` when absent); ``ppt`` must equal the Identity ``ppt`` and
    be absent exactly when that is.
    """
    if header.get("x5u") != identity.info:
        raise IdentityError("PASSporT x5u differs from the Identity info URI")
    if header.get("alg") != identity.effective_alg:
        raise IdentityError("PASSporT alg differs from the Identity alg")
    if header.get("ppt") != identity.ppt:
        raise IdentityError("PASSporT ppt differs from the Identity ppt")
