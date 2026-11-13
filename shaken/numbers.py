"""Telephone number canonicalisation (RFC 8224 sec. 8.3).

Only the mechanical first step of sec. 8.3 is done here: drop every character that is not a
digit, ``#`` or ``*``. The second step (decide whether the result is a globally routable number
with a country code and convert a dial string to E.164) needs a numbering plan and local policy,
which sec. 8.3 para 5 leaves to the domain, so it is the caller's job and is not attempted.
"""

from __future__ import annotations

import re

__all__ = ["canonicalize_tn", "is_tn_spec"]

_TN_SPEC = re.compile(r"[0-9#*]+")
_NOT_TN_CHAR = re.compile(r"[^0-9#*]")


def is_tn_spec(text: str) -> bool:
    """True when ``text`` matches ``tn-spec = 1*tn-char`` (RFC 8224 sec. 8.3 para 8).

    ASCII digits only: a ``re`` digit class would match other Unicode digits, so ``0-9`` is spelled
    out.
    """
    return isinstance(text, str) and _TN_SPEC.fullmatch(text) is not None


def canonicalize_tn(text: str) -> str:
    """Return the canonical number string of ``text`` (RFC 8224 sec. 8.3 para 2).

    ``+``, dashes, parentheses, spaces and any other non-numeric character are dropped; ``#`` and
    ``*`` survive. A result with no characters left is refused rather than returned empty.
    """
    if not isinstance(text, str):
        raise TypeError("canonicalize_tn takes str")
    result = _NOT_TN_CHAR.sub("", text)
    if not result:
        raise ValueError(f"no digits, '#' or '*' in {text!r}: nothing to canonicalise")
    return result
