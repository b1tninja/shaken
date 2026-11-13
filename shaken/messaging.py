"""The "msg" PASSporT type and the "msgi" message-integrity claim (RFC 9475 sec. 3.2).

``msgi`` is ``<alg>-<base64 digest>``: a hash algorithm name, a hyphen, and the base64 (RFC 4648
sec. 4, standard alphabet with padding) of the digest of the entire MIME body of the message.
This module builds and checks that string and the claims shape. How the MIME body is
canonicalised before hashing is not specified by RFC 9475 sec. 3.2 para 4 ("a canonicalized and
concatenated string or binary-data-based MIME body"), so every function takes the exact octets the
caller hashes and records no canonicalisation of its own: two implementations that disagree about
line endings will disagree about the digest, which is a gap in the RFC and a row in ROADMAP.md.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from typing import TYPE_CHECKING, Any

from .claims import ClaimsError, validate_claims

if TYPE_CHECKING:
    from collections.abc import Mapping

__all__ = [
    "MSGI_ALGORITHMS",
    "PPT_MSG",
    "msg_claims",
    "msg_header",
    "msgi_digest",
    "msgi_matches",
    "validate_msg_claims",
]

PPT_MSG = "msg"
MSGI_ALGORITHMS = {"sha256": "sha256", "sha384": "sha384", "sha512": "sha512"}
"""The hash algorithms an implementation MUST support (RFC 9475 sec. 3.2 para 3), by msgi name.

The RFC allows more, from the COSE Algorithms registry's recommended hashes; none is added here
because that registry is not in the primarysource collections yet.
"""


def msg_header(x5u: str) -> dict[str, str]:
    """The protected header of a "msg" PASSporT (RFC 9475 sec. 5.2)."""
    return {"alg": "ES256", "ppt": PPT_MSG, "typ": "passport", "x5u": x5u}


def msgi_digest(body: bytes, algorithm: str = "sha256") -> str:
    """The ``msgi`` claim value for the MIME body octets ``body``."""
    if algorithm not in MSGI_ALGORITHMS:
        raise ClaimsError(f"msgi algorithm {algorithm!r} is not one of {sorted(MSGI_ALGORITHMS)}")
    digest = hashlib.new(MSGI_ALGORITHMS[algorithm], body).digest()
    return f"{algorithm}-{base64.b64encode(digest).decode('ascii')}"


def _split(value: object) -> tuple[str, bytes]:
    if not isinstance(value, str):
        raise ClaimsError('"msgi" must be a string (RFC 9475 sec. 3.2 para 3)')
    algorithm, hyphen, text = value.partition("-")
    # sec. 3.2 para 3: lowercase, no hyphen. "sha256" has digits, so "only lowercase letters"
    # cannot be taken literally; the names the RFC itself lists are the rule applied here.
    if not hyphen or not algorithm or not text or algorithm != algorithm.lower():
        raise ClaimsError('"msgi" must be a lowercase algorithm name, "-", and a base64 digest')
    try:
        return algorithm, base64.b64decode(text, validate=True)
    except binascii.Error as error:
        raise ClaimsError(f'"msgi" digest is not base64: {error}') from error


def msgi_matches(value: str, body: bytes) -> bool:
    """Whether the ``msgi`` claim value is the digest of ``body``.

    Raises:
        ClaimsError: ``value`` is malformed or names an algorithm this module does not hash with;
            RFC 9475 sec. 3.2 para 6 says what to tell the sender is local policy (SIP 438 is
            "most appropriate" for a mismatch), so a mismatch is ``False`` and not an error.
    """
    algorithm, digest = _split(value)
    if algorithm not in MSGI_ALGORITHMS:
        raise ClaimsError(f"msgi algorithm {algorithm!r} is not supported")
    return hmac.compare_digest(digest, hashlib.new(MSGI_ALGORITHMS[algorithm], body).digest())


def msg_claims(
    base: Mapping[str, Any], *, body: bytes | None = None, algorithm: str = "sha256"
) -> dict[str, Any]:
    """The claims of a "msg" PASSporT: ``base`` (iat, orig, dest) plus an optional ``msgi``.

    ``msgi`` is OPTIONAL (RFC 9475 sec. 3.2 para 2), so it is written only when ``body`` is given.
    """
    validate_claims(base)
    claims = dict(base)
    if body is not None:
        claims["msgi"] = msgi_digest(body, algorithm)
    return claims


def validate_msg_claims(claims: Mapping[str, Any], ppt: str | None) -> bool:
    """Check the ``msgi`` claim against the PASSporT type; return whether ``msgi`` applies.

    "Authentication services MUST NOT include "msgi" elements in PASSporT types other than "msg""
    and "Verification services MUST ignore the presence of "msgi" in non-"msg" PASSporT types"
    (RFC 9475 sec. 3.2 para 2). This is the verifier's side: for a type other than "msg" the claim
    is ignored and the answer is ``False`` however it looks. For "msg" a present ``msgi`` must be
    well-formed and the answer is ``True`` (``False`` when absent: nothing to check).

    Raises:
        ClaimsError: a "msg" PASSporT has a malformed ``msgi``.
    """
    if ppt != PPT_MSG or "msgi" not in claims:
        return False
    _split(claims["msgi"])
    return True
