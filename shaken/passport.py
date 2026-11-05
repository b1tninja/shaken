"""token construction, canonicalisation and signature (RFC 8225).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Claims = Any  # placeholder: give it a real type in the milestone that needs it
    SigningKey = Any  # placeholder: give it a real type in the milestone that needs it
    TrustStore = Any  # placeholder: give it a real type in the milestone that needs it
    Verification = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "create",
    "verify",
]


def create(claims: Claims, key: SigningKey, certs: list) -> str:
    """Pending behaviour defined by RFC 8225.

    Not implemented yet. See the ``passport.create()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("create() is not implemented: RFC 8225")


def verify(token: str, store: TrustStore) -> Verification:
    """Pending behaviour defined by RFC 8225.

    Not implemented yet. See the ``passport.verify()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("verify() is not implemented: RFC 8225")
