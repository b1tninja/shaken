"""the registered claims and the SHAKEN extension set (RFC 8225, RFC 8588).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Claims = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "shaken_claims",
]


def shaken_claims(orig: str, dest: str, level: str) -> Claims:
    """Pending behaviour defined by RFC 8588.

    Not implemented yet. See the ``claims.shaken_claims()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("shaken_claims() is not implemented: RFC 8588")
