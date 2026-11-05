"""x5u retrieval with bounds, x5c validation, CA pinning.

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Certificate = Any  # placeholder: give it a real type in the milestone that needs it
    TrustStore = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "resolve",
]


def resolve(x5u: str | None, x5c: list | None, store: TrustStore) -> Certificate:
    """Pending behaviour defined by RFC 8225.

    Not implemented yet. See the ``credentials.resolve()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("resolve() is not implemented: RFC 8225")
