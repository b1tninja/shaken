"""the outcome object: what passed, what was skipped and why.

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Headers = Any  # placeholder: give it a real type in the milestone that needs it
    TrustStore = Any  # placeholder: give it a real type in the milestone that needs it
    Verification = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "verify_request",
]


def verify_request(headers: Headers, store: TrustStore) -> Verification:
    """Pending behaviour defined by RFC 8224 sec. 6.2.

    Not implemented yet. See the ``verify.verify_request()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("verify_request() is not implemented: RFC 8224 sec. 6.2")
