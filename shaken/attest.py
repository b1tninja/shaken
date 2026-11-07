"""attestation levels and the policy a verifier applies (RFC 8588).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Policy = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "policy_for",
]


def policy_for(level: str) -> Policy:
    """Pending behaviour defined by RFC 8588 sec. 4.

    Not implemented yet. See the ``attest.policy_for()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("policy_for() is not implemented: RFC 8588 sec. 4")
