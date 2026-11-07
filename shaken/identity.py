"""the SIP header field build and parse (RFC 8224).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    IdentityHeader = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "build_header",
    "parse_header",
]


def build_header(token: str, info: str) -> str:
    """Pending behaviour defined by RFC 8224 sec. 4.

    Not implemented yet. See the ``identity.build_header()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("build_header() is not implemented: RFC 8224 sec. 4")


def parse_header(value: str) -> IdentityHeader:
    """Pending behaviour defined by RFC 8224 sec. 4.

    Not implemented yet. See the ``identity.parse_header()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("parse_header() is not implemented: RFC 8224 sec. 4")
