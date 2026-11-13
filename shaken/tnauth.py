"""The TN Authorization List certificate extension (RFC 8226 sec. 9 and Appendix A).

Parsed with ``asn1core``, strict DER. The module is EXPLICIT TAGS (Appendix A para 5), so each
``TNEntry`` alternative is a context tag wrapping the universal one: ``spc [0]`` holds an
IA5String, ``range [1]`` a SEQUENCE, ``one [2]`` an IA5String.

What this module answers is "what did the CA put in the extension". Whether a given call's
originating number falls inside it is ``covers``; whether the certificate chain is trusted is not
decided here. A ``ServiceProviderCode`` names a provider's numbers indirectly and cannot be
expanded without an external registry, so ``covers`` reports it separately.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from asn1core.errors import Asn1Error
from asn1core.node import Node, decode
from asn1core.tag import TagClass

if TYPE_CHECKING:
    from asn1core.cert import Certificate

__all__ = [
    "ID_PE_TNAUTHLIST",
    "ServiceProviderCode",
    "TNAuthListError",
    "TNEntry",
    "TelephoneNumber",
    "TelephoneNumberRange",
    "covers",
    "from_certificate",
    "parse_tn_auth_list",
]

ID_PE_TNAUTHLIST = "1.3.6.1.5.5.7.1.26"
"""``id-pe-TNAuthList ::= { id-pe 26 }`` (RFC 8226 sec. 9 para 4); id-pe is 1.3.6.1.5.5.7.1."""

_IA5_STRING = 22
_INTEGER = 2
_SEQUENCE = 16
_TN_CHARS = frozenset("0123456789#*")
_DIGITS = frozenset("0123456789")


class TNAuthListError(ValueError):
    """The extension is not a valid TNAuthorizationList."""


@dataclass(frozen=True, slots=True)
class ServiceProviderCode:
    """``spc [0]``: an OCN, SPID or other provider identifier (RFC 8226 sec. 9 para 13)."""

    code: str


@dataclass(frozen=True, slots=True)
class TelephoneNumberRange:
    """``range [1]``: ``count`` numbers starting at ``start`` (RFC 8226 sec. 9 para 14)."""

    start: str
    count: int


@dataclass(frozen=True, slots=True)
class TelephoneNumber:
    """``one [2]``: a single number (RFC 8226 sec. 9 para 15)."""

    number: str


TNEntry = ServiceProviderCode | TelephoneNumberRange | TelephoneNumber


def _ia5(node: Node, what: str) -> str:
    if node.tag.number != _IA5_STRING or node.tag.tag_class is not TagClass.universal:
        raise TNAuthListError(f"{what} must be an IA5String")
    if node.payload is None:
        raise TNAuthListError(f"{what} must be primitive")
    try:
        return node.payload.decode("ascii")
    except UnicodeDecodeError as error:
        raise TNAuthListError(f"{what} is not ASCII") from error


def _telephone_number(text: str, what: str) -> str:
    # IA5String (SIZE (1..15)) (FROM ("0123456789#*")), RFC 8226 sec. 9 para 11.
    if not 1 <= len(text) <= 15 or not set(text) <= _TN_CHARS:
        raise TNAuthListError(f"{what} {text!r} is not 1..15 characters of 0-9 # *")
    return text


def _single(node: Node, what: str) -> Node:
    if not node.constructed or len(node.children) != 1:
        raise TNAuthListError(f"{what}: EXPLICIT tag must wrap exactly one value")
    return node.children[0]


def _entry(node: Node) -> TNEntry:
    if node.tag.tag_class is not TagClass.context:
        raise TNAuthListError("TNEntry must be a context-tagged alternative")
    inner = _single(node, "TNEntry")
    if node.tag.number == 0:
        code = _ia5(inner, "ServiceProviderCode")
        return ServiceProviderCode(code)
    if node.tag.number == 2:
        return TelephoneNumber(_telephone_number(_ia5(inner, "TelephoneNumber"), "TelephoneNumber"))
    if node.tag.number == 1:
        if inner.tag.number != _SEQUENCE or inner.tag.tag_class is not TagClass.universal:
            raise TNAuthListError("TelephoneNumberRange must be a SEQUENCE")
        # The "..." in the module is an extension marker: later members are tolerated, not read.
        if len(inner.children) < 2:
            raise TNAuthListError("TelephoneNumberRange needs start and count")
        start = _telephone_number(_ia5(inner.children[0], "range start"), "range start")
        count_node = inner.children[1]
        if (
            count_node.tag.number != _INTEGER
            or count_node.tag.tag_class is not TagClass.universal
            or count_node.payload is None
        ):
            raise TNAuthListError("range count must be an INTEGER")
        count = int.from_bytes(count_node.payload, "big", signed=True)
        if count < 2:
            raise TNAuthListError("range count must be at least 2 (INTEGER (2..MAX))")
        if not set(start) <= _DIGITS:
            raise TNAuthListError("range count is not applicable to a start with '#' or '*'")
        if int(start) + count >= 10 ** len(start):
            raise TNAuthListError(
                f"range {start!r}+{count} makes the number longer (RFC 8226 sec. 9 para 14)"
            )
        return TelephoneNumberRange(start, count)
    raise TNAuthListError(f"unknown TNEntry alternative [{node.tag.number}]")


def parse_tn_auth_list(der: bytes) -> tuple[TNEntry, ...]:
    """Parse the extension value (the OCTET STRING's content: ``Extension.value``).

    Strict DER, one or more entries (``SIZE (1..MAX)``), nothing after the SEQUENCE.
    """
    try:
        root, end = decode(der, der=True)
    except Asn1Error as error:
        raise TNAuthListError(f"not DER: {error}") from error
    if end != len(der):
        raise TNAuthListError("trailing bytes after TNAuthorizationList")
    if root.tag.number != _SEQUENCE or root.tag.tag_class is not TagClass.universal:
        raise TNAuthListError("TNAuthorizationList must be a SEQUENCE")
    if not root.children:
        raise TNAuthListError("TNAuthorizationList must hold at least one entry (SIZE (1..MAX))")
    return tuple(_entry(child) for child in root.children)


def from_certificate(certificate: Certificate) -> tuple[TNEntry, ...] | None:
    """The certificate's TN Authorization List, or ``None`` when it has no such extension.

    RFC 8226 sec. 9 para 1 says the extension is non-critical; a critical one is read all the
    same, since refusing it would hide what the CA wrote.
    """
    extension = certificate.extension(ID_PE_TNAUTHLIST)
    if extension is None:
        return None
    return parse_tn_auth_list(extension.value)


def covers(entries: tuple[TNEntry, ...], number: str) -> bool | None:
    """Does the list authorise ``number`` (a canonical digit string, RFC 8224 sec. 8.3)?

    ``True`` when a ``one`` entry equals it or a ``range`` contains it (``start`` up to but not
    including ``start + count``, the same length). ``False`` when the list has only those
    entry kinds and none matches. ``None`` when nothing matched and the list also holds a
    ``ServiceProviderCode``: the answer then depends on a provider registry this package does not
    have.
    """
    unresolved = False
    for entry in entries:
        if isinstance(entry, TelephoneNumber):
            if entry.number == number:
                return True
        elif isinstance(entry, TelephoneNumberRange):
            if (
                len(number) == len(entry.start)
                and number.isdigit()
                and int(entry.start) <= int(number) < int(entry.start) + entry.count
            ):
                return True
        else:
            unresolved = True
    return None if unresolved else False
