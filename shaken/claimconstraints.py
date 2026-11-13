"""JWT Claim Constraints certificate extensions (RFC 8226 sec. 8, RFC 9118).

Two extensions carry the same idea. ``id-pe-JWTClaimConstraints`` (RFC 8226 sec. 8, ``id-pe 27``)
has ``mustInclude`` and ``permittedValues``. ``id-pe-eJWTClaimConstraints`` (RFC 9118 sec. 3,
``id-pe 33``) adds ``mustExclude`` and says a permitted value MUST match exactly. Both modules are
``EXPLICIT TAGS``, so each ``[n]`` wraps the SEQUENCE it names (RFC 9118 Figure 2 shows it).

RFC 9118 updates RFC 8226 and defines no way to say which one wins when a certificate carries
both; ``from_certificate`` prefers the enhanced extension and ``parse_`` of either is available
for a caller with another policy.

What is decided here is the CA's statement. Whether the certificate chains to a trust anchor is
``credentials``' business; this module checks a claims set against what the extension says.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from asn1core.errors import Asn1Error
from asn1core.node import Node, decode
from asn1core.tag import TagClass

if TYPE_CHECKING:
    from collections.abc import Mapping

    from asn1core.cert import Certificate

__all__ = [
    "BASELINE_CLAIMS",
    "ID_PE_EJWT_CLAIM_CONSTRAINTS",
    "ID_PE_JWT_CLAIM_CONSTRAINTS",
    "ClaimConstraintsError",
    "JwtClaimConstraints",
    "check_claims",
    "from_certificate",
    "parse_constraints",
]

ID_PE_JWT_CLAIM_CONSTRAINTS = "1.3.6.1.5.5.7.1.27"  # RFC 8226 sec. 8 para 9
ID_PE_EJWT_CLAIM_CONSTRAINTS = "1.3.6.1.5.5.7.1.33"  # RFC 9118 sec. 3 para 6
BASELINE_CLAIMS = frozenset({"iat", "orig", "dest"})
"""The claims every PASSporT carries (RFC 8225); both RFCs call them always permitted."""

_IA5_STRING = 22
_UTF8_STRING = 12
_SEQUENCE = 16
_MUST_INCLUDE = 0
_PERMITTED_VALUES = 1
_MUST_EXCLUDE = 2
_PAIR = 2


class ClaimConstraintsError(ValueError):
    """The extension is not a valid (Enhanced) JWT Claim Constraints value."""


@dataclass(frozen=True, slots=True)
class JwtClaimConstraints:
    """What the CA constrained.

    ``permitted_values`` maps a claim name to its listed values, in encoded order. ``enhanced``
    says which extension this was read from (only RFC 9118 has ``must_exclude``). ``ignored`` is
    RFC 9118 sec. 3 item 3: a baseline claim in ``mustExclude`` makes the certificate "be treated
    as if the extension was not present", so ``check_claims`` then applies nothing.
    """

    must_include: tuple[str, ...] = ()
    permitted_values: tuple[tuple[str, tuple[str, ...]], ...] = ()
    must_exclude: tuple[str, ...] = ()
    enhanced: bool = False
    ignored: bool = False

    @property
    def redundant_baseline(self) -> tuple[str, ...]:
        """Baseline claims listed in ``mustInclude``, which both RFCs say SHOULD NOT be."""
        return tuple(name for name in self.must_include if name in BASELINE_CLAIMS)


def _single(node: Node, what: str) -> Node:
    if not node.constructed or len(node.children) != 1:
        raise ClaimConstraintsError(f"{what}: EXPLICIT tag must wrap exactly one value")
    return node.children[0]


def _sequence(node: Node, what: str) -> tuple[Node, ...]:
    if node.tag.tag_class is not TagClass.universal or node.tag.number != _SEQUENCE:
        raise ClaimConstraintsError(f"{what} must be a SEQUENCE")
    if not node.children:
        raise ClaimConstraintsError(f"{what} is SIZE (1..MAX) and may not be empty")
    return node.children


def _text(node: Node, number: int, kind: str, what: str) -> str:
    if (
        node.tag.tag_class is not TagClass.universal
        or node.tag.number != number
        or node.payload is None
    ):
        raise ClaimConstraintsError(f"{what} must be a primitive {kind}")
    try:
        return node.payload.decode("ascii" if number == _IA5_STRING else "utf-8")
    except UnicodeDecodeError as error:
        raise ClaimConstraintsError(f"{what} is not valid {kind} text") from error


def _names(node: Node, what: str) -> tuple[str, ...]:
    return tuple(
        _text(child, _IA5_STRING, "IA5String", what + " JWTClaimName")
        for child in _sequence(_single(node, what), what)
    )


def _values(node: Node, what: str) -> tuple[tuple[str, tuple[str, ...]], ...]:
    out = []
    for entry in _sequence(_single(node, what), what):
        parts = _sequence(entry, what + " entry")
        if len(parts) != _PAIR:
            raise ClaimConstraintsError(f"{what} entry must be SEQUENCE {{ claim, values }}")
        claim = _text(parts[0], _IA5_STRING, "IA5String", what + " claim")
        values = tuple(
            _text(v, _UTF8_STRING, "UTF8String", what + " value")
            for v in _sequence(parts[1], what + " values")
        )
        out.append((claim, values))
    return tuple(out)


def parse_constraints(der: bytes, *, enhanced: bool) -> JwtClaimConstraints:
    """Parse an extension value (``Extension.value``) as RFC 8226 sec. 8 or, with ``enhanced``, RFC 9118.

    Strict DER, nothing after the SEQUENCE, fields in tag order, and at least one of them present
    (the ``WITH COMPONENTS`` clause in both modules). ``mustExclude [2]`` is refused in the
    RFC 8226 form, where it does not exist.

    Raises:
        ClaimConstraintsError: the bytes are not a conforming extension value.
    """
    try:
        root, end = decode(der, der=True)
        if end != len(der):
            raise ClaimConstraintsError("trailing bytes after the extension value")
        if root.tag.tag_class is not TagClass.universal or root.tag.number != _SEQUENCE:
            raise ClaimConstraintsError("the extension value must be a SEQUENCE")
        fields: dict[int, Node] = {}
        previous = -1
        for item in root.children:
            if item.tag.tag_class is not TagClass.context:
                raise ClaimConstraintsError("a field is not context-tagged")
            number = item.tag.number
            if number <= previous or number > (_MUST_EXCLUDE if enhanced else _PERMITTED_VALUES):
                raise ClaimConstraintsError(
                    f"field [{number}] is repeated, out of order or unknown"
                )
            previous = number
            fields[number] = item
        if not fields:
            raise ClaimConstraintsError("at least one of the constraints must be present")
        must_include = _names(fields[0], "mustInclude") if _MUST_INCLUDE in fields else ()
        permitted = _values(fields[1], "permittedValues") if _PERMITTED_VALUES in fields else ()
        must_exclude = _names(fields[2], "mustExclude") if _MUST_EXCLUDE in fields else ()
    except Asn1Error as error:
        raise ClaimConstraintsError(f"not DER: {error}") from error
    ignored = bool(BASELINE_CLAIMS & set(must_exclude))
    return JwtClaimConstraints(must_include, permitted, must_exclude, enhanced, ignored)


def from_certificate(certificate: Certificate) -> JwtClaimConstraints | None:
    """The certificate's claim constraints, or ``None`` when it carries neither extension.

    The enhanced extension (RFC 9118) wins when both are present. Both are non-critical and only
    for end-entity certificates (RFC 8226 sec. 8 para 1, RFC 9118 sec. 3 para 1); a critical or
    CA one is read all the same, since refusing it would hide what the CA wrote.
    """
    extension = certificate.extension(ID_PE_EJWT_CLAIM_CONSTRAINTS)
    if extension is not None:
        return parse_constraints(extension.value, enhanced=True)
    extension = certificate.extension(ID_PE_JWT_CLAIM_CONSTRAINTS)
    if extension is not None:
        return parse_constraints(extension.value, enhanced=False)
    return None


def check_claims(
    constraints: JwtClaimConstraints | None, claims: Mapping[str, Any]
) -> tuple[str, ...]:
    """Every way ``claims`` (a PASSporT payload) breaks what the certificate allows.

    Empty means conforming. The baseline claims ``iat``, ``orig`` and ``dest`` are always
    required (RFC 8226 sec. 8 item 1; RFC 9118 sec. 3 item 1), constraints or not. A permitted
    value must match exactly (RFC 9118) and so must be a JSON string equal to one listed; a claim
    that is absent is not a violation of ``permittedValues`` (RFC 9118 sec. 4, second bullet).
    An ``ignored`` extension applies nothing beyond the baseline.
    """
    problems = [f"{name} must appear" for name in sorted(BASELINE_CLAIMS - claims.keys())]
    if constraints is None or constraints.ignored:
        return tuple(problems)
    problems += [
        f"{name} must appear (mustInclude)"
        for name in constraints.must_include
        if name not in claims and name not in BASELINE_CLAIMS
    ]
    for name, values in constraints.permitted_values:
        if name in claims and not (isinstance(claims[name], str) and claims[name] in values):
            problems.append(f"{name} must be one of {list(values)} (permittedValues)")
    problems += [
        f"{name} must not appear (mustExclude)"
        for name in constraints.must_exclude
        if name in claims
    ]
    return tuple(problems)
