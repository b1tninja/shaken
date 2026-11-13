"""Reading the credential a PASSporT points at: certificates, signer keys, TN authority.

``load_certificates`` and ``signer_verifier`` are the parts that need no network and no trust
decision: parse what was fetched (certificate parsing is ``asn1core``'s, strict DER) and turn a
certificate's public key into the verifier ``passport.verify`` takes. ``resolve``, which fetches
from ``x5u`` under bounds and validates the chain to a pinned STI trust anchor, is not written:
it needs the network rules of ROADMAP.md section 5 and the path validation ``pkix`` has not
shipped.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import TYPE_CHECKING

import pkix.chain
import pkix.errors
import pkix.validity
from asn1core import names_equal, pem
from asn1core.cert import Certificate, parse_certificate
from asn1core.errors import Asn1Error

from .jws import Es256Verifier, JwsError

if TYPE_CHECKING:
    from typing import Any

    TrustStore = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "MAX_CHAIN",
    "ChainResult",
    "CredentialError",
    "load_certificates",
    "resolve",
    "signer_verifier",
    "validate_chain",
]

MAX_CHAIN = 8
"""Most certificates ``load_certificates`` returns. A convention of this library, not an RFC limit."""


class CredentialError(ValueError):
    """What was fetched is not a usable certificate or chain."""


def load_certificates(data: bytes) -> tuple[Certificate, ...]:
    """Parse a PEM bundle of ``CERTIFICATE`` blocks, or one bare DER certificate, with asn1core.

    Order is preserved: by convention the signer's certificate comes first. More than
    ``MAX_CHAIN`` certificates, or none, is refused.
    """
    try:
        if b"-----BEGIN" in data:
            blocks = pem.certificates(data)
            if not blocks:
                raise CredentialError("no CERTIFICATE block in the PEM data")
            if len(blocks) > MAX_CHAIN:
                raise CredentialError(f"more than {MAX_CHAIN} certificates")
            return tuple(parse_certificate(block.der) for block in blocks)
        return (parse_certificate(data),)
    except Asn1Error as error:
        raise CredentialError(f"not a certificate: {error}") from error


def signer_verifier(certificate: Certificate) -> Es256Verifier:
    """The ES256 verifier for the key in ``certificate``. Refuses any key that is not P-256."""
    try:
        return Es256Verifier.from_spki_der(certificate.subject_public_key_info)
    except JwsError as error:
        raise CredentialError(str(error)) from error


def resolve(x5u: str | None, x5c: list | None, store: TrustStore) -> Certificate:
    """Pending behaviour defined by RFC 8225 sec. 4.3.

    Not implemented yet. See the ``credentials.resolve()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("resolve() is not implemented: RFC 8225 sec. 4.3")


@dataclass(frozen=True, slots=True)
class ChainResult:
    """A chain that validated: the path (signer first), the anchor that closed it, and what was proved.

    ``checked`` names every check applied. It is deliberately explicit, because RFC 5280 sec. 6.1
    is larger than what is checked here: name, policy and path-length constraints, key usage,
    critical extensions and revocation are not (``pkix`` has not shipped those rows). A caller that
    needs them must not read ``ChainResult`` as full path validation.
    """

    path: tuple[Certificate, ...]
    anchor: Certificate
    checked: tuple[str, ...]


CHECKED = (
    "issuer name linkage (RFC 5280 sec. 6.1.3(a)(4), 7.1)",
    "validity period at the given time (sec. 6.1.3(a)(2))",
    "signature of each certificate under its issuer's key (sec. 6.1.3(a)(1))",
    "each issuing certificate asserts cA (sec. 4.2.1.9)",
)


def validate_chain(
    signer: Certificate,
    intermediates: tuple[Certificate, ...],
    anchors: tuple[Certificate, ...],
    at: datetime.datetime,
) -> ChainResult:
    """Validate ``signer`` to one of the STI trust ``anchors`` with ``pkix``, as of ``at``.

    RFC 8226 sec. 4 and 7 leave acquisition open and certificate validity to RFC 5280 sec. 6, so
    this runs the part of that algorithm ``pkix`` provides today (see ``ChainResult.checked``):
    candidate paths by issuer name, then for each the validity of every certificate, each
    signature under its issuer's key (the anchor's key closes the path) and the ``cA`` assertion of
    every issuing certificate. The first candidate that passes wins. The anchors are the caller's
    pinned STI-CA roots; which roots those are is not decided here (the owner's trust-anchor
    decision, see ROADMAP.md), and no store is read.

    A certificate's ``TNAuthList`` is not consulted: ``verify.tn-authority`` does that, after this.

    Raises:
        CredentialError: no candidate path passes; the message says why the last one failed.
    """
    candidates = pkix.chain.candidates(signer, intermediates, anchors)
    if not candidates:
        raise CredentialError("no certification path from the signer to an STI trust anchor")
    why = "no candidate passed"
    for path in candidates:
        try:
            anchor = _check_path(path, anchors, at)
        except _PathRefusedError as failure:
            why = str(failure)
            continue
        return ChainResult(tuple(path), anchor, CHECKED)
    raise CredentialError(f"no valid path to an STI trust anchor: {why}")


class _PathRefusedError(Exception):
    pass


def _check_path(
    path: list[Certificate], anchors: tuple[Certificate, ...], at: datetime.datetime
) -> Certificate:
    anchor = next((a for a in anchors if names_equal(path[-1].issuer, a.subject)), None)
    if anchor is None:  # pragma: no cover - candidates() ended the path at an anchor name
        raise _PathRefusedError("the path does not end at an anchor")
    issuers = [*path[1:], anchor]
    for certificate, issuer in zip(path, issuers, strict=True):
        if not pkix.validity.check_validity(certificate, at).ok:
            raise _PathRefusedError(f"{certificate.subject} is not valid at {at.isoformat()}")
        if not pkix.chain.may_issue(issuer):
            raise _PathRefusedError(
                f"{issuer.subject} may not issue certificates (cA is not asserted)"
            )
        try:
            pkix.validity.check_signature(certificate, issuer)
        except pkix.errors.PkixError as error:
            raise _PathRefusedError(f"signature of {certificate.subject}: {error}") from error
    if not pkix.validity.check_validity(anchor, at).ok:
        raise _PathRefusedError("the trust anchor is not valid at the given time")
    return anchor
