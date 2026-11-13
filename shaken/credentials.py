"""Reading the credential a PASSporT points at: certificates, signer keys, TN authority.

``load_certificates`` and ``signer_verifier`` are the parts that need no network and no trust
decision: parse what was fetched (certificate parsing is ``asn1core``'s, strict DER) and turn a
certificate's public key into the verifier ``passport.verify`` takes. ``resolve``, which fetches
from ``x5u`` under bounds and validates the chain to a pinned STI trust anchor, is not written:
it needs the network rules of ROADMAP.md section 5 and the path validation ``pkix`` has not
shipped.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from asn1core import pem
from asn1core.cert import Certificate, parse_certificate
from asn1core.errors import Asn1Error

from .jws import Es256Verifier, JwsError

if TYPE_CHECKING:
    from typing import Any

    TrustStore = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "MAX_CHAIN",
    "CredentialError",
    "load_certificates",
    "resolve",
    "signer_verifier",
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
