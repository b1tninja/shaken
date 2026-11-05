"""shaken -- PASSporT and SIP Identity for telephone traffic.

Robocall mitigation runs on PASSporT: a signed assertion about the originating number,
carried in a SIP Identity header and verified against a certificate published by the
originating provider.
"""

from __future__ import annotations

from . import apps, attest, claims, cli, credentials, identity, messaging, passport, verify
from .attest import policy_for
from .claims import shaken_claims
from .credentials import resolve
from .identity import build_header, parse_header
from .passport import create
from .verify import verify_request

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "apps",
    "attest",
    "build_header",
    "claims",
    "cli",
    "create",
    "credentials",
    "identity",
    "messaging",
    "parse_header",
    "passport",
    "policy_for",
    "resolve",
    "shaken_claims",
    "verify",
    "verify_request",
]
