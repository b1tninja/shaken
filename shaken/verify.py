"""Verifying PASSporTs: one token, and the chains of diverted calls (RFC 8224 sec. 6.2, RFC 8946 sec. 4.2).

``verify_passport`` runs, in this order, what a verification service owes one full-form token once
the caller has found the credential: parse (an unsupported ``ppt`` is refused), validate the signer
certificate's chain to the caller's pinned anchors (``credentials.validate_chain``), check the ES256
signature under that certificate's key, hold the claims to the certificate's JWT Claim Constraints
(RFC 8226 sec. 8 and RFC 9118 sec. 3, both extensions when both are present), and optionally check
the freshness of ``iat``. Everything fails closed: any step that cannot be completed is a
``VerificationError``, never a pass.

``verify_div_chains`` and ``verify_div_o`` apply RFC 8946 sec. 4.2 steps 1 to 5 (and sec. 5.1 for
the nested ``opt`` of "div-o") on top of that. The credential for each token comes from a caller
supplied function, because fetching ``x5u`` is the network's and the trust anchors are the owner's
decision (ROADMAP.md); nothing here reads a store or opens a socket.

What is not done here: the comparison of ``orig`` and ``dest`` with the SIP ``From`` and ``To``
(``verify.binding``), the compact form, and the ``attest`` policy. ``verify_request``, which would
take SIP headers, is still a stub.

Freshness windows are conventions of the caller's ``Policy``: sixty seconds is the RECOMMENDED
default (RFC 8224 sec. 6.2 Step 4), and RFC 8946 sec. 4.2 step 4 says a longer window for the
innermost PASSporT of a transferred call "on the order of three hours" might suffice. A token
dated in the future by more than the window is refused too: the RFCs do not say, and a token from
the future cannot be fresh.
"""

from __future__ import annotations

import datetime
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import pkix.validity

from . import claimconstraints, passport, tnauth
from .credentials import ChainResult, CredentialError, signer_verifier, validate_chain
from .div import PPT_DIV_O, DivChain, link_chains
from .jws import JwsError, b64url_decode

if TYPE_CHECKING:
    from asn1core.cert import Certificate

    Headers = Any  # placeholder: give it a real type in the milestone that needs it
    TrustStore = Any  # placeholder: give it a real type in the milestone that needs it
    Verification = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "Credentials",
    "DateCheck",
    "DivVerdict",
    "Policy",
    "VerificationError",
    "Verified",
    "check_date_freshness",
    "check_tn_authority",
    "verify_div_chains",
    "verify_div_o",
    "verify_passport",
    "verify_request",
]

_MAX_OPT_DEPTH = 16  # a bound on the nested "opt" walk, not a protocol limit

Credentials = Callable[[passport.ParsedToken], tuple["Certificate", tuple["Certificate", ...]]]
"""Given a parsed token, return its signer certificate and the intermediates to try.

The caller reads the ``x5u`` header (or whatever its policy allows), fetches under its own bounds
and returns what it got. Raise ``credentials.CredentialError`` when there is none.
"""


class VerificationError(ValueError):
    """A token or chain that does not verify. ``reasons`` lists every rule it broke when known."""

    def __init__(self, message: str, reasons: Sequence[str] = ()) -> None:
        super().__init__(message)
        self.reasons = tuple(reasons)


@dataclass(frozen=True, slots=True)
class Policy:
    """Local policy for a verification (RFC 8224 sec. 6.2.1 leaves it to the verifier).

    ``freshness`` is the window in seconds around the verification time (sixty is RECOMMENDED).
    ``innermost_freshness`` is the window for the innermost PASSporT of a diverted call, and
    defaults to ``freshness``. ``check_innermost`` turns off the RECOMMENDED innermost check.
    ``supported_ppt`` is every ``ppt`` this verifier understands; a token carrying another is not
    verified (RFC 8224 sec. 6.2 Step 1).
    """

    freshness: int = 60
    innermost_freshness: int | None = None
    check_innermost: bool = True
    supported_ppt: frozenset[str] = frozenset({"shaken", "div", "div-o"})

    def __post_init__(self) -> None:
        for window in (self.freshness, self.innermost_freshness):
            if window is not None and window < 0:
                raise ValueError("a freshness window cannot be negative")


@dataclass(frozen=True, slots=True)
class Verified:
    """A token that passed ``verify_passport``: what was parsed and the chain that vouched for it.

    ``constraints_applied`` is the number of JWT Claim Constraints extensions the claims were held
    to (0, 1 or 2). ``chain.checked`` says exactly which RFC 5280 checks stand behind the chain.
    """

    token: passport.ParsedToken
    chain: ChainResult
    constraints_applied: int

    @property
    def signer(self) -> Certificate:
        return self.chain.path[0]


def _check_fresh(iat: int, at: datetime.datetime, window: int, what: str) -> None:
    if abs(at.timestamp() - iat) > window:
        raise VerificationError(f"the {what} iat {iat} is outside the {window} second window")


@dataclass(frozen=True, slots=True)
class DateCheck:
    """The outcome of a passing ``check_date_freshness``.

    ``iat_differs`` is ``None`` when no ``iat`` was given, else whether it names another second
    than the Date. ``use_iat`` is true when RFC 8224 sec. 6.2 Step 4 says the signature check
    (Step 5) should be computed with the ``iat`` in place of the Date.
    """

    iat_differs: bool | None
    use_iat: bool


def check_date_freshness(
    date: datetime.datetime,
    at: datetime.datetime,
    *,
    window: int = 60,
    signer: Certificate | None = None,
    iat: int | None = None,
) -> DateCheck:
    """RFC 8224 sec. 6.2 Step 4: is the request's Date fresh, and inside the signing credential's validity.

    ``date`` is the SIP ``Date`` header already parsed to a timezone-aware instant and ``at`` the
    verification time; no SIP request is modelled. Step 4: the Date must meet local policy for
    freshness ("sixty seconds is RECOMMENDED", ``window``) and "fall within the validity period
    of the credential used to sign" (``signer``, checked at the Date by ``pkix.validity``; pass
    ``None`` to skip that half). A Date from the future by more than ``window`` is refused as
    well, a convention this package applies everywhere (``Policy``): the RFC names only stale
    values. The Date has one-second resolution, so the comparison is in whole seconds.

    With ``iat`` (the full form of PASSporT): "the verifier SHOULD compare the iat value ... to
    the Date". When they differ and the ``iat`` is itself within ``window`` of ``at``, the result
    says ``use_iat`` so Step 5 is computed with the ``iat`` instead of the Date. An ``iat`` that
    differs and is not fresh is not used, and does not fail this check: the RFC attaches no
    refusal to it, and the Date is then what the signature must cover.

    Raises:
        VerificationError: the Date is stale or from the future, or outside the credential's
            validity. RFC 8224 sec. 6.2.2 maps a stale Date to a 403 "Forbidden" response.
        ValueError: ``date`` or ``at`` is naive, or ``window`` is negative.
    """
    for name, value in (("date", date), ("at", at)):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError(f"{name} must be timezone-aware")
    if window < 0:
        raise ValueError("a freshness window cannot be negative")
    date_seconds = int(date.timestamp())
    if abs(int(at.timestamp()) - date_seconds) > window:
        raise VerificationError(f"the Date header is outside the {window} second window")
    if signer is not None:
        result = pkix.validity.check_validity(signer, date)
        if not result.ok:
            raise VerificationError(
                f"the Date header is outside the signing credential's validity ({result.reason})"
            )
    if iat is None:
        return DateCheck(None, False)
    differs = iat != date_seconds
    return DateCheck(differs, differs and abs(int(at.timestamp()) - iat) <= window)


def verify_passport(
    token: str,
    credentials: Credentials,
    anchors: tuple[Certificate, ...],
    at: datetime.datetime,
    *,
    policy: Policy | None = None,
    max_age: int | None = None,
) -> Verified:
    """Verify one full-form PASSporT as of ``at`` (RFC 8224 sec. 6.2 Steps 1, 3, 4, 5; RFC 8226 sec. 8).

    Order: parse, resolve the credential, validate its chain to ``anchors``, check the signature
    under the signer certificate's key, hold the claims to the certificate's claim constraints,
    then check freshness when ``max_age`` seconds is given. The constraints are applied only after
    the chain was accepted, so a certificate nobody trusts never decides anything. A certificate
    carrying both RFC 8226 and RFC 9118 constraints is held to both (PORTFOLIO.md sec. 9 item 15).

    Raises:
        VerificationError: any step failed; ``reasons`` lists constraint violations.
    """
    policy = policy or Policy()
    try:
        parsed = passport.parse(token, supported_ppt=policy.supported_ppt)
        signer, intermediates = credentials(parsed)
        chain = validate_chain(signer, intermediates, anchors, at)
        passport.verify(token, signer_verifier(chain.path[0]), supported_ppt=policy.supported_ppt)
    except (passport.PassportError, CredentialError) as error:
        raise VerificationError(str(error)) from error
    try:
        constraints = claimconstraints.from_certificate(chain.path[0])
    except claimconstraints.ClaimConstraintsError as error:
        raise VerificationError(f"the signer's claim constraints are malformed: {error}") from error
    problems = claimconstraints.check_claims(constraints, parsed.payload)
    if problems:
        raise VerificationError("the claims break the certificate's constraints", problems)
    if max_age is not None:
        _check_fresh(parsed.payload["iat"], at, max_age, "token")
    return Verified(parsed, chain, len(constraints))


def check_tn_authority(signer: Certificate, identifier: tuple[str, str]) -> None:
    """Refuse unless ``signer``'s TN Authorization List authorises ``identifier`` (RFC 8226 sec. 9).

    ``identifier`` is ``("tn", digits)`` or ``("uri", text)``. Only a telephone number can be
    covered by a TNAuthList, so a URI is refused (nothing here can show authority over it), as is a
    certificate with no list, a number the list does not cover, and a number whose answer depends
    on a Service Provider Code registry this package does not have (``tnauth.covers`` returns
    ``None``). Call it after chain validation.
    """
    kind, value = identifier
    if kind != "tn":
        raise VerificationError(
            f"authority over a {kind!r} identifier cannot be shown by a TNAuthList"
        )
    try:
        entries = tnauth.from_certificate(signer)
    except tnauth.TNAuthListError as error:
        raise VerificationError(f"the signer's TNAuthList is malformed: {error}") from error
    if entries is None:
        raise VerificationError("the signer certificate has no TNAuthList")
    answer = tnauth.covers(entries, value)
    if answer is None:
        raise VerificationError(
            "the signer's TNAuthList holds a Service Provider Code, which needs a registry"
        )
    if not answer:
        raise VerificationError(f"the signer's TNAuthList does not cover {value}")


@dataclass(frozen=True, slots=True)
class DivVerdict:
    """The outcome for one chain: its claims sets (outermost first), whether it verified and why not.

    ``ok`` is true only when every check of RFC 8946 sec. 4.2 steps 1 to 5 passed; ``reasons`` is
    then empty. A failed chain lists every reason found, not only the first.
    """

    claims: tuple[Mapping[str, Any], ...]
    ok: bool
    reasons: tuple[str, ...]


def _div_identity(claims: Mapping[str, Any]) -> tuple[str, str]:
    div = claims["div"]
    kind = "tn" if "tn" in div else "uri"
    return kind, div[kind]


def _dest_holds(dest: Mapping[str, Any], identifier: tuple[str, str]) -> bool:
    kind, value = identifier
    return value in dest.get(kind, ())


def _ppt_of(token: str) -> str | None:
    """The ``ppt`` of a token's header, read without trusting anything else about it."""
    try:
        header = json.loads(b64url_decode(token.split(".", 1)[0]))
    except (JwsError, ValueError):
        return None
    ppt = header.get("ppt") if isinstance(header, dict) else None
    return ppt if isinstance(ppt, str) else None


def _judge(
    claims: tuple[Mapping[str, Any], ...],
    verified: Sequence[Verified | VerificationError],
    call_target: tuple[str, str],
    at: datetime.datetime,
    policy: Policy,
) -> DivVerdict:
    """Steps 1 to 5 of RFC 8946 sec. 4.2 over a chain whose members are already verified or failed."""
    reasons: list[str] = []
    outermost, innermost = claims[0], claims[-1]
    # step 1: the outermost dest against the target of the call
    if not _dest_holds(outermost["dest"], call_target):
        reasons.append("step 1: the outermost dest does not hold the call target")
    # steps 2 and 5: every signature; the outermost signer's authority over the div identity
    for position, outcome in enumerate(verified):
        if isinstance(outcome, VerificationError):
            reasons.append(f"step 5: member {position} does not verify: {outcome}")
            reasons.extend(f"  {why}" for why in outcome.reasons)
    first = verified[0]
    if isinstance(first, Verified):
        try:
            check_tn_authority(first.signer, _div_identity(outermost))
        except VerificationError as error:
            reasons.append(f"step 2: {error}")
    # step 3: one orig through the whole chain
    if any(member["orig"] != innermost["orig"] for member in claims):
        reasons.append("step 3: the orig differs between members of the chain")
    # step 4: freshness of the outermost (MUST) and the innermost (RECOMMENDED)
    try:
        _check_fresh(outermost["iat"], at, policy.freshness, "outermost")
    except VerificationError as error:
        reasons.append(f"step 4: {error}")
    if policy.check_innermost:
        window = (
            policy.freshness if policy.innermost_freshness is None else policy.innermost_freshness
        )
        try:
            _check_fresh(innermost["iat"], at, window, "innermost")
        except VerificationError as error:
            reasons.append(f"step 4: {error}")
    return DivVerdict(claims, not reasons, tuple(reasons))


def verify_div_chains(
    tokens: Sequence[str],
    credentials: Credentials,
    anchors: tuple[Certificate, ...],
    at: datetime.datetime,
    call_target: tuple[str, str],
    *,
    policy: Policy | None = None,
) -> tuple[DivVerdict, ...]:
    """Verify the "div" PASSporTs among ``tokens`` (every Identity header of a request), RFC 8946 sec. 4.2.

    The tokens are linked into chains (``div.link_chains``); each chain gets one ``DivVerdict``:
    the outermost ``dest`` must hold ``call_target`` (step 1), the outermost signer must have
    authority over the ``div`` identity (step 2, by TNAuthList), every member must share the
    ``orig`` (step 3), the outermost ``iat`` must be fresh and the innermost one too unless the
    policy turns that RECOMMENDED check off (step 4), and every member's signature, chain and claim
    constraints must verify (step 5). Tokens with a ``ppt`` the policy does not support are left
    out before linking, so a "div" that referred to one cannot complete a chain.

    Raises:
        div.ChainError: no complete chain can be built (sec. 4.2 para 2: "div" validation cannot
            complete; the caller may still ``verify_passport`` the non-"div" tokens).
        VerificationError: a token is not a PASSporT at all.
    """
    policy = policy or Policy()
    kept = [t for t in tokens if (_ppt_of(t) is None or _ppt_of(t) in policy.supported_ppt)]
    try:
        parsed = [passport.parse(t, supported_ppt=policy.supported_ppt) for t in kept]
    except passport.PassportError as error:
        raise VerificationError(str(error)) from error
    chains: tuple[DivChain, ...] = link_chains([p.payload for p in parsed])
    position = {id(p.payload): i for i, p in enumerate(parsed)}
    cache: dict[int, Verified | VerificationError] = {}

    def check(index: int) -> Verified | VerificationError:
        if index not in cache:
            try:
                cache[index] = verify_passport(kept[index], credentials, anchors, at, policy=policy)
            except VerificationError as error:
                cache[index] = error
        return cache[index]

    return tuple(
        _judge(
            chain.claims,
            [check(position[id(member)]) for member in chain.claims],
            call_target,
            at,
            policy,
        )
        for chain in chains
    )


def verify_div_o(
    token: str,
    credentials: Credentials,
    anchors: tuple[Certificate, ...],
    at: datetime.datetime,
    call_target: tuple[str, str],
    *,
    policy: Policy | None = None,
) -> DivVerdict:
    """Verify a "div-o" PASSporT and the PASSporTs nested in its ``opt`` claim (RFC 8946 sec. 5.1).

    No linking is needed: the chain is the nesting. The same checks as ``verify_div_chains`` run
    (sec. 5.1 para 3), and for each nested token its ``dest`` must hold the ``div`` identity of the
    token that encloses it and its ``orig`` must equal the enclosing one. Nested "div-o" tokens
    are followed through their own ``opt``, down to a token without one. The outermost signer's
    authority over its ``div`` identity is checked as in step 2; the nested signers' is not, since
    sec. 4.2 asks for the outermost only.

    Raises:
        VerificationError: the outer token is not a "div-o" PASSporT, or is malformed.
    """
    policy = policy or Policy()
    outcomes: list[Verified | VerificationError] = []
    claims: list[Mapping[str, Any]] = []
    structure: list[str] = []
    current = token
    for depth in range(_MAX_OPT_DEPTH):
        try:
            verified = verify_passport(current, credentials, anchors, at, policy=policy)
        except VerificationError as error:
            if depth == 0 and not claims:
                try:
                    passport.parse(current, supported_ppt=policy.supported_ppt)
                except passport.PassportError as parse_error:
                    raise VerificationError(str(parse_error)) from parse_error
            outcomes.append(error)
            break
        payload = verified.token.payload
        if depth == 0 and (verified.token.ppt != PPT_DIV_O or "div" not in payload):
            raise VerificationError('the outer token is not a "div-o" PASSporT (RFC 8946 sec. 5)')
        if claims:
            enclosing = claims[-1]
            if payload["orig"] != enclosing["orig"]:
                structure.append(f"sec. 5.1: nested token {depth} has another orig")
            if not _dest_holds(payload["dest"], _div_identity(enclosing)):
                structure.append(f"sec. 5.1: nested token {depth} dest does not hold the div")
        outcomes.append(verified)
        claims.append(payload)
        nested = payload.get("opt")
        if "div" not in payload or not isinstance(nested, str):
            break
        current = nested
    else:
        structure.append("sec. 5.1: the opt nesting is deeper than the bound")
    if not claims:
        return DivVerdict((), False, tuple(f"step 5: {outcome}" for outcome in outcomes))
    verdict = _judge(tuple(claims), outcomes[: len(claims)], call_target, at, policy)
    extra = [
        f"step 5: the token nested at depth {len(claims)} does not verify: {outcome}"
        for outcome in outcomes[len(claims) :]
        if isinstance(outcome, VerificationError)
    ]
    reasons = (*verdict.reasons, *structure, *extra)
    return DivVerdict(verdict.claims, not reasons, tuple(reasons))


def verify_request(headers: Headers, store: TrustStore) -> Verification:
    """Pending behaviour defined by RFC 8224 sec. 6.2.

    Not implemented yet. See the ``verify.verify_request()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("verify_request() is not implemented: RFC 8224 sec. 6.2")
