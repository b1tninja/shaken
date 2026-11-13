"""Verification: claim constraints once the chain is accepted, and RFC 8946 sec. 4.2 chains.

Provenance: every certificate is minted here with ``cryptography`` (root, then signers under it) and
every token is signed by the matching private key, so each signature and each chain link is real.
The TNAuthList and claim-constraint extension values are written with a four-line TLV helper that
shares no code with asn1core, from the ASN.1 of RFC 8226 sec. 9 and sec. 8 and RFC 9118 sec. 3. The
claims of the diverted-call tokens follow RFC 8946 sec. 3 and sec. 4.2 (the RFC's own printed tokens
carry a typo, see ``test_div.py``). No vendor capture and no carrier trace.
"""

from __future__ import annotations

import datetime

import pytest
from asn1core.cert import parse_certificate
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from shaken import passport
from shaken.claimconstraints import ID_PE_EJWT_CLAIM_CONSTRAINTS, ID_PE_JWT_CLAIM_CONSTRAINTS
from shaken.claims import shaken_claims, shaken_header
from shaken.credentials import CredentialError
from shaken.div import ChainError, div_claims, div_header, div_o_claims
from shaken.jws import Es256Signer
from shaken.tnauth import ID_PE_TNAUTHLIST
from shaken.verify import (
    DateCheck,
    Policy,
    VerificationError,
    check_date_freshness,
    check_tn_authority,
    verify_div_chains,
    verify_div_o,
    verify_passport,
)

AT = datetime.datetime(2026, 6, 1, 12, 0, tzinfo=datetime.UTC)
NOW = int(AT.timestamp())
ORIG = "12155551212"
FIRST = "12155551213"  # the called number the first retargeting entity diverts from
SECOND = "12155551214"  # where the call goes next
THIRD = "12155551215"
ORIGID = "123e4567-e89b-12d3-a456-426655440000"


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag, len(content)]) + content


def seq(*items: bytes) -> bytes:
    return tlv(0x30, b"".join(items))


def ia5(text: str) -> bytes:
    return tlv(0x16, text.encode())


def tn_list(*numbers: str) -> bytes:
    """TNAuthorizationList of ``one`` entries: [2] EXPLICIT TelephoneNumber (RFC 8226 sec. 9)."""
    return seq(*(tlv(0xA2, ia5(number)) for number in numbers))


def names(*claims: str) -> bytes:
    return seq(*(ia5(c) for c in claims))


def constraints(*, include=None, permitted=None, exclude=None) -> bytes:
    parts = []
    if include is not None:
        parts.append(tlv(0xA0, names(*include)))
    if permitted is not None:
        claim, *values = permitted
        listed = seq(*(tlv(0x0C, v.encode()) for v in values))
        parts.append(tlv(0xA1, seq(seq(ia5(claim), listed))))
    if exclude is not None:
        parts.append(tlv(0xA2, names(*exclude)))
    return seq(*parts)


def mint(subject, issuer, key, issuer_key, *, ca, extensions=(), days=(-30, 365)):
    def name(common):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common)])

    builder = (
        x509.CertificateBuilder()
        .subject_name(name(subject))
        .issuer_name(name(issuer))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(AT + datetime.timedelta(days=days[0]))
        .not_valid_after(AT + datetime.timedelta(days=days[1]))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    for oid, der in extensions:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier(oid), der), critical=False
        )
    der = builder.sign(issuer_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
    return parse_certificate(der)


ROOT_KEY = ec.generate_private_key(ec.SECP256R1())
ROOT = mint("sti root", "sti root", ROOT_KEY, ROOT_KEY, ca=True)
OTHER_ROOT_KEY = ec.generate_private_key(ec.SECP256R1())
OTHER_ROOT = mint("other root", "other root", OTHER_ROOT_KEY, OTHER_ROOT_KEY, ca=True)


class Party:
    """A signing service provider: a key, a certificate for it and the x5u its tokens name."""

    def __init__(
        self, label, numbers, *, extra=(), issuer=("sti root", ROOT_KEY), tn_authority=True
    ):
        self.signer = Es256Signer.generate()
        self.x5u = f"https://{label}.example/cert.pem"
        key = self.signer._key
        extensions = [(ID_PE_TNAUTHLIST, tn_list(*numbers))] if tn_authority else []
        self.cert = mint(label, issuer[0], key, issuer[1], ca=False,
                         extensions=[*extensions, *extra])  # fmt: skip


def resolver(*parties, intermediates=()):
    table = {p.x5u: p.cert for p in parties}

    def credentials(parsed):
        cert = table.get(parsed.header["x5u"])
        if cert is None:
            raise CredentialError("no credential for " + parsed.header["x5u"])
        return cert, intermediates

    return credentials


def shaken_token(party, *, iat=NOW, attest="A", dest=FIRST):
    claims = shaken_claims(ORIG, [dest], iat=iat, attest=attest, origid=ORIGID)
    return passport.create(claims, shaken_header(party.x5u), party.signer)


def test_a_valid_token_verifies_and_reports_what_stood_behind_it():
    origin = Party("origin", [ORIG])
    verified = verify_passport(shaken_token(origin), resolver(origin), (ROOT,), AT, max_age=60)
    assert verified.token.payload["attest"] == "A"
    assert verified.constraints_applied == 0
    assert verified.chain.anchor.subject == ROOT.subject
    assert verified.signer is verified.chain.path[0]


def test_claim_constraints_enforced():
    """RFC 8226 sec. 8 and RFC 9118 sec. 3, applied after the chain, both extensions together."""
    # RFC 8226: attest must be "B" or "C" (a permitted value), and origid must not appear
    only_bc = (ID_PE_JWT_CLAIM_CONSTRAINTS, constraints(permitted=("attest", "B", "C")))
    no_origid = (ID_PE_EJWT_CLAIM_CONSTRAINTS, constraints(exclude=["origid"]))
    limited = Party("limited", [ORIG], extra=[only_bc])
    with pytest.raises(VerificationError, match="constraints") as caught:
        verify_passport(shaken_token(limited, attest="A"), resolver(limited), (ROOT,), AT)
    assert any("attest must be one of" in why for why in caught.value.reasons)
    passed = verify_passport(shaken_token(limited, attest="B"), resolver(limited), (ROOT,), AT)
    assert passed.constraints_applied == 1
    # RFC 9118 mustExclude: the shaken claim set carries origid, so this signer cannot sign it
    excluding = Party("excluding", [ORIG], extra=[no_origid])
    with pytest.raises(VerificationError) as caught:
        verify_passport(shaken_token(excluding), resolver(excluding), (ROOT,), AT)
    assert caught.value.reasons == ("origid must not appear (mustExclude)",)
    # a certificate with both extensions is held to both: here only the second is broken
    both = Party("both", [ORIG], extra=[only_bc, no_origid])
    with pytest.raises(VerificationError) as caught:
        verify_passport(shaken_token(both, attest="B"), resolver(both), (ROOT,), AT)
    assert caught.value.reasons == ("origid must not appear (mustExclude)",)
    # a mustInclude of a claim the token lacks
    needs_more = Party(
        "needs", [ORIG], extra=[(ID_PE_JWT_CLAIM_CONSTRAINTS, constraints(include=["confidence"]))]
    )
    with pytest.raises(VerificationError) as caught:
        verify_passport(shaken_token(needs_more), resolver(needs_more), (ROOT,), AT)
    assert caught.value.reasons == ("confidence must appear (mustInclude)",)


def test_constraints_are_not_consulted_until_the_chain_is_accepted():
    """A violating token under an untrusted root is refused for the chain, not for the claims."""
    excluding = (ID_PE_EJWT_CLAIM_CONSTRAINTS, constraints(exclude=["origid"]))
    stranger = Party("stranger", [ORIG], extra=[excluding], issuer=("other root", OTHER_ROOT_KEY))
    with pytest.raises(VerificationError) as caught:
        verify_passport(shaken_token(stranger), resolver(stranger), (ROOT,), AT)
    assert "constraints" not in str(caught.value)
    assert caught.value.reasons == ()


def test_malformed_claim_constraints_fail_closed():
    broken = Party("broken", [ORIG], extra=[(ID_PE_JWT_CLAIM_CONSTRAINTS, b"\x04\x00")])
    with pytest.raises(VerificationError, match="malformed"):
        verify_passport(shaken_token(broken), resolver(broken), (ROOT,), AT)


def test_other_failures_are_refusals_not_passes():
    origin = Party("origin", [ORIG])
    credentials = resolver(origin)
    token = shaken_token(origin)
    forged = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
    with pytest.raises(VerificationError):
        verify_passport(forged, credentials, (ROOT,), AT)
    with pytest.raises(VerificationError):  # no anchors, no trust
        verify_passport(token, credentials, (), AT)
    with pytest.raises(VerificationError):  # the credential resolver found nothing
        verify_passport(token, resolver(), (ROOT,), AT)
    with pytest.raises(VerificationError, match=r"not valid JSON|3 dot-separated"):
        verify_passport("not.a.token.at.all", credentials, (ROOT,), AT)
    with pytest.raises(VerificationError, match="window"):  # stale by two minutes
        verify_passport(shaken_token(origin, iat=NOW - 120), credentials, (ROOT,), AT, max_age=60)
    with pytest.raises(VerificationError, match="window"):  # from the future
        verify_passport(shaken_token(origin, iat=NOW + 120), credentials, (ROOT,), AT, max_age=60)
    ppt_only_shaken = Policy(supported_ppt=frozenset({"shaken"}))
    div_party = Party("div", [FIRST])
    div_token = passport.create(
        div_claims(
            {"dest": {"tn": [FIRST]}, "iat": NOW, "orig": {"tn": ORIG}},
            diverted_from=("tn", FIRST),
            new_dest={"tn": [SECOND]},
        ),
        div_header(div_party.x5u),
        div_party.signer,
    )
    with pytest.raises(VerificationError, match="unsupported"):
        verify_passport(div_token, resolver(div_party), (ROOT,), AT, policy=ppt_only_shaken)


def test_tn_authority():
    holder = Party("holder", [FIRST])
    check_tn_authority(holder.cert, ("tn", FIRST))
    with pytest.raises(VerificationError, match="does not cover"):
        check_tn_authority(holder.cert, ("tn", SECOND))
    with pytest.raises(VerificationError, match="'uri'"):
        check_tn_authority(holder.cert, ("uri", "sip:a@example.net"))
    bare = Party("bare", [], tn_authority=False)
    with pytest.raises(VerificationError, match="no TNAuthList"):
        check_tn_authority(bare.cert, ("tn", FIRST))
    spc = Party("spc", [])
    spc_cert = mint(
        "spc", "sti root", ec.generate_private_key(ec.SECP256R1()), ROOT_KEY, ca=False,
        extensions=[(ID_PE_TNAUTHLIST, seq(tlv(0xA0, ia5("1234"))))],
    )  # fmt: skip
    assert spc.cert is not None
    with pytest.raises(VerificationError, match="Service Provider Code"):
        check_tn_authority(spc_cert, ("tn", FIRST))


# --- diverted calls ----------------------------------------------------------------------------


def original_token(origin):
    """The innermost PASSporT: ORIG called FIRST."""
    return shaken_token(origin, dest=FIRST)


def div_token(party, claims_dest, diverted_from, *, iat=NOW):
    original = {"dest": {"tn": [diverted_from]}, "iat": iat, "orig": {"tn": ORIG}}
    claims = div_claims(
        original, diverted_from=("tn", diverted_from), new_dest={"tn": [claims_dest]}, iat=iat
    )
    return passport.create(claims, div_header(party.x5u), party.signer)


def chain_world():
    origin = Party("origin", [ORIG])
    first = Party("first", [FIRST])
    second = Party("second", [SECOND])
    return origin, first, second


def test_div_chain_verification():
    origin, first, second = chain_world()
    tokens = [
        original_token(origin),  # ORIG -> FIRST
        div_token(first, SECOND, FIRST),  # diverted from FIRST to SECOND
        div_token(second, THIRD, SECOND),  # diverted from SECOND to THIRD
    ]
    credentials = resolver(origin, first, second)
    target = ("tn", THIRD)
    (verdict,) = verify_div_chains(tokens, credentials, (ROOT,), AT, target)
    assert verdict.ok, verdict.reasons
    assert [c["dest"]["tn"] for c in verdict.claims] == [[THIRD], [SECOND], [FIRST]]
    # the order of the Identity header fields is not significant (RFC 8946 sec. 3 para 15)
    (shuffled,) = verify_div_chains(tokens[::-1], credentials, (ROOT,), AT, target)
    assert shuffled.ok

    # step 1: the outermost dest must hold the call target
    (wrong_target,) = verify_div_chains(tokens, credentials, (ROOT,), AT, ("tn", "19995550000"))
    assert not wrong_target.ok
    assert any(why.startswith("step 1") for why in wrong_target.reasons)


def test_div_chain_step_2_the_signer_needs_authority_over_the_div_identity():
    origin, first, _second = chain_world()
    impostor = Party("impostor", ["19995550000"])  # signs a div for a number it does not hold
    tokens = [original_token(origin), div_token(impostor, SECOND, FIRST)]
    (verdict,) = verify_div_chains(
        tokens, resolver(origin, first, impostor), (ROOT,), AT, ("tn", SECOND)
    )
    assert not verdict.ok
    assert any(why.startswith("step 2") and "does not cover" in why for why in verdict.reasons)


def test_div_chain_step_3_orig_must_not_change():
    origin, first, _second = chain_world()
    # the retargeting entity alters orig: link_chains will not take it for a parent at all
    altered = {"dest": {"tn": [FIRST]}, "iat": NOW, "orig": {"tn": "12155559999"}}
    claims = div_claims(altered, diverted_from=("tn", FIRST), new_dest={"tn": [SECOND]})
    bad = passport.create(claims, div_header(first.x5u), first.signer)
    with pytest.raises(ChainError):
        verify_div_chains(
            [original_token(origin), bad], resolver(origin, first), (ROOT,), AT, ("tn", SECOND)
        )


def test_div_chain_step_4_freshness_of_the_outermost_and_the_innermost():
    origin, first, _second = chain_world()
    credentials = resolver(origin, first)
    target = ("tn", SECOND)
    old = NOW - 3600
    # a stale innermost token replayed under a fresh div (sec. 4.2 step 4)
    replay = [shaken_token(origin, iat=old), div_token(first, SECOND, FIRST, iat=NOW)]
    (verdict,) = verify_div_chains(replay, credentials, (ROOT,), AT, target)
    assert not verdict.ok
    assert any("innermost iat" in why for why in verdict.reasons)
    # a longer innermost window for a transferred call (three hours is the RFC's upper bound)
    (longer,) = verify_div_chains(
        replay, credentials, (ROOT,), AT, target, policy=Policy(innermost_freshness=3 * 3600)
    )
    assert longer.ok, longer.reasons
    # the innermost check is RECOMMENDED, so a policy may switch it off
    (off,) = verify_div_chains(
        replay, credentials, (ROOT,), AT, target, policy=Policy(check_innermost=False)
    )
    assert off.ok
    # the outermost is a MUST and no policy switch removes it
    stale_outer = [shaken_token(origin, iat=old), div_token(first, SECOND, FIRST, iat=old)]
    (outer,) = verify_div_chains(
        stale_outer, credentials, (ROOT,), AT, target, policy=Policy(check_innermost=False)
    )
    assert not outer.ok
    assert any("outermost iat" in why for why in outer.reasons)


def test_div_chain_step_5_every_signature_in_the_chain():
    origin, first, second = chain_world()
    credentials = resolver(origin, first, second)
    tokens = [
        original_token(origin),
        div_token(first, SECOND, FIRST),
        div_token(second, THIRD, SECOND),
    ]
    # spoil the signature of the middle one: it is neither the outermost nor the innermost
    middle = tokens[1]
    tokens[1] = middle[:-4] + ("AAAA" if not middle.endswith("AAAA") else "BBBB")
    (verdict,) = verify_div_chains(tokens, credentials, (ROOT,), AT, ("tn", THIRD))
    assert not verdict.ok
    assert any(why.startswith("step 5: member 1") for why in verdict.reasons)
    # and the innermost signed by a key under another root
    stranger = Party("stranger", [ORIG], issuer=("other root", OTHER_ROOT_KEY))
    inner = shaken_token(stranger)
    (untrusted,) = verify_div_chains(
        [inner, div_token(first, SECOND, FIRST)],
        resolver(stranger, first),
        (ROOT,),
        AT,
        ("tn", SECOND),
    )
    assert not untrusted.ok
    assert any(why.startswith("step 5: member 1") for why in untrusted.reasons)


def test_div_chain_without_a_complete_chain_cannot_be_validated():
    origin, first, _second = chain_world()
    credentials = resolver(origin, first)
    with pytest.raises(ChainError):  # the div has no earlier PASSporT whose dest holds its div
        verify_div_chains(
            [div_token(first, SECOND, FIRST)], credentials, (ROOT,), AT, ("tn", SECOND)
        )
    with pytest.raises(ChainError):
        verify_div_chains([original_token(origin)], credentials, (ROOT,), AT, ("tn", FIRST))
    # an innermost token with an unsupported ppt is dropped, so the div cannot complete a chain
    only_div = Policy(supported_ppt=frozenset({"div", "div-o"}))
    with pytest.raises(ChainError):
        verify_div_chains(
            [original_token(origin), div_token(first, SECOND, FIRST)],
            credentials, (ROOT,), AT, ("tn", SECOND), policy=only_div,
        )  # fmt: skip


def test_div_o_nested_opt_is_verified_as_a_chain():
    origin, first, second = chain_world()
    credentials = resolver(origin, first, second)
    original = {"dest": {"tn": [FIRST]}, "iat": NOW, "orig": {"tn": ORIG}}
    inner_token = original_token(origin)
    first_claims = div_o_claims(
        original, inner_token, diverted_from=("tn", FIRST), new_dest={"tn": [SECOND]}
    )
    first_token = passport.create(first_claims, div_header(first.x5u, original=True), first.signer)
    second_claims = div_o_claims(
        {"dest": {"tn": [SECOND]}, "iat": NOW, "orig": {"tn": ORIG}},
        first_token,
        diverted_from=("tn", SECOND),
        new_dest={"tn": [THIRD]},
    )
    outer = passport.create(second_claims, div_header(second.x5u, original=True), second.signer)
    verdict = verify_div_o(outer, credentials, (ROOT,), AT, ("tn", THIRD))
    assert verdict.ok, verdict.reasons
    assert [c["dest"]["tn"] for c in verdict.claims] == [[THIRD], [SECOND], [FIRST]]
    # step 1 and step 2 apply to the outermost
    wrong = verify_div_o(outer, credentials, (ROOT,), AT, ("tn", FIRST))
    assert not wrong.ok
    assert any(why.startswith("step 1") for why in wrong.reasons)
    # an old nested original is caught by the innermost freshness check
    stale_inner = shaken_token(origin, iat=NOW - 7200)
    stale_first = passport.create(
        div_o_claims(original, stale_inner, diverted_from=("tn", FIRST), new_dest={"tn": [SECOND]}),
        div_header(first.x5u, original=True),
        first.signer,
    )
    stale = verify_div_o(stale_first, credentials, (ROOT,), AT, ("tn", SECOND))
    assert not stale.ok
    assert any("innermost iat" in why for why in stale.reasons)
    # a nested token that does not verify is reported, not skipped
    stranger = Party("stranger", [ORIG], issuer=("other root", OTHER_ROOT_KEY))
    bad_first = passport.create(
        div_o_claims(
            original, shaken_token(stranger), diverted_from=("tn", FIRST), new_dest={"tn": [SECOND]}
        ),
        div_header(first.x5u, original=True),
        first.signer,
    )
    untrusted = verify_div_o(
        bad_first, resolver(origin, first, stranger), (ROOT,), AT, ("tn", SECOND)
    )
    assert not untrusted.ok
    assert any("nested at depth" in why for why in untrusted.reasons)
    # the outer token must be a div-o
    with pytest.raises(VerificationError, match="div-o"):
        verify_div_o(inner_token, credentials, (ROOT,), AT, ("tn", FIRST))


def at(seconds):
    return AT + datetime.timedelta(seconds=seconds)


def test_date_freshness_step_4():
    """RFC 8224 sec. 6.2 Step 4: the Date within the window and inside the credential's validity."""
    signer = Party("alice", [ORIG]).cert  # valid from 30 days before AT to 365 days after
    # sixty seconds is RECOMMENDED: the boundary is inside, one second more is stale
    assert check_date_freshness(at(-60), AT, signer=signer) == DateCheck(None, False)
    assert check_date_freshness(at(60), AT) == DateCheck(None, False)
    with pytest.raises(VerificationError, match="60 second"):
        check_date_freshness(at(-61), AT, signer=signer)
    with pytest.raises(VerificationError, match="60 second"):
        check_date_freshness(at(61), AT)  # from the future is refused too, a convention
    # the window is local policy
    assert check_date_freshness(at(-300), AT, window=300).iat_differs is None
    with pytest.raises(VerificationError):
        check_date_freshness(at(-301), AT, window=300)
    # the Date must also be inside the validity period of the credential that signed
    with pytest.raises(VerificationError, match="not_yet_valid"):
        check_date_freshness(
            AT - datetime.timedelta(days=31), AT - datetime.timedelta(days=31), signer=signer
        )
    late = AT + datetime.timedelta(days=366)
    with pytest.raises(VerificationError, match="expired"):
        check_date_freshness(late, late, signer=signer)
    # a naive instant has no meaning and a negative window is a mistake
    with pytest.raises(ValueError, match="timezone-aware"):
        check_date_freshness(datetime.datetime(2026, 6, 1, 12, 0), AT)
    with pytest.raises(ValueError, match="negative"):
        check_date_freshness(AT, AT, window=-1)


def test_date_freshness_compares_the_iat_of_the_full_form():
    """Step 4: if iat differs from the Date but is within policy, Step 5 should use the iat."""
    date = at(-10)
    same = check_date_freshness(date, AT, iat=int(date.timestamp()))
    assert same == DateCheck(False, False)
    near = check_date_freshness(date, AT, iat=NOW - 3)
    assert near == DateCheck(True, True)
    # an iat that differs and is itself stale is not used, and does not fail the request
    stale = check_date_freshness(date, AT, iat=NOW - 3600)
    assert stale == DateCheck(True, False)
    # the Date's whole second is what is compared
    assert check_date_freshness(date + datetime.timedelta(milliseconds=500), AT, iat=NOW - 10) == (
        DateCheck(False, False)
    )
