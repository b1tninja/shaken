# Specification completeness -- and the roadmap it implies

This is the project's north star: every protocol obligation shaken could plausibly take on,
with an honest status against the code at `HEAD`. It is blunt about gaps on purpose. A
roadmap that overstates its coverage is not a plan, it is marketing.

**The honesty rule:** a row may read `[ok]` only when a named test would fail if the
behaviour regressed. Reading the code and agreeing with it is not enough. That is how
"decoded but never sent" quietly becomes "implemented".

Legend: `[ok]` implemented and pinned by a named test -- `[part]` partial, with what is
missing stated -- `[ ]` not implemented -- `[no]` deliberate non-goal.

A Where cell marked `(to be written)` names the test that will pin the row once it exists; no
such test has been written yet, and the row cannot leave `[ ]` until it has. The Milestone
column places the row on the ladder in section 2, and `-` means it is not placed yet.

Update the affected row in the same commit that changes the behaviour. A row and its test
drift apart within one release, and the document becomes useless exactly when it is needed.

## 1. Obligations

| Obligation | Spec | Status | Where | Milestone |
|---|---|---|---|---|
| `passport.canonical_json()` | RFC 8225 sec. 9 | `[ok]` | `tests/test_passport.py::test_deterministic_json_rules` | M1 |
| `passport.signing_input()` | RFC 8225 sec. 6 and Appendix A, RFC 7515 sec. 5.1 | `[ok]` | `tests/test_rfc_findings.py::test_rfc8225_appendix_a_encoding_steps_are_correct` | M1 |
| `passport.create()` | RFC 8225 sec. 6, RFC 7515 sec. 5.1, RFC 7518 sec. 3.4 | `[ok]` | `tests/test_passport.py::test_create_matches_the_pinned_vector` | M1 |
| `passport.parse()` | RFC 8225 sec. 4, 5, 8.1, RFC 7515 sec. 5.2 | `[ok]` | `tests/test_passport.py::test_typ_alg_ppt_checked` | M1 |
| `passport.verify()` | RFC 8225 sec. 6, RFC 7515 sec. 5.2: the signature and the token's shape only, not freshness, binding or trust (rows below) | `[part]` | `tests/test_passport.py::test_verify_accepts_the_pinned_vector` | M1 |
| `passport.to_compact()` | RFC 8225 sec. 7 | `[ok]` | `tests/test_passport.py::test_compact_form_round_trip` | M2 |
| `passport.verify_compact()` | RFC 8225 sec. 7 | `[ok]` | `tests/test_passport.py::test_compact_form_round_trip` | M2 |
| `jws.b64url_decode()` | RFC 7515 sec. 2 and Appendix C | `[ok]` | `tests/test_jws.py::test_b64url_decode_strict` | M1 |
| `jws.es256_raw_to_der()` | RFC 7518 sec. 3.4 | `[ok]` | `tests/test_jws.py::test_raw_der_conversion` | M1 |
| `jws.es256_der_to_raw()` | RFC 7518 sec. 3.4 | `[ok]` | `tests/test_jws.py::test_raw_der_conversion` | M1 |
| `claims.shaken_claims()` | RFC 8588 sec. 4, 5, 8; RFC 8225 sec. 5 | `[ok]` | `tests/test_claims.py::test_rfc8588_section_6_payload_with_errata_applied` | M1 |
| `claims.validate_claims()` | RFC 8225 sec. 5, RFC 8224 erratum 5715 | `[ok]` | `tests/test_claims.py::test_dest_shape_is_object_with_arrays` | M1 |
| `claims.validate_shaken_claims()` | RFC 8588 sec. 4, 5 | `[ok]` | `tests/test_claims.py::test_attest_values` | M1 |
| `numbers.canonicalize_tn()` | RFC 8224 sec. 8.3: step 1 only (drop non-digits); converting to a global E.164 number is local policy and not done | `[part]` | `tests/test_claims.py::test_tn_canonical_digits_only` | M1 |
| `identity.build_header()` | RFC 8224 sec. 4 with erratum 6499 | `[ok]` | `tests/test_identity.py::test_roundtrip_build_parse` | M2 |
| `identity.parse_header()` | RFC 8224 sec. 4 with erratum 6499 | `[ok]` | `tests/test_identity.py::test_full_and_compact_forms` | M2 |
| `identity.parse_all()` | RFC 8224 sec. 4 para 1 | `[ok]` | `tests/test_identity.py::test_multiple_identity_headers` | M2 |
| `identity.check_mirrors()` | RFC 8224 sec. 4.1 para 3-5 | `[ok]` | `tests/test_identity.py::test_header_must_mirror_the_identity_parameters` | M2 |
| `tnauth.parse_tn_auth_list()` | RFC 8226 sec. 9, Appendix A | `[ok]` | `tests/test_tnauth.py::test_vector_list_is_read` | M3 |
| `tnauth.from_certificate()` | RFC 8226 sec. 9 | `[ok]` | `tests/test_tnauth.py::test_certificate_carries_the_extension` | M3 |
| `tnauth.covers()` | RFC 8226 sec. 9 para 12-15: numbers and ranges only; a ServiceProviderCode needs a registry | `[part]` | `tests/test_tnauth.py::test_covers` | M3 |
| `credentials.load_certificates()` | RFC 8226 sec. 7, asn1core | `[ok]` | `tests/test_tnauth.py::test_certificate_carries_the_extension` | M3 |
| `credentials.signer_verifier()` | RFC 8225 sec. 4.3, RFC 7518 sec. 3.4 | `[ok]` | `tests/test_tnauth.py::test_certificate_key_verifies_the_pinned_token` | M3 |
| `credentials.resolve()` | RFC 8225 sec. 4.3 | `[ ]` | `tests/test_obligations.py::test_resolve` (to be written) | M3 |
| `attest.policy_for()` | RFC 8588 sec. 4 | `[ ]` | `tests/test_obligations.py::test_policy_for` (to be written) | M4 |
| `verify.verify_request()` | RFC 8224 sec. 6.2 | `[ ]` | `tests/test_obligations.py::test_verify_request` (to be written) | M4 |
| `finding.rfc8225-appendix-a-signature` | RFC 8225 Appendix A | `[ok]` | `tests/test_rfc_findings.py::test_rfc8225_appendix_a_signature_verifies_under_neither_printed_key` | - |
| `finding.rfc8225-appendix-a-keys` | RFC 8225 Appendix A.1, A.2 | `[ok]` | `tests/test_rfc_findings.py::test_rfc8225_appendix_a_keys_are_not_a_pair` | - |
| `finding.rfc8225-section-9-1-json` | RFC 8225 sec. 9.1 | `[ok]` | `tests/test_rfc_findings.py::test_rfc8225_section_9_1_printed_result_is_not_valid_json` | - |
| `finding.rfc8225-section-7-1-string-iat` | RFC 8225 sec. 7.1, erratum 5985 | `[ok]` | `tests/test_rfc_findings.py::test_rfc8225_section_7_1_example_has_a_string_iat` | - |
| `finding.rfc8588-section-6-example` | RFC 8588 sec. 6, erratum 6656 | `[ok]` | `tests/test_rfc_findings.py::test_rfc8588_section_6_example_is_not_valid_json` | - |
| `finding.rfc8225-section-7-1-signature` | RFC 8225 sec. 7.1, RFC 8224 sec. 4.1.1: the A.2 key verifies this example (string iat), and its erratum-5985 correction would not | `[ok]` | `tests/test_rfc_findings.py::test_rfc8225_section_7_1_signature_does_verify_under_the_a2_key_for_its_string_iat_payload` | - |
| `verify.freshness` | RFC 8224 sec. 4.1 para 11 and sec. 6.2 (sixty seconds is RECOMMENDED; read sec. 6.2 first) | `[ ]` | `tests/test_verify.py::test_freshness_window` (to be written) | M4 |
| `verify.binding` | RFC 8224 sec. 6.2: the token's orig and dest against the From and To of the request; `check_mirrors` covers only the header | `[ ]` | `tests/test_verify.py::test_orig_dest_binding` (to be written) | M4 |
| `verify.tn-authority` | RFC 8226 sec. 9 with `tnauth.covers()`, after chain validation | `[ ]` | `tests/test_verify.py::test_tn_authority` (to be written) | M4 |
| `credentials.chain-validation` | RFC 8226 sec. 4 and 7 (read 2026-11-13: sec. 4 says nothing about validation beyond algorithms, sec. 7 leaves acquisition open), RFC 5280 sec. 6: `credentials.validate_chain` runs what pkix provides today (candidate paths by name, validity, each signature, the cA assertion) against pinned anchors; `ChainResult.checked` lists exactly that | `[part]` | `tests/test_credentials.py::test_chain_to_anchor`, `tests/test_credentials.py::test_chain_refusals` | M3 |
| `credentials.chain-constraints` | RFC 5280 sec. 6.1.4 (name, policy and path-length constraints, key usage, critical extensions), sec. 6.3 revocation: waits for pkix `chain.ca_constraints`, `chain.critical_extensions`, `chain.issuer_binding` and its revocation rows, then `validate_chain` calls them; RFC 8226 sec. 10 (freshness and revocation of STI certificates) belongs here | `[ ]` | `tests/test_credentials.py::test_chain_constraints_and_revocation` (to be written) | M3 |
| `credentials.chain-anchor-choice` | which STI-CA roots are pinned is the owner's trust-anchor decision, as in certledger; `validate_chain` takes anchors as an argument and reads no store | `[ ]` | `tests/test_credentials.py::test_pinned_anchor_set` (to be written) | M3 |
| `credentials.x5u-fetch-bounds` | RFC 8225 sec. 4.3, RFC 8224 sec. 7.3; HTTPS only, no redirect to another host, maximum bytes, maximum time, no ambient proxy: conventions unless ATIS-1000074 fixes numbers | `[ ]` | `tests/test_credentials.py::test_fetch_is_bounded` (to be written) | M3 |
| `tnauth.jwt-claim-constraints` | RFC 8226 sec. 8 and RFC 9118 (EnhancedJWTClaimConstraints, updates 8226): `claimconstraints.parse_constraints`, `from_certificate` and `check_claims` | `[ok]` | `tests/test_claimconstraints.py::test_claim_constraints`, `tests/test_claimconstraints.py::test_rfc8226_form_and_malformed_values`, `tests/test_claimconstraints.py::test_baseline_claim_in_must_exclude_means_extension_is_ignored` | M4 |
| `verify.claim-constraints` | RFC 8226 sec. 8 and RFC 9118 sec. 3: `verify_request` must call `claimconstraints.check_claims` with the signer certificate's constraints once chain validation has accepted it; both extensions present is undefined by either RFC | `[ ]` | `tests/test_verify.py::test_claim_constraints_enforced` (to be written) | M4 |
| `tnauth.by-reference` | RFC 8226 sec. 10.1 (TN list by reference, id-ad-stirTNList) | `[ ]` | `tests/test_tnauth.py::test_by_reference` (to be written) | - |
| `passport.mky` | RFC 8225 sec. 5.2.2: the media-key claim, its sort rule and a=fingerprint handling | `[ ]` | `tests/test_passport.py::test_mky` (to be written) | - |
| `passport.div` | RFC 8946 sec. 3, 5, 6 (diverted calls: the div claim, div-o and opt; updates RFC 8224): `div.div_claims`, `div_o_claims`, `validate_div_claims`, `link_chains` | `[part]` | `tests/test_div.py::test_div_claims_follow_rfc_8946_section_3`, `tests/test_div.py::test_div_shape_rules_and_div_o`, `tests/test_div.py::test_chains_link_div_passports_to_their_originals` | - |
| `verify.div-chain` | RFC 8946 sec. 4.2 steps 1-5: outermost dest against the call target, the signer's authority over the `div` identity, orig equality, freshness of outermost and RECOMMENDED innermost iat, every signature in the chain; sec. 5.1 for the nested `opt` of div-o (parse the embedded token and run the same checks) | `[ ]` | `tests/test_verify.py::test_div_chain_verification` (to be written) | M4 |
| `messaging.rcs` | RFC 9475 sec. 3.2: the "msg" type and the "msgi" claim (`messaging.msg_claims`, `msgi_digest`, `msgi_matches`, `validate_msg_claims`); sec. 3.1 sessions need the `mky` claim (row `passport.mky`), sec. 4 certificates need no new code | `[part]` | `tests/test_messaging.py::test_messaging` | - |
| `messaging.msgi-canonicalisation` | RFC 9475 sec. 3.2 para 4 says the digest is over a "canonicalized" MIME body and defines no canonicalisation; two implementations can disagree on line endings. Ask the IETF or find the ATIS profile before fixing a rule | `[ ]` | `tests/test_messaging.py::test_msgi_canonical_form` (to be written) | - |
| `messaging.msgi-extra-hashes` | RFC 9475 sec. 3.2 para 3 MAY support the recommended hashes of the COSE Algorithms registry; needs the registry in primarysource | `[ ]` | `tests/test_messaging.py::test_cose_recommended_hashes` (to be written) | - |
| `finding.rfc8946-div-example` | RFC 8946 sec. 3 and 5: the examples print `"div":{"tn":"121555551213"}` (12 digits) for a diversion from 12155551213; the sec. 3 token's signature verifies under the Appendix A key typo included, the sec. 5 `opt` token's does not | `[ok]` | `tests/test_div.py::test_rfc8946_example_findings` | - |
| `finding.rfc9475-msgi-example` | RFC 9475 sec. 3.2 para 5: the "sha256-" example decodes to 42 octets, not 32; para 3 says "only lowercase letters" for an algorithm name that the same paragraph spells `sha256` | `[ok]` | `tests/test_messaging.py::test_rfc9475_example_is_not_a_sha256_digest` | - |
| `finding.rfc9118-figure-1` | RFC 9118 sec. 5 Figure 1 is a real certificate carrying both a TNAuthList and an Enhanced JWT Claim Constraints extension; it is the positive vector for `tnauth.jwt-claim-constraints` | `[ok]` | `tests/test_claimconstraints.py::test_claim_constraints` | - |
| `identity.ppt-quoting` | RFC 8224 erratum 6519 (held, not verified) asks for quoted ppt; ATIS-1000074 reportedly quotes. `build_header(quote_ppt=)` supports both; the default needs ATIS-1000074 | `[ ]` | `tests/test_identity.py::test_roundtrip_build_parse` | - |
| `jws.other-algorithms` | RFC 8225 sec. 4.2 para 2 allows others; only ES256 is supported. RFC 7518 is updated by RFC 9864 (fully-specified algorithms), which says the JOSE ES256 registration is already fully specified (RFC 9864 sec. 2.1 para 1) | `[no]` | `tests/test_passport.py::test_typ_alg_ppt_checked` | - |
| `ci.asn1core-checkout` | `.github/workflows/ci.yml` still runs `pip install -e ".[dev]"`, which cannot resolve the unpublished `asn1core` dependency, nor now `pkix` (and its `sigwire`); pkix's workflow checks it out into `.deps/` and installs it, and this one must do the same until asn1core publishes | `[ ]` | `.github/workflows/ci.yml` (to be written) | M3 |
| `interop.synthetic-trace` | M5 as synthetic SIP traces signed by a non-Python implementation (a captured carrier trace holds real numbers) | `[ ]` | `tests/test_interop.py::test_synthetic_trace` (to be written) | M5 |

## 2. Milestones

- M1 PASSporT create and verify with canonicalisation vectors
- M2 Identity header build and parse
- M3 credential resolution with x5u bounds and CA pinning
- M4 attestation policy and the verification outcome object
- M5 interop against a captured carrier trace
- M6 publication: 0.1.0

Every milestone is accepted by its rows above flipping to `[ok]` with a named test, not by
the code existing. Coverage in `pyproject.toml` ratchets in the same commit.

## 3. Errata watch

Each entry below was read through rfclib on 2026-11-13 (`errata(ref, status="all")`).

- RFC 8224 (updated by RFC 8946): **5715 verified**, `dest` is an object holding arrays, `{"tn":[...]}` or `{"uri":[...]}`, not an array of objects (the printed sec. 4.1 text contradicts RFC 8225 sec. 5.2.1 and its own example). Applied in `claims.validate_claims()`. **6499 verified**, `signed-identity-digest` is `1*(base64url-char / ".")` with `base64url-char = ALPHA / DIGIT / "-" / "_"`. Applied in `identity.parse_header()`. 5391 held (what `iat` is set from) and 6519 held (quote `ppt`) are not applied; 5390 rejected.
- RFC 8588: **6656 verified**, `iat` in the sec. 6 example is a number. Applied in `claims`. 8414 (reported) only updates a link to ATIS-1000074 v003.
- RFC 8946, RFC 9118, RFC 9475: no erratum on file (rfclib, 2026-11-13). RFC 8946 is itself an update to RFC 8224; RFC 9118 updates RFC 8226.
- RFC 8225: no verified erratum. 5392 (held) is about what time `iat` records; 5985 (reported) is the string `iat` in sec. 7.1. Two further findings are not in the RFC Editor's list and are pinned in `tests/test_rfc_findings.py`: the Appendix A signature verifies under neither printed key and the two keys are not a pair (the A.2 key signs the sec. 7.1 example instead); the sec. 9.1 result string is not valid JSON (a closing brace is missing after the `uri` array).
- RFC 8226 (updated by RFC 9118): 5610 verified, `Of` should be `OF` in the Appendix A ASN.1 (editorial; no effect on the encoding).
- RFC 7518 (updated by RFC 9864): four verified errata, all editorial (6612, 8526, 8568, 8747); none on a rule used here.
- RFC 7515: 7767 reported (integrity protection of header parameters), three rejected. RFC 7519: 8060 verified (header validation defers to RFC 7515), 8388 editorial. `passport.parse()` refuses any `crit` header (RFC 7515 sec. 4.1.11), the safe reading of both.
- Policy questions (what to do with a failed verification) belong to ATIS, not the RFCs. Say which document decided.

## 4. Deliberate non-goals

| Non-goal | Status | Revisit when |
|---|---|---|
| a SIP stack or transport: this handles a header and a token | `[no]` | a named document requires it |
| an STI-VI registry client or policy database service | `[no]` | a named document requires it |
| number routing, carrier relationships or any business logic about who may sign | `[no]` | a named document requires it |

## 5. Open questions

- how x5u retrieval is bounded so a verifier cannot be turned into a traffic amplifier: the row `credentials.x5u-fetch-bounds` lists the limits that need numbers
- M5 (interop against a captured carrier trace): decided in the first pass to use synthetic traces only, because a captured trace holds real telephone numbers; row `interop.synthetic-trace`
- ATIS-1000074 (SHAKEN) cannot be read through rfclib. The edition (v003 is the one RFC 8588 erratum 8414 links) and its text must be obtained by hand before any policy row, `ppt` quoting or a freshness number is closed
- whether to report the RFC 8225 Appendix A and sec. 9.1 findings to the RFC Editor (owner decision)
- chain validation is partial until `pkix` ships path constraints and revocation (rows `credentials.chain-constraints`, `credentials.chain-anchor-choice`); `pkix`'s `result.validate()` is still a stub, so `credentials.validate_chain` composes `chain.candidates`, `validity.check_validity`, `validity.check_signature` and `chain.may_issue` itself and should call `result.validate()` when it exists
- RFC 8226 sec. 8 and RFC 9118 define two extensions and neither says which governs a certificate carrying both; `claimconstraints.from_certificate` prefers RFC 9118's. Owner decision if a stricter reading (apply both) is wanted

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented
