# Specification completeness -- and the roadmap it implies

This is the project's north star: every protocol obligation shaken could plausibly take on,
with an honest status against the code at `HEAD`. It is blunt about gaps on purpose. A
roadmap that overstates its coverage is not a plan, it is marketing.

**The honesty rule:** a row may read `[ok]` only when a named test would fail if the
behaviour regressed. Reading the code and agreeing with it is not enough. That is how
"decoded but never sent" quietly becomes "implemented".

Legend: `[ok]` implemented and pinned by a named test -- `[part]` partial, with what is
missing stated -- `[ ]` not implemented -- `[no]` deliberate non-goal.

Update the affected row in the same commit that changes the behaviour. A row and its test
drift apart within one release, and the document becomes useless exactly when it is needed.

## 1. Obligations

| Obligation | Spec | Status | Where |
|---|---|---|---|
| `passport.create()` | RFC 8225 | `[ ]` | `tests/test_obligations.py::create` |
| `passport.verify()` | RFC 8225 | `[ ]` | `tests/test_obligations.py::verify` |
| `claims.shaken_claims()` | RFC 8588 | `[ ]` | `tests/test_obligations.py::shaken_claims` |
| `identity.build_header()` | RFC 8224 | `[ ]` | `tests/test_obligations.py::build_header` |
| `identity.parse_header()` | RFC 8224 | `[ ]` | `tests/test_obligations.py::parse_header` |
| `credentials.resolve()` | RFC 8225 | `[ ]` | `tests/test_obligations.py::resolve` |
| `attest.policy_for()` | RFC 8588 | `[ ]` | `tests/test_obligations.py::policy_for` |
| `verify.verify_request()` | RFC 8224 | `[ ]` | `tests/test_obligations.py::verify_request` |

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

- RFC 8224 carries 2 verified errata and is updated by RFC 8946; RFC 8588 carries 1 verified erratum.
- RFC 8225 has 2 errata on file with none verified: re-check the page before M1.
- Policy questions (what to do with a failed verification) belong to ATIS, not the RFCs. Say which document decided.

## 4. Deliberate non-goals

| Non-goal | Status | Revisit when |
|---|---|---|
| a SIP stack or transport: this handles a header and a token | `[no]` | a named document requires it |
| an STI-VI registry client or policy database service | `[no]` | a named document requires it |
| number routing, carrier relationships or any business logic about who may sign | `[no]` | a named document requires it |

## 5. Open questions

- how x5u retrieval is bounded so a verifier cannot be turned into a traffic amplifier

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented
