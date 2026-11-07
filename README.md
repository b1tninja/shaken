# shaken

<!-- PyPI badges go live with the first release. Until then a version badge renders
     "no version" on the landing page, which reads as a defect rather than a date, so
     the badges stay commented out until the tag exists.
-->

**Pre-alpha shell.** The package surface, the obligation matrix and the CI gates exist.
No protocol behaviour is implemented: every public function raises `NotImplementedError`,
and the test suite records that rather than hiding it. Read
[ROADMAP.md](ROADMAP.md) before depending on any of it.

shaken -- PASSporT and SIP Identity for telephone traffic

Robocall mitigation runs on PASSporT: a signed assertion about the originating number, carried in a SIP Identity header and verified against a certificate published by the originating provider. RFC 8225 defines the token, RFC 8588 the SHAKEN attestation levels, RFC 8224 the header. Python has none of it: stir is an unrelated package from 2018, passport is a 2014 configuration tool, and shaken and stirshaken are free names as of 2026-11-05. Any Python SIP service today ships unsigned traffic, which increasingly means it is blocked.

## The gap, with a date

PyPI was queried on 2026-11-05 for this name and for every neighbouring project. Landscape
claims rot quickly: two projects in this portfolio shipped within five days of the survey,
which is why the table below carries dates instead of adjectives.

| Project | Version | Last release | Why it is not this project |
|---|---|---|---|
| stir | 0.0.3 | 2018-06-20 | an unrelated microservice merge tool |
| passport | 0.1.1 | 2014-07-22 | a Consul configuration manager |
| shaken, stirshaken | - | - | absent from PyPI (2026-11-05) |

What this project intends to add:

- create and verify a PASSporT with the canonicalisation the specification demands
- build and parse the Identity header including info, ppt and alg parameters
- credential retrieval by x5u with a pinned CA store, and x5c inline validation
- attestation level handling (A, B, C) as explicit policy rather than a boolean
- replay and cache control: iat and txn discipline without inventing a cache

## Specification spine

Status and publication dates below were read from the RFC Editor record on 2026-11-05. A
section number is cited only where that section was read in full; everything else cites the
document, which is the honest grain size for a plan. See [docs/rfc-map.md](docs/rfc-map.md).

| Document | Status | Published | What it gives this project |
|---|---|---|---|
| RFC 8225 | Proposed Standard | 2018-02 | PASSporT: the compact token, its claims and canonicalisation |
| RFC 8224 | Proposed Standard | 2018-02 | the SIP Identity header and verification behaviour |
| RFC 8588 | Proposed Standard | 2019-05 | the SHAKEN extension: attestation levels and origin identifier |
| RFC 9475 | Proposed Standard | 2023-12 | messaging use cases and extensions beyond voice |
| ATIS-1000074 (SHAKEN) | ATIS / SIP Forum | - | the deployment profile that fixes policy, caching and headers |

### Errata watch

- RFC 8224 carries 2 verified errata and is updated by RFC 8946; RFC 8588 carries 1 verified erratum.
- RFC 8225 has 2 errata on file and none verified as of 2026-11-07 (rfclib): 5392 is Held for Document Update and concerns the iat claim, 5985 is Reported and editorial.
- Policy questions (what to do with a failed verification) belong to ATIS, not the RFCs. Say which document decided.

## Module layout

| Module | Responsibility |
|---|---|
| `passport` | token construction, canonicalisation and signature (RFC 8225) |
| `claims` | the registered claims and the SHAKEN extension set (RFC 8225, RFC 8588) |
| `identity` | the SIP header field build and parse (RFC 8224) |
| `credentials` | x5u retrieval with bounds, x5c validation, CA pinning |
| `attest` | attestation levels and the policy a verifier applies (RFC 8588) |
| `verify` | the outcome object: what passed, what was skipped and why |
| `messaging` | the extensions for non-voice communications (RFC 9475) |

## What it does not do

- a SIP stack or transport: this handles a header and a token
- an STI-VI registry client or policy database service
- number routing, carrier relationships or any business logic about who may sign


## Install

```bash
git clone https://github.com/b1tninja/shaken.git
cd shaken
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\\Scripts\\Activate.ps1
pip install -e ".[dev]"
```

Not published to PyPI yet. The name is reserved for this repository's trusted publisher at
the moment of the first release.

## Development

All four gates must pass, on Linux and Windows alike:

```bash
ruff check . && ruff format --check .
mypy shaken
pytest -q --cov
python -O -m pytest -q
```

The last line is the one that matters most in a protocol library. `-O` strips `assert`, and a
parser whose bounds checks were asserts stops being a parser under production flags. Wire
paths raise named exceptions; asserts belong in tests and nowhere else.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
