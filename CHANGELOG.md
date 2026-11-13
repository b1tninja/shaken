# Changelog

The format follows Keep a Changelog, and this project adheres to Semantic Versioning.

## Unreleased

### Added

- `jws`: strict base64url, the 64-octet ES256 signature format and DER conversion, and an ES256 signer and verifier over `cryptography`.
- `passport`: deterministic JSON (RFC 8225 sec. 9), `create`, `parse`, `verify`, the compact form.
- `claims`: the SHAKEN claims builder and validators (RFC 8588), with RFC 8224 erratum 5715 and RFC 8588 erratum 6656 applied.
- `identity`: Identity header value build and parse (RFC 8224 sec. 4) with erratum 6499 applied, and the mirror check against the PASSporT header.
- `numbers`: telephone number canonicalisation, step 1 of RFC 8224 sec. 8.3.
- `tnauth`: the TN Authorization List extension (RFC 8226 sec. 9), read through asn1core; `credentials.load_certificates` and `credentials.signer_verifier`.
- `tests/test_rfc_findings.py`: RFC 8225 Appendix A's signature verifies under neither printed key and its two keys are not a pair; RFC 8225 sec. 9.1 and RFC 8588 sec. 6 print invalid JSON.

### Changed

- Runtime dependencies are now `asn1core` (sibling checkout) and `cryptography`; the `crypto` extra is gone.
- `docs/plan.md` now depends on pkix (path validation), not only asn1core.

Still stubs, raising `NotImplementedError`: `credentials.resolve`, `attest.policy_for`, `verify.verify_request`.

## 0.0.0 - 2026-11-05

### Added

- Package skeleton, obligation matrix and CI gates for shaken.
- `shaken.apps` namespace reserved for composition that is not protocol behaviour.
