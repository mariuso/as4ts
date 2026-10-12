# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Wire format locked.** Every source of randomness and time is injectable
  internally (clock, XML ids, MIME boundary, content id, session key, IV), with
  committed byte-identical golden fixtures for the SOAP envelope and multipart
  body. The entropy seam is not a public input (see Removed).
- **`sendAs4` returns facts, not decisions.** The result is a union:
  `receipt-verified`, `receipt-unverified`, `error-signal` (all ebMS errors),
  `no-signal`, `transport-failure`, `not-sent`. The accepted/retryable/fatal/
  unknown mapping moved to the pure `classify(result, table?)`.
- **Signer interface.** `signingKey`/`signingCertificate` are replaced by
  `signer: { certificate, sign(data) }`; `signerFromKey` builds one from a local
  key, and the produced signature is verified before sending.
- **Certificate validation is injected and required.**
  `validateCertificate({ certificatePem, purpose, now })` is a required input;
  `trust` is removed from the core. `src/pki/*` moved behind the
  `certificate-validator` entry point (`createCertificateValidator`).
- **Profile object.** Network constants live in a `profile` input; Peppol is the
  default. No hook may read or modify the envelope.
- **Operational inputs.** Added `signal: AbortSignal`, `http` options,
  `spoolDirectory` (files mode `0600`) and `onEvent`.
- The message timestamp is taken immediately before the envelope is built; the
  `User-Agent` is derived from the package name and version.
- **Test/example crypto moved off `node-forge`.** The test PKI/CRL/OCSP fixtures,
  the golden-fixture generator and the example's PKCS#12 parsing now use
  `pkijs`/`asn1js`, removing the dev-only `node-forge` advisory. The generated
  fixtures are unchanged.

### Added

- Apache-2.0 `LICENSE`; the package is named `as4ts`; `SECURITY.md` points at
  GitHub private vulnerability reporting.
- Three package entry points: sender, certificate validator, classifier, with a
  test that snapshots each exported surface.
- Tests for abort at every phase (asserting no temp files remain), a missing or
  throwing validator, a delegated OCSP responder, CRL fallback, a second send on
  a reused connection, and a forged receipt wrapped around another signer's
  signature.
- `SECURITY.md`, `CHANGELOG.md`, ESLint/Prettier configuration and a CI workflow
  on Node 22 and 24.
- Offline receipt captures made by this project's own sender against real
  Peppol test-network access points (`test/fixtures/captures/`, no third-party
  material) and `test/captures.test.ts`, which verifies each capture's signature,
  C14N, signer chain and binding against the bundled G3 test anchors.

### Removed

- `.lookup/`, `.selftest/`, the sample invoice files, and all company/seat/
  endpoint identifiers from the tree and documentation.
- `entropy` is no longer a `SendAs4Input`. A caller-supplied session key and IV
  could reuse a key/IV pair and break encryption; the send core now takes the
  entropy source as an internal parameter (`sendAs4Internal` in `src/internal.ts`,
  tests only).

### Fixed

- **OCSP responses are matched to the request.** The response `CertID` (hash
  algorithm, issuer-name hash, issuer-key hash and serial) must match, so an
  attacker on the plain-HTTP OCSP path can no longer replay another certificate's
  `good` answer.
- **Abort during receipt verification** returned `not-sent`; it now returns
  `receipt-unverified` with the raw signal, since the message was sent and
  answered.
- **Aborted transport failures** were always `retryable`; classification now keys
  on `requestBytesWritten`, so an abort after upload is `unknown`.
- **Partial receipts** (acknowledging only some of the signed parts) are now
  rejected; every signed reference must be present in the receipt.
- **`502`/`504` with no signal** are classified `unknown` (a gateway may have
  forwarded the message), not `retryable`.
- **`sentAt` is optional** and absent when no envelope was built, instead of an
  empty string.

### Security

- No code path sends without calling the certificate validator.
- TLS 1.2 floor and certificate verification cannot be disabled. The
  caller-supplied HTTP `agent` option was removed: an `https.Agent` can carry
  `rejectUnauthorized: false`, which silently disabled verification. The sender
  now always uses its own agent, so there is no option to turn verification off.
