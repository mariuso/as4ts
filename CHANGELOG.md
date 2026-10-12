# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`as4ts/lookup`.** `lookupParticipant(input)` performs exactly one SML/SMP
  discovery and returns a union of facts (`found`, `not-registered`,
  `not-supported`, `signature-invalid`, `unavailable`). It derives the SML DNS
  name from the participant identifier, resolves the SMP with a U-NAPTR lookup,
  fetches the signed service metadata, verifies the SMP's inclusive-C14N
  enveloped XML signature and validates the signer with purpose `smp-signer`,
  then selects the endpoint for the process and transport profile within its
  activation/expiration window. DNS and HTTP are injectable, there is no caching
  and no retry, and `sendAs4` never calls it.
- **The receiving side is reserved.** Receiving is planned but not implemented
  (see [`docs/receiving.md`](docs/receiving.md)); no `receive*` value or type is
  exported yet, and `test/package-surface.test.ts` now fails if one appears. A
  future `receiveAs4` can therefore be added without a breaking rename. **No
  exports were renamed**: nothing sender-specific described a direction-neutral
  thing.

### Changed

- **Shared code is direction-neutral.** WS-Security signature verification moved
  out of `receipt/verify.ts` into `xml/ws-security.ts`; `verifyReceipt` now
  applies only the receipt-specific rules (the signature must cover the signal,
  `RefToMessageId`, the NonRepudiationInformation digests, signer equals
  receiver). `xml/`, `pki/`, `crypto/` and `profile` must not import the
  sender-only modules, enforced by `test/module-layout.test.ts`.
- **Certificate purposes.** `CertificatePurpose` gains `message-signer` (the
  access point that signed an inbound user message) and `smp-signer` (the SMP
  signer). `createCertificateValidator` accepts `intermediatesByPurpose` so an
  SMP CA can be kept from validating an access point certificate and the
  reverse; `message-signer` follows `receipt-signer`.
- **`Signer` doc.** Notes that a future receiver will need an unwrap-key
  operation on the same key holder, so key-service implementations can plan for
  it.
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
- **The PKCS#12 loader picks the certificate that matches the private key.** It
  previously used "first certificate without basic constraints, else file order",
  which chose the CA whenever the manager certificate carried `CA:FALSE` (as
  Peppol AP certificates do) and the CA was listed first — surfacing later as
  `signature.mismatch`.
- **Legacy PKCS#12 containers fail with an actionable message.** Pre-PBES2
  containers (RC2/3DES, e.g. `openssl pkcs12 -legacy`) now report "re-export with
  a current OpenSSL, or pass `--sender-cert`/`--sender-key`" instead of pkijs's
  `Unknown "contentEncryptionAlgorithm"`.

### Security

- No code path sends without calling the certificate validator.
- TLS 1.2 floor and certificate verification cannot be disabled. The
  caller-supplied HTTP `agent` option was removed: an `https.Agent` can carry
  `rejectUnauthorized: false`, which silently disabled verification. The sender
  now always uses its own agent, so there is no option to turn verification off.
