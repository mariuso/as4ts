# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0-rc.3] - 2026-10-15

A release candidate that completes the bounded, streaming receive path. The
receiving side now parses MIME incrementally with spooled parts, inspects the SBDH
header while streaming the recovered document, and preflights and bounds every XML
parse and canonicalisation, with a measured 500 MiB / four-concurrent-open
contract. On the sending side it bounds receipt, error-signal and SMP lookup
parsing, and it no longer caches a revocation-service outage for a full hour.

### Added

- **Bounded inbound limits (`InboundLimits`).** `openAs4Message` now accepts
  `limits: Partial<InboundLimits>`: every omitted property falls back to its
  default, so supplying one bound never silently removes another. New fields:
  `maxDomXmlBytes` (uncompressed XML eligible for DOM processing),
  `maxCanonicalBytes`, and the structural `maxXmlDepth`, `maxXmlNodes`,
  `maxXmlAttributes` and `maxXmlTokenBytes`. `maxXmlBytes` now bounds only the
  incrementally inspected (SBDH) document, not DOM parsing. `resolveInboundLimits`
  and `validateInboundLimits` are exported, and an invalid configuration is
  reported as the new receiving `limits.invalid` failure before anything is
  parsed. A caller that still passes only `maxXmlBytes` gets
  `maxDomXmlBytes = min(default, maxXmlBytes)`: lowering the legacy limit still
  tightens the DOM budget, raising it never raises it.
- **New inbound failure reasons** `xml.too-many-attributes` and
  `xml.token-too-large`, also members of `SbdhResourceLimit`, so an over-limit
  header is reported as `sbdh.status: 'resource-limit'` with the parser's reason
  rather than as malformed.
- **`ResolvedAttachment.spoolPath`.** The MIME parser now hands recovery a
  parser-owned spool to move (a single rename on the same filesystem) instead of a
  ciphertext stream to copy; `source` is correspondingly optional, for a caller
  that drives recovery directly. A failed transfer is a local storage failure
  (`payload.spool-failed`), never a silent re-spool.
- `responseLimits` on `sendAs4` / `transmitAs4` and `limits` on `lookupParticipant`,
  with `defaultResponseLimits` / `defaultLookupLimits` and their types exported, to
  bound receipt, error-signal and SMP lookup XML parsing and canonicalisation.
- The `limits.invalid` not-sent reason (classified `fatal`) and an optional,
  secret-free `detail` on `NoSignalResult`.
- `RevocationPolicy.unknownCacheMs`, the maximum cache lifetime for an `unknown`
  revocation answer (default 60 s).
- **A measured receiving contract and harness.** `npm run measure:receive`
  generates deterministic signed fixtures and measures the bundled receiver in a
  fresh child under plain `node`; the 500 MiB claim, its limits override and how to
  reproduce it are in [`docs/receiving-limits.md`](docs/receiving-limits.md), with
  the recorded macOS and Linux results in
  [`docs/receiving-measurements.md`](docs/receiving-measurements.md).

### Changed

- **MIME parsing is incremental.** Each non-SOAP part is streamed into a
  parser-owned spool file with backpressure rather than buffered, so peak memory
  does not grow with the request body; only the bounded SOAP envelope is held in
  memory. The parser's spool and recovery's workspace share the caller's
  `spoolDirectory` filesystem, and the transfer between them is a rename.
- **SBDH inspection streams.** The recovered document is inspected incrementally
  with bounded retention of only the SBDH facts needed for comparison, while the
  whole document is still parsed, so malformed content after the header and a
  second header are still detected. The header budgets are separate from the
  document budget.
- **XML is preflighted and bounded.** Before the DOM is built, a bounded SAX pass
  enforces depth, node, attribute and lexical-token limits, and canonicalisation
  checks a conservative expansion bound before allocating. Only XML 1.0 is
  accepted (XML 1.1 is rejected) on both the streaming and DOM paths.
- Receipts, error signals and SMP lookup responses are parsed strictly
  (`parseStrictXml`): malformed, encoding-mismatched or DOCTYPE-bearing responses
  that were previously repaired are now `no-signal` / `unavailable`, and receipt
  and SMP canonicalisation are bounded before they run.
- An unreachable revocation service is now remembered for 60 s instead of the
  full `maxCacheMs` (60 min by default), so a recovered service is used again
  quickly.

### Fixed

- **`abortableStream` no longer retains consumed chunks.** Before the fix the MIME
  parser kept the whole request body in memory while parsing — before
  authentication, up to `maxRequestBytes` per concurrent receive — and the SBDH
  and spool readers retained their streams when the caller passed a signal.
- **The sender no longer reports `not-sent` for an unexpected parse error after
  the request went out.** Reading or parsing a response that throws unexpectedly
  now yields `no-signal` with `detail: 'internal.error'`, instead of claiming a
  request that was definitely sent was never sent.
- The MIME parser honours the configured `spoolDirectory`. It previously always
  spooled under the OS temporary directory, so the initial quarantine ignored the
  caller's storage choice and a cross-filesystem rename could fail.
- Filesystem failures while parsing are reported as `payload.spool-failed`
  (stage `payload`) instead of an internal error.
- SBDH header accounting is bound to the namespace-validated header element, and
  an XML 1.1 declaration or a lexical/SAX divergence fails closed, so an
  over-limit or lookalike header can no longer be silently reported as
  consistent.

## [0.2.0-rc.1] - 2026-10-13

A release candidate for the inbound receiving side. The signature-coverage policy
is selected but **not yet frozen** — it awaits captured wire bytes from independent
senders — and peer interoperability and the Peppol Testbed are not yet complete.
See [`docs/receiving-coverage.md`](docs/receiving-coverage.md) and
[`docs/receiving-fixtures.md`](docs/receiving-fixtures.md).

### Added

- **Inbound receiving: `openAs4Message` and `respondAs4Message`.** `openAs4Message`
  verifies and unpacks one inbound `UserMessage` — bounded MIME parsing, strict
  XML, WS-Security signature and coverage (`eb:Messaging`, the SOAP Body and every
  attachment), signer validation with purpose `message-signer`, session-key unwrap
  with rollover, ciphertext-only quarantine with a two-pass recovery,
  decompression and payload recovery — and returns verified facts, owned
  disposable handles and a serialisable receipt context. `respondAs4Message`
  returns the exact signed receipt or ebMS error bytes once the caller has durably
  accepted the document. Expected failures are values with a stage, a reason and
  whether a correlated error is answerable.
- **`as4ts/receive` entry point** (`openAs4Message`, `respondAs4Message`,
  `keyHolderFromKey`, `ebmsErrorFor`, `notServicedError`, `defaultInboundLimits`) —
  a fifth package entry point.
- **Durable-inbox example** (`npm run examples:receive`) demonstrating
  commit-before-acknowledge, per-message serialisation, atomic fsynced publication,
  duplicate suppression and lost-response recovery.
- **Inbound capture harness and Phase 6 validation gate** (`npm run validate:receive`),
  which requires successful, receipt-accepted captures from two distinct sender
  implementations.

### Changed

- **Shared ebMS error definitions.** Direction-neutral error metadata (code, name,
  severity, category) moved out of the sender classification layer; receiving maps
  each failure reason deliberately and keeps local diagnostics off the wire.
- **`verifyReceipt` compares full reference semantics.** Receipt acknowledgements
  are compared against the supplied digest method, ordered transforms and
  inclusive-prefix parameters, not only URI/digest pairs, so a peer that used
  supported canonicalisation parameters is accepted. The fixed expectations for
  the sender's own URI/digest-only references are unchanged.
- **Five package entry points** (adds `./receive`).

## [0.1.0] - 2026-10-13

### Changed

- **Publishing metadata.** The README installs from the GitHub repository
  (`npm install github:mariuso/as4ts`) instead of an unregistered npm name;
  `package.json` gains `repository`, `bugs`, `homepage` and the `./lookup`
  export; `SECURITY.md` lists the lookup code in scope.
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

- **Replayable outbound messages: `prepareAs4` and `transmitAs4`.** `prepareAs4`
  validates the receiver certificate, spools the encrypted payload, and signs the
  envelope, producing an immutable `PreparedMessage` artifact (`metadata.json` plus
  the encrypted attachment). `transmitAs4` performs one attempt against it without
  rebuilding or re-signing anything, so a retry re-sends byte-identical content and
  verifies the receipt against the original signed references.
  `loadPreparedMessage` reloads a persisted artifact (for example after a restart).
  `sendAs4` is unchanged as the one-shot convenience over the two.
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
- Apache-2.0 `LICENSE`; the package is named `as4ts`; `SECURITY.md` points at
  GitHub private vulnerability reporting.
- Four package entry points: sender, certificate validator, classifier and
  lookup, with a test that snapshots each exported surface.
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

- **OCSP `nextUpdate` presence was conflated with absence.** A `[0] EXPLICIT`
  `nextUpdate` that was present but not a valid time was treated as absent and fell
  through to the max-age window; it is now rejected as `unknown`. Unsupported OCSP
  response versions and unrecognized critical extensions at the response and
  SingleResponse levels are rejected as well.
- **A delegated responder's `byKey` identifier was decoded incorrectly.** The
  parser treated the inner OCTET STRING's hash bytes as ASN.1, so a
  correctly-encoded `[2] EXPLICIT` ResponderID was rejected. It now unwraps the
  OCTET STRING directly; the test fixture emits the normative explicit encoding,
  and `byName` and `byKey` are both covered.
- **An invalid CRL `nextUpdate` could create a cache entry that never expired.**
  Invalid or non-monotonic CRL dates are rejected, and `RevocationCache` now
  refuses a non-finite expiry, so a malformed `expiresAt` can no longer be served
  indefinitely.
- **OCSP `nextUpdate` was never parsed, and `thisUpdate` was optional.** OCSP
  encodes `nextUpdate` inside `[0] EXPLICIT`, but the parser looked for two direct
  time fields, so a correctly-encoded expired `nextUpdate` was ignored and an
  answer missing the mandatory `thisUpdate` still returned `good`. The
  `SingleResponse` is now decoded positionally, `thisUpdate` is required, and a
  malformed or inconsistent date is rejected.
- **OCSP freshness could outlive the answer.** An answer without `nextUpdate` is
  now bounded by `ocspMaxAgeMs` (default 24 hours, configurable) and expires at
  `thisUpdate + ocspMaxAgeMs`, so it is never cached beyond that.
- **CRL verification accepted CRLs that do not cover the certificate.** Delta
  CRLs, scoped or indirect CRLs, and unknown critical CRL extensions are now
  rejected; the CRL issuer Name must match the certificate issuer (full `Name`,
  not common name); the issuer must assert `cRLSign` when Key Usage is present;
  and a CRL without `nextUpdate` is rejected.
- **A delegated OCSP responder was not bound to the response.** The responder
  certificate must now match the response's `ResponderID` (by name or key hash),
  assert `digitalSignature` when Key Usage is present, and carry no unsupported
  critical extension.
- **The signer could not be cancelled.** `Signer.sign` now accepts an optional
  `AbortSignal`; the sender passes its own signal to the signer and stops starting
  new phases once the caller aborts. `signerFromKey` refuses to sign when the
  signal is already aborted.
- **Response parsing had no explicit XML/MIME budgets.** The signal parser now
  rejects a document type declaration, enforces element-count and depth budgets,
  and bounds the MIME part count and per-part header size.
- **Local spool failures were reported as `internal.error`.** A filesystem error
  while creating the workspace or spooling the payload now yields
  `not-sent`/`spool.failed` (retryable), preserving the fact that no HTTP request
  had started.
- **`requestBytesWritten` overstated what it measured.** The transport-failure
  field is renamed to `requestMayHaveBeenSent`: a conservative fact, true once the
  connection was established (after which the request may have reached the
  receiver) and false only when nothing was sent.
- **Error signal descriptions conflated two things.**
  `eb:Error/@shortDescription` and the `eb:Description` element are now parsed
  into distinct `shortDescription` and `description` fields.
- **Signal parsing accepted shapes it should reject.** The parser now requires a
  SOAP 1.1 or 1.2 envelope with exactly one Header and Body, a `Messaging` that is
  a direct child of `Header`, and a single `SignalMessage`/`UserMessage`; a
  `SignalMessage` mixing a `Receipt` with `Error`s (or carrying more than one
  `Receipt`) is rejected.
- **Error signals were not correlated with the message.** Any parsed error became
  `error-signal` and was classified by its code, so a signal naming a different
  message could stop delivery. `error-signal` now carries `refToMessageId` and a
  `correlation` fact (`matches` / `absent` / `mismatched`); a `mismatched` signal
  is classified `unknown` and cannot establish rejection.
- **A spool cleanup failure could override the send result.** The `finally` block
  awaited cleanup unguarded, so an `rm` failure replaced an already-computed
  outcome (including `receipt-verified`) with a rejection. Cleanup failure is now
  reported through a `cleanup` event on `onEvent` and never changes the result,
  and the workspace marks itself cleaned only after removal succeeds so a failed
  cleanup can be retried.
- **Certificate path validation missed constraints.** The constrained validator
  now decodes Basic Constraints and Key Usage from DER (Node's `keyUsage`
  accessor exposes Extended Key Usage OIDs, which caused a false rejection of any
  CA that asserted an EKU), enforces `pathLenConstraint` by counting the
  non-self-issued CA certificates below each CA, rejects unknown critical
  extensions, unsupported path-affecting extensions, duplicate and malformed
  extensions, and checks the leaf's Key Usage against the requested purpose. The
  supported profile, including the accepted signature algorithms and chain
  shapes, is documented in [`docs/certificate-profile.md`](docs/certificate-profile.md).
- **The shared WS-Security verifier accepted unsupported reference semantics.** It
  checked reference digests but never the declared transform sequence, and it
  skipped `cid:` attachment references before checking their digest method, so a
  correctly re-signed envelope with an unknown transform — or an unsupported
  attachment algorithm — still verified. Every reference now has its SHA-256
  digest method and full transform sequence validated before any digest is
  computed (exclusive C14N for SOAP parts, the SwA content-signature transform for
  attachments). Signature selection is structural (only a signature inside a
  `wsse:Security` header; ambiguous headers are rejected), and malformed
  certificate bytes return a `malformed` value instead of throwing.
- **Receipt acknowledgements were compared by digest text only.** Each
  `NonRepudiationInformation` reference is now compared against the reference the
  sender signed for its digest method, ordered transforms and parameters, and
  exactly-once cardinality; duplicates and acknowledgements of references we did
  not sign are rejected. Namespace prefixes remain irrelevant, so captures from
  independent implementations still verify.
- **Revocation deadlines ended before the response body.** The fetch cleared its
  timer once headers arrived, so a stalled or oversized OCSP/CRL body held
  validation open indefinitely. The deadline and caller cancellation now stay
  active through the body read, which is capped at `maxResponseBytes` (default
  1 MiB, configurable on the revocation policy).
- **The module-layout guard missed file imports.** `SENDER_ONLY` held `.ts` names
  while resolved imports were `.js`, so only directory imports were caught. The
  guard now normalises extensions, recurses into subdirectories, and is tested
  against deliberate violations.
- **SMP lookup read facts outside the signature.** A forged `ServiceInformation`
  hidden inside the (digest-excluded) `ds:Signature` element was read as
  verified, so a genuine signature over participant A could return an attacker's
  endpoint and certificate. The verifier now requires exactly one `ds:Signature`
  that is a direct child of the root and exactly one empty-URI `ds:Reference`,
  and returns the document **with the signature removed**; only that document is
  searched for the endpoint and the redirect.
- **Real SMP responses failed signature verification.** Inclusive C14N must carry
  the namespace declarations a node inherits from its ancestors; without them the
  `ds:SignedInfo` of every real SMP response canonicalised differently. The SMP
  canonicaliser now passes the inherited namespaces, and captured responses from
  two independent SMP implementations verify.
- **SMP lookup hardening.** The HTTP response is size-capped; elements are matched
  in their specification namespace, not by local name in any namespace.
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
