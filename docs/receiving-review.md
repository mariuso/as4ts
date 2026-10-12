# AS4 receiving findings and implementation recommendations

Review date: 2026-10-12. Local source baseline: `63657e2`.

The proposed receiving architecture is a good fit for as4ts: verify and unpack one message with `open`, let the caller durably accept it, then construct a response with `respond`. Retain that separation. Before implementation, strengthen the shared verifier, define resource and evidence ownership, and specify recovery after duplicate requests and interrupted acknowledgments.

This review supplements [the receiving design note](receiving.md). Receiving remains unimplemented. Confirmed local findings, proposed behavior, and unresolved interoperability questions are distinguished below. Implementation comparisons are expressed as transferable patterns without identifying other projects.

## Existing capabilities and reuse boundaries

The package already provides outbound messaging, optional participant lookup, certificate validation, and outcome classification. Receiving should become a separate `as4ts/receive` entry point while preserving the sender's public API and one-operation model.

| Existing component                                                                                 | Useful receiving capability                                                             | Work still required                                                                                                               |
| -------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| [WS-Security verifier](../src/xml/ws-security.ts)                                                  | Signature verification, envelope digests, unique reference resolution, covered elements | Strict reference algorithms and transforms, bounded processing, structural selection, attachment verification, exception handling |
| [XML utilities](../src/xml/nodes.ts) and [canonicalization](../src/xml/c14n.ts)                    | Namespace-aware DOM operations and exclusive C14N                                       | Strict inbound parser configuration, resource limits, broader canonicalization vectors                                            |
| [Certificate validator](../src/certificate-validator.ts) and `src/pki/`                            | Configured trust roots, path validation, revocation, `message-signer` purpose           | Bounded complete network operations, inbound identity binding, explicit trust-failure outcomes                                    |
| [Profile](../src/profile.ts) and [constants](../src/constants.ts)                                  | Shared protocol identifiers                                                             | Receiving policy and acceptance checks                                                                                            |
| [Temporary workspace](../src/temp-file.ts)                                                         | Private scratch directory and explicit cleanup                                          | Ownership across `open` and caller storage, stream tracking, crash cleanup, aggregate quotas                                      |
| [Signal parser](../src/xml/signal.ts)                                                              | Signal recognition and response envelope extraction                                     | A separate streaming inbound MIME parser and strict UserMessage parser                                                            |
| [Signing helpers](../src/xml/security.ts)                                                          | Signing through an injected key holder                                                  | Direction-neutral failure handling and a production signal builder                                                                |
| [Fake receiver](../test/helpers/fake-receiver.ts) and [receipt helper](../test/helpers/receipt.ts) | Examples of unwrap, decrypt, digest checking, receipt and error XML                     | Production implementations with explicit invariants; the helpers are not security boundaries                                      |

No new server, queue, database, reporting engine, business-document model, or business validation engine is implied. Protocol validation remains library work; durable acceptance and operational policy remain application work.

## Confirmed local findings

| Finding                                                                           | Evidence and impact                                                                                                                                                            | Required follow-up                                                                                                             |
| --------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------ |
| XML reference transforms are not strictly validated                               | `verifyReferences` uses exclusive C14N without rejecting unsupported declared transforms. A correctly re-signed test envelope with an unsupported transform was accepted.      | Validate the entire allowed transform sequence before calculating a digest.                                                    |
| Attachment references bypass algorithm checks                                     | The `cid:` branch returns before checking `DigestMethod`. A probe with unsupported attachment transform and digest algorithms still returned successful envelope verification. | Distinguish declared references from verified attachments; validate algorithms even when attachment content is resolved later. |
| Malformed certificates can escape as exceptions                                   | Replacing the signing token with invalid certificate bytes caused `ERR_OSSL_ASN1_WRONG_TAG`, despite the verifier's documented value-only behavior.                            | Convert expected parsing and cryptographic failures into structured results.                                                   |
| Signature selection is permissive                                                 | `findSignature` searches descendants and falls back to any signature in the document. Certificate extraction also accepts an inline certificate fallback.                      | Select the applicable Security header structurally and enforce the selected Peppol token policy.                               |
| Reference facts are incomplete for receipt generation                             | `SignedReference` retains URI and digest only.                                                                                                                                 | Preserve validated digest algorithms, transforms, parameters, and necessary namespace context.                                 |
| XML parsing is not hardened for an exposed endpoint                               | `parseXml` creates a default DOM parser, with no explicit structural limits or strict warning/error policy.                                                                    | Add a bounded, strict inbound path.                                                                                            |
| MIME extraction is buffered                                                       | `extractSoapEnvelope` accepts a complete `Buffer` and searches boundary markers; it is not a streaming upload parser.                                                          | Implement byte-safe framing, bounded headers, transfer decoding, and backpressure.                                             |
| Receipt test scaffolding has weaker coverage than the proposed production builder | `buildSignedReceipt` signs Messaging or Body, not both.                                                                                                                        | Build and validate production receipts separately.                                                                             |
| Revocation reads outlive their timeout                                            | `fetchWithTimeout` clears its timer and abort listener after response headers. Later `arrayBuffer()` reads have no explicit size cap.                                          | Keep deadlines and cancellation active through body consumption; bound response bytes.                                         |
| The module guard misses forbidden file imports                                    | Resolved imports use `.js`, while `SENDER_ONLY` contains `.ts` filenames. Directory restrictions still work.                                                                   | Normalize extensions, recurse as the module tree grows, and test the guard with deliberate violations.                         |

The cryptographic probes demonstrate contract and validation gaps; they are not a demonstration of an unauthenticated end-to-end document acceptance exploit. Attachment content is deliberately outside the current envelope verifier's scope, so the receiving layer must complete that verification.

The existing receipt, module-layout, and package-surface suites passed 28 tests during review. Those tests do not cover the gaps above. Live receiving interoperability and the Peppol Testbed remain release gates.

## Public API and acceptance boundary

Keep `open(headers, body, options)` and `respond(decision, context)` as conceptual names until the public API is designed. Expected failures should remain values.

`open` should return verified metadata, owned payload/evidence handles, and an immutable receipt context. It must not return success until complete MIME consumption, cryptographic verification, and any required decompression have succeeded. Distinguish processing failures from local resource or certificate-service unavailability.

`respond` should consume that context plus an explicit caller decision, such as committed, already committed, or rejected. It should return exact response bytes, content type, and the information needed by an HTTP adapter. Reject contexts that were not produced by successful verification for positive receipts. Prevent accidental construction or mutation of receipt digests; TypeScript `readonly` alone is not a runtime guarantee.

The split encourages correct ordering but cannot prove that the caller committed data. Replace the existing design note's claim that it makes storage-first ordering the "only possible order" with an explicit caller obligation and an integration example.

An AS4 receipt represents successful message-service-handler processing and can provide non-repudiation evidence. It does not by itself prove downstream business acceptance. Durable inbox commitment is the proposed acknowledgment boundary for this library's integrations. [OASIS AS4 section 3.4](https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/profiles/AS4-profile/v1.0/AS4-profile-v1.0.html)

Keep the HTTP framework outside the core. An example adapter should demonstrate deadlines, cancellation, storage, duplicates, evidence retention, and response writing. A thin handler alone would not solve those integration obligations.

## Parsing and resource limits

Apply limits before any trust decision and retain them after authentication. A trusted signer can still send a resource-intensive message.

| Library limits                                                       | Host and application limits                       |
| -------------------------------------------------------------------- | ------------------------------------------------- |
| Actual request bytes, envelope bytes, attachment bytes and count     | Connection and header timeouts, admission control |
| MIME boundary length, header bytes and count, transfer-decoded bytes | Concurrent requests and worker capacity           |
| XML depth, node count, attributes, text, IDs and references          | Shared temporary-disk quota and storage capacity  |
| Certificate, signature and wrapped-key sizes                         | Key-service concurrency and rate limits           |
| Decompressed bytes and optional compression ratio                    | Deployment-wide CPU and memory budgets            |
| Operation deadline and abort propagation                             | Durable-storage deadline and recovery policy      |

Count observed bytes. `Content-Length` permits an early rejection but does not replace stream accounting. Accept chunked HTTP bodies through the host's decoded request stream.

The MIME parser must handle boundaries split at any chunk offset, binary and supported transfer-encoded parts, folded headers, Content-ID matching, valid delimiter framing, and the final boundary. Never decode the entire multipart body as UTF-8 or trim attachment content. Reject duplicate IDs, ambiguous roots, malformed encodings, missing parts, and unexplained parts under the chosen profile.

Choose and test root-part selection and permitted attachment ordering explicitly. Do not silently generalize a response-envelope extractor into a request parser.

Reject DTDs and malformed XML. Enforce structural bounds before expensive DOM and canonicalization work. A synchronous parser cannot be interrupted by an `AbortSignal`; use a tightly bounded input and, where needed, a worker with a deadline that the host can enforce. Checking depth only after an unbounded DOM has been built is too late.

Retain a terminal failure state. A parser that catches an underlying stream error must not convert a size-limit violation or abort into a successful operation. Verify every pipeline has consumed its required input and completed before accepting its output.

Use an absolute decompressed-byte cap as the primary decompression-bomb protection. A ratio limit can supplement it; allow an initial grace window if using streaming ratios, and test legitimate highly compressible documents. Do not rely on gzip's advertised size or buffering behavior.

Do not freeze the runtime dependency count as a security requirement. Evaluate a maintained MIME or streaming XML parser against the maintenance and fuzzing cost of an in-repo implementation.

## Signature verification and profile policy

Separate cryptographic facts from protocol policy:

```text
Bounded structural parsing
    -> cryptographic verification facts
    -> Peppol coverage and metadata validation
    -> complete attachment authentication and digest verification
    -> application acceptance
```

Require an unambiguous SOAP Envelope with the expected direct Header and Body. Resolve the applicable Messaging and Security elements by namespace, position, and role. Parse application metadata from the exact elements whose protection was established; a similarly named descendant is not an acceptable substitute.

Build an ID index once, reject ambiguous identifiers, and cap the number of references. Validate every URI, digest method, transform sequence, and parameter. Reject unsupported external references rather than dereferencing them. Validate the signing token type and its relation to the signature. Do not assume that `KeyInfo` itself is signed merely because it is inside a signature element.

For each attachment, validate the entire relationship:

```text
Signed PartInfo href
    <-> MIME Content-ID
    <-> EncryptedData CipherReference
    <-> EncryptedKey DataReference
    <-> signed attachment reference
```

Reject missing, duplicate, or extra mappings. Successful envelope verification is an internal intermediate state, not a successful receive result. Require verified coverage of the actual Messaging element and every accepted payload.

### Empty Body coverage remains an explicit decision

Inspected receiver policies differ: one requires Body, Messaging, and attachments; another requires Messaging and attachments when attachments exist, and Messaging plus Body otherwise. This describes inbound acceptance, not necessarily what those senders emit.

OASIS AS4 sections 5.1.4 and 5.1.5 describe coverage for SOAP messages and SOAP with Attachments. Settle their application to the selected Peppol profile before freezing inbound policy. Keep outbound signing of all three, include both acceptance cases in the interop corpus, and reject unexpected business content in the Peppol SOAP Body. Do not introduce a blanket option that disables coverage checking. [OASIS AS4 signing rules](https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/profiles/AS4-profile/v1.0/AS4-profile-v1.0.html)

### Canonicalization needs independent vectors

Exercise arbitrary and uppercase prefixes, inherited namespace declarations, default namespaces, `InclusiveNamespaces/PrefixList` including `#default`, namespace redeclarations, whitespace, and reference ordering. The current namespace-materialization helper explicitly skips `#default`; its complete behavior needs a dedicated vector rather than an assumed diagnosis.

Keep the original envelope bytes for evidence because verification helpers may modify the working DOM to materialize namespace declarations. Verify generated receipts after serialization as well as checking signatures before output.

Interoperability with several applications is useful, but applications can share an underlying XML-security engine. Maintain independent canonicalization vectors and profile assertions alongside wire captures.

## Decryption and payload exposure

Validate encryption algorithms and parameters before invoking a private key. For the current profile, the proposed supported combination is RSA-OAEP with SHA-256 and MGF1-SHA-256, followed by AES-128-GCM. Require a 16-byte unwrapped session key, a 12-byte IV, and a 16-byte authentication tag; reject truncated attachment layouts. Keep any additional algorithm compatibility explicit. [CEF AS4 1.14 security configuration](https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/pages/467117656/eDelivery+AS4+-+1.14)

`decipher.update()` returns plaintext before GCM authentication completes. Authentication is established by successful finalization. Do not pipe that output directly into decompression or an application consumer. [Node crypto authentication behavior](https://nodejs.org/api/crypto.html#decipherupdatedata-inputencoding-outputencoding)

For gzip payloads, the simplest design preserving ciphertext-only quarantine is:

```text
Encrypted attachment -> private ciphertext spool
    -> decrypt and hash, discard plaintext output
    -> verify GCM tag and signed compressed-content digest
    -> decrypt again into bounded gunzip and a private document spool
    -> expose payload only after complete success
```

Keep the ciphertext private and unchanged between passes, and verify successful finalization on the second pass too. This costs an additional decryption pass and file reads, but has bounded memory and a clear authentication boundary. Internally produced plaintext exists briefly for hashing; the invariant is that it is neither persisted nor released before authentication.

A lower-I/O alternative writes compressed plaintext to a private quarantine file during the first pass, then exposes or decompresses it only after authentication and digest verification. That permits unauthenticated plaintext on disk and therefore changes the stronger quarantine invariant. Choose deliberately rather than treating these approaches as equivalent.

Never acknowledge on partial stream consumption. Test damaged final GCM tags, truncated gzip data, invalid gzip trailers, and consumers that stop reading early. `open` must detect failures before returning success.

## Compression and attachment transforms

Do not always gunzip. The inherited CEF profile requires accepting uncompressed payloads even when compression is configured. Select decompression from validated metadata; reject unsupported compression declarations. A genuine decompression failure maps to `EBMS:0303`. [CEF AS4 1.14 section 3.3.1](https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/pages/467117656/eDelivery+AS4+-+1.14)

SHA-256 of decrypted bytes is correct for the gzip attachment representation, but is not the universal attachment signature rule. The SwA content transform depends on MIME type: XML attachments require exclusive canonicalization, and text has its own canonicalization rules. Transfer decoding belongs to MIME processing before these transforms. [OASIS SwA sections 5.4 and 5.5](https://docs.oasis-open.org/wss/v1.1/wss-v1.1-spec-errata-os-SwAProfile.html)

Spike uncompressed XML early. Authenticate it before parsing, then apply the correct content transform before exposing it. Decide whether bounded DOM processing is sufficient for the advertised payload size or whether streaming canonicalization is required. The gzip-specific first-pass hash above cannot simply be reused for all MIME types.

## Addressing and SBDH consistency

Validate AP identifiers and roles, agreement, process/service scheme and value, action/document type, conversation ID, MPC, payload properties, and part mappings. Accept omission of `mpc` when it means the default MPC. Do not turn the sender's default `MimeType` into an unsupported receiving restriction.

Bind the authenticated signing AP to `From/PartyId` and the receiving AP identity to local configuration. Keep AP identities separate from the original sender and final recipient participants. Peppol requires the integrated SBDH business message in the first attachment after the AS4 header. [Peppol AS4 profile](https://docs.peppol.eu/edelivery/as4/specification/)

Add a focused, bounded SBDH reader over authenticated payload data and compare:

| AS4 field                | SBDH field               |
| ------------------------ | ------------------------ |
| `originalSender`         | Sender identifier        |
| `finalRecipient`         | Receiver identifier      |
| Service value and scheme | Process identifier       |
| Action                   | Document type identifier |

Compare normalized identifier structures according to their schemes, not casually trimmed or URL-decoded strings. Return explicit inconsistencies. This is protocol consistency checking, not full invoice parsing or Schematron validation.

Keep the serviced-participant decision with the caller. Prefer a local capability registry for the normal decision; SMP checks can be optional operational checks. Avoid making every inbound request depend on a fresh remote lookup or accepting a recipient because an endpoint URL contains a local URL as a substring. An unserviced participant/document/process combination requires `EBMS:0004`, severity `failure`, with `PEPPOL:NOT_SERVICED` detail. [Peppol AS4 section 4.4](https://docs.peppol.eu/edelivery/as4/specification/)

## Certificates and key rollover

Reuse the `message-signer` purpose, configured AP trust anchors and intermediates, and explicit revocation policy. Preserve the difference between invalid/revoked credentials and unavailable revocation information. Apply AP identity binding in addition to path validation. Generic signature verification is not proof of Peppol AP authorization.

Bound complete OCSP/CRL operations, including response-body reads. Retain cancellation until completion and make redirects and allowed network destinations deliberate. Reuse the validator's long-lived cache; keep network and key-service concurrency bounded at the host level.

Keep `Signer` backward compatible. Add a separate unwrap/decryptor capability and a bounded set of local decryption credentials. Select a candidate using the referenced certificate fingerprint or public key, with controlled fallback during rollover. Never let an untrusted identifier select an arbitrary remote key-service resource.

Validate OAEP parameters and output length regardless of which key provider performs unwrap. Return a generic wire decryption failure while retaining safe local diagnostics. Never log session keys, private keys, or payload contents.

Use the active signing credential for new receipts and retain older decryption credentials for the defined migration window. Test retries encrypted to an older certificate and responses signed with the active certificate.

The existing same-key-holder note is not a universal cloud-service contract. Some managed RSA key services permit either signing or decryption for a key, but not both. Separate interfaces avoid assuming that an existing signing credential can automatically unwrap session keys. Deployment must still provision a valid certificate/key arrangement. [Managed key usage constraints](https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateKey.html)

## Evidence and temporary resource ownership

Return owned handles rather than only filesystem paths. A handle should expose size, relevant digests, supported read access, and explicit disposal. Document whether repeated reads are supported and which artifacts survive until disposal. Close streams before deleting backing files; clean partial files on failures and cancellation. The host needs a policy for abandoned workspaces after process crashes.

Allow the caller to retain:

- Original envelope bytes and bounded request metadata needed to interpret them.
- Complete validated references and their algorithm/transform parameters.
- Signer certificate, validation time, relevant trust facts, and the decryption credential identifier.
- The authenticated compressed representation when used, plus the decompressed document and their digests.
- The durable acceptance record and exact final signed response bytes.

Recompression need not reproduce the signed bytes. Retain the original signed representation when evidence retention requires it. Keep evidence access separate from ordinary business-document consumption so the caller can choose retention without forcing a full in-memory copy.

Define how receipt context can be recovered after restart: either persist sufficient verified evidence with integrity protection appropriate to the storage boundary, or reopen and reverify retained input under an explicit recovery policy. An in-memory opaque token alone cannot support crash recovery.

## Duplicate handling and durable acceptance

AS4 retries intentionally retain MessageId and the non-repudiation digests. A repeated ID is not automatically malicious or a mandatory error response. Distinguish a retransmission from conflicting reuse. [OASIS AS4 section 3.2](https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/profiles/AS4-profile/v1.0/AS4-profile-v1.0.html)

Keep persistence with the caller, but document a transactional inbox contract using an atomic uniqueness constraint within the receiving scope. Bind the record to authenticated identity and verified signed content. Do not use a whole-HTTP-body hash as the retry identity; MIME packaging and encryption bytes can differ.

| State                                                          | Proposed behavior                                                                                                   |
| -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| New verified message                                           | Coordinate a claim, then commit payload, evidence, and inbox state before acknowledgment.                           |
| Concurrent processing                                          | Wait or return an appropriate failure under caller policy; do not acknowledge another request's unfinished storage. |
| Committed with matching identity and signed content            | Suppress repeat business delivery; return the retained receipt or regenerate from retained verified evidence.       |
| Same ID with conflicting identity or signed content            | Reject conflicting reuse; never substitute the old receipt.                                                         |
| Processing failed before commit                                | Make the claim recoverable so a legitimate retry can proceed.                                                       |
| Commit succeeded but receipt generation or transmission failed | Preserve committed state and allow receipt recovery without another business delivery.                              |

A seen-message cache registered before application processing is not a durable inbox. A boolean duplicate answer cannot express whether the previous attempt committed, failed, or is still active. Choose retention to cover the supported retry horizon and specify behavior after expiry.

The recommended application sequence is:

```text
open
    -> validate participant service and required payload metadata
    -> commit document, evidence, inbox record and delivery work
    -> respond
    -> persist exact signed response bytes
    -> write HTTP response
```

If object storage and inbox storage cannot commit atomically, define staged objects and recovery so committed inbox entries never point at unavailable payloads. A storage or network failure after inbox commitment must not erase the committed record.

Test crashes at every transition. A signed receipt need not prove downstream business completion, but it must never acknowledge a document the configured acceptance boundary has not secured.

## Receipt and error construction

Build a production signal builder rather than promoting test helpers unchanged. Use the verified original reference information in NRI; preserve transform parameters and namespace context needed to represent those references correctly. Sign the receipt's Messaging and Body, serialize it, and verify the serialized result before returning its bytes. Keep response MessageId, timestamp, and `RefToMessageId` explicit. [OASIS AS4 receipt rules](https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/profiles/AS4-profile/v1.0/AS4-profile-v1.0.html)

Distinguish receipt XML under construction from final signed bytes and from successful HTTP transmission. Persistence hooks are useful, but storing an intermediate unsigned receipt does not retain the final cryptographic evidence. `respond` should make the exact output bytes available for persistence and retransmission.

Not every failed `open` has usable success facts or a safely parsed MessageId. Model failures with a processing stage, reason, and optional bounded correlation context. Keep diagnostic data separate from safe wire error details.

Separate transport rejection, SOAP faults, and ebMS errors. An oversized or malformed upload may require a transport response rather than an invented ebMS correlation. Do not require every early parsing failure to produce a signed signal. Do not respond to incoming errors or receipts with automatic positive receipts.

Move direction-neutral protocol error definitions out of the sender classification layer. Keep sender retry classification separate from receiving error construction. Map decompression failure, recipient-not-serviced, failed authentication, failed decryption, policy violations, and storage failures deliberately. The inherited profile recommends `EBMS:0202` for unsuccessful receiving processing when no receipt can be returned. [CEF AS4 1.14 section 3.3.2](https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/pages/467117656/eDelivery+AS4+-+1.14)

Preserve unfamiliar peer error codes. In particular, `EBMS:4001` occurs as an implementation-specific duplicate response; it is not a verified receipt or proof of successful durable delivery. Include it in outbound compatibility tests without promoting it into a universal protocol rule.

## Lessons for implementation choices

The useful patterns from implementation review are narrow persistence interfaces, separate response-evidence hooks, exact signature-coverage facts, profile-specific validation, retained compressed evidence, resource ownership, and negative protocol tests.

Avoid these patterns when implementing the receiver:

- Deferring attachment-digest verification without guaranteeing it is eventually called.
- Treating a reference to the message identifier, without the original signed digests, as valid NRI.
- Assuming attachment transfer encoding is always base64 or converting multipart binary data into text.
- Selecting tokens by fixed generated IDs rather than verified references.
- Materializing the entire decompressed business document in memory for application handoff.
- Returning success when no storage/acceptance handler is configured.
- Treating a pre-processing duplicate-cache entry as evidence of successful delivery.
- Logging session-key material, or equating a debug/probe mode with a safe production trust policy.
- Adding generic profile machinery or extensive security-bypass switches to solve a narrow Peppol requirement.

Derive new implementations from the protocol invariants and tests. External source code is not a correctness oracle, and multiple interoperable applications may share the same cryptographic implementation.

## Test and interoperability plan

Maintain both positive interoperability fixtures and adversarial inputs. Use test credentials and retain complete wire bytes with expected semantic facts, not only locally regenerated XML.

| Area        | Required cases                                                                                                                                                                                                       |
| ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| MIME        | Every boundary split position, binary and base64, malformed transfer encoding, duplicate/missing IDs, incorrect root selection, folded or oversized headers, missing closing boundary, unexpected parts              |
| XML         | Malformed XML, DTDs, excessive depth/nodes/attributes, duplicate IDs, extra Security/Messaging/UserMessage structures, wrong SOAP namespace or structural position                                                   |
| Signature   | Valid signature over the wrong node, missing Messaging coverage, missing attachment coverage, selected Body coverage policy, wrong transforms/digest algorithms, altered payload references, malformed signing token |
| C14N        | Prefix variations, inherited/default namespaces, inclusive prefix lists, `#default`, whitespace, namespace ordering and redeclarations                                                                               |
| Encryption  | Wrong recipient key, rollover keys, wrong OAEP parameters, wrong session-key length, truncated IV/tag, tampered ciphertext and final tag                                                                             |
| Compression | Uncompressed XML with the correct SwA transform, gzip, high compression ratios, output limits, invalid trailers, truncation, early consumer termination                                                              |
| Peppol      | AP identity binding, participant routing, SBDH/header mismatches, omitted default MPC, unsupported service/document/process, certificate and token requirements                                                      |
| Resources   | Cancellation at each stage, disk exhaustion, slow clients, certificate-service timeouts after headers, swallowed stream errors, cleanup after failure and disposal                                                   |
| Acceptance  | Failed persistence, missing acceptance handler, concurrent duplicates, conflicting reuse, lease recovery, commit followed by signing failure, response loss, crash/restart, evidence reconstruction                  |
| Responses   | Complete NRI and transform parameters, signature over final serialized receipt, correct error mapping, missing correlation context, implementation-specific peer errors                                              |

Obtain sender fixtures from at least two established implementations before freezing the parser and coverage policy. Validate generated receipts with those senders. Add independent XML/security vectors because application diversity does not necessarily imply cryptographic-engine diversity.

The Peppol Testbed receiving suite remains a final conformance gate. Existing local sender/receipt tests and source reviews are not substitutes for it.

## Proposed implementation phases

1. **Shared verification and contracts.** Fix reference validation, expected exceptions, revocation-body bounds, and module guards. Define failure stages, immutable receipt context, evidence ownership, and the durable inbox example. Resolve empty Body coverage.
2. **Interoperability fixtures and focused spikes.** Collect real UserMessages and prototype bounded MIME handling and uncompressed XML attachment verification. Decide parser dependencies and the advertised size envelope.
3. **Receiving primitives.** Add separate unwrap credentials, bounded streams, ciphertext quarantine, complete digest/authentication checks, conditional decompression, and disposable payload handles.
4. **Open and Peppol validation.** Implement structural header parsing, coverage policy, AP identity checks, SBDH consistency, and structured failure facts.
5. **Responses and public surface.** Implement signed receipts and errors, shared protocol error definitions, the fifth entry point, and updated package/layout guardrails.
6. **Acceptance and release validation.** Exercise the transactional inbox example, fault injection, resource tests, key rollover, live peer interoperability, and the Testbed.

## Decisions to settle before release

- Exact required signature coverage for an empty SOAP Body with MIME attachments.
- Ciphertext-only quarantine versus a private unauthenticated-plaintext spool.
- MIME/XML parser choice, supported encodings, and practical resource defaults.
- Uncompressed XML size support and canonicalization strategy.
- Public payload/evidence ownership and restart-safe receipt-context recovery.
- Capability-check integration and the placement of bounded SBDH extraction.
- Duplicate retention, concurrent-claim recovery, and same-ID content conflicts.
- Key-provider capabilities, rollover windows, and certificate-service failure policy.
- Error taxonomy and HTTP response behavior before trustworthy correlation exists.

Keep the core framework-free and storage-neutral. The release should include an integration example concrete enough to demonstrate durable acceptance and lost-response recovery, not only a happy-path HTTP endpoint.
