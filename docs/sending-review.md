# Sending implementation review

Reviewed on 2026-10-12 against source revision `63657e2`. This complements the [receiving review](receiving-review.md).

The sender has a sound streaming and separation-of-responsibility design. The highest-priority changes are preserving signed content across retries, completing certificate path validation, and tightening the conditions under which a receipt becomes verified. Several smaller lifecycle defects can also cause the caller to lose evidence or make the wrong delivery decision.

On the reviewed snapshot, all 139 existing tests and TypeScript typechecking passed. Additional focused probes confirmed the findings below. Those probes were run separately from the committed tests; they should become regression tests when fixes are implemented. Passing the current suite establishes internal consistency, not independent implementation interoperability or testbed conformance. Concurrent working-tree edits to the shared signature verifier appeared after these checks and are outside this review snapshot.

## What should be preserved

- [Payload preparation](../src/crypto/payload.ts) performs compression, SHA-256 hashing of compressed plaintext, and AES-GCM encryption in one streaming pass. Only ciphertext is spooled, with private file permissions.
- [Envelope construction](../src/xml/envelope.ts) signs the Body, Messaging header, and attachment digest. The attachment digest is taken before encryption, with compression already applied.
- [Signing](../src/xml/security.ts) verifies the injected signer's output against its certificate before transmission. This is useful for both local and remote key holders.
- [HTTP transport](../src/http/send.ts) enforces HTTPS, certificate verification, a TLS version floor, explicit connection and request deadlines, and a response size cap.
- [Receipt verification](../src/receipt/verify.ts) binds coverage to the exact parsed Messaging or SignalMessage element, checks the signer, compares the message reference, and requires acknowledgement of every expected reference. Certificate rollover with the same AP identity is supported without requiring certificate-byte equality.
- [Outcome classification](../src/outcome.ts) remains separate from transport. Retry scheduling, queue ownership, and business decisions can stay with the caller.

## Confirmed findings

### P1 Retries change the signed message

[sendAs4Internal](../src/send.ts) creates a new timestamp and attachment Content-ID on every invocation. [buildUserMessage](../src/xml/user-message.ts) also creates new signed XML IDs. The public contract and README tell callers to reuse `as4MessageId` when retrying an uncertain outcome, but the API cannot retain the original signed content.

A probe built two envelopes with identical message parameters, including a fixed timestamp and attachment ID. Both the Body digest and Messaging digest changed because their `wsu:Id` values changed. Normal sends introduce further differences.

AS4 non-repudiation retries must retain both the message ID and the receipt digest values. Rebuilding the message can make an original cached receipt fail verification against the retry, or cause a receiver enforcing content consistency to reject the duplicate. [AS4 section 3.2](https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/profiles/AS4-profile/v1.0/AS4-profile-v1.0.html)

**Proposed fix:** introduce a prepared outbound message that can be transmitted more than once. Preserve the signed XML, exact compressed payload representation or encrypted wire artifact, reference metadata, timestamp, and attachment IDs. Define serialization and caller-owned durable storage so a process restart does not require reconstruction. Keep `sendAs4` as a convenience for a single preparation and transmission.

Retaining and retransmitting an existing encrypted artifact does not require exposing the entropy seam. Do not solve this by letting production callers pin the random generator or recreate session keys and IVs. If re-encryption is supported later, preserve the original signed representation and define certificate rollover behavior explicitly.

**Regression:** have a receiver accept the first request but lose its response, then return the original receipt on retry. Assert identical signed-reference metadata and successful verification after both an in-process retry and a persisted-artifact reload.

### P1 Certificate path validation misses constraints

[buildCertificatePath](../src/pki/chain.ts) checks validity, issuer names, signatures, CA status, loops, and configured trust anchors. It does not process path-length constraints or unknown critical extensions. Focused probes accepted a chain with a subordinate CA below a `pathLenConstraint=0` intermediate and accepted a leaf with an unknown critical extension. These are required parts of certificate validation. [RFC 5280 sections 4.2 and 6.1](https://www.rfc-editor.org/rfc/rfc5280.html)

The extra `issuer.keyUsage.includes('keyCertSign')` check also reads the wrong property. Node exposes Extended Key Usage OIDs through that property. Adding an EKU extension to a correctly signed CA caused a false rejection claiming that `keyCertSign` was missing. [Node X509Certificate documentation](https://nodejs.org/api/crypto.html#x509keyusage)

The opposite Key Usage bypass was not reproduced: a CA restricted to digital signatures was rejected by Node's `ca` check. The confirmed acceptance defects are the missing path constraints and critical-extension processing; the EKU confusion is a separate false-rejection defect.

**Proposed fix:** use a maintained path-validation implementation, or define and implement a deliberately constrained Peppol certificate validator with explicit extension handling. Decode Basic Constraints and Key Usage correctly, enforce applicable path constraints, reject unsupported critical extensions, and apply leaf-use requirements appropriate to encryption or signing. The current `purpose` selects intermediate sets; it does not itself enforce leaf key permissions.

The configured intermediate set limits which chains can be constructed. This finding does not mean an arbitrary untrusted certificate is accepted. It means a cryptographically linked path to a configured root can still be accepted despite constraints that should invalidate it.

**Regression:** retain both rejected-chain probes, valid chains with relevant EKUs, and leaf-purpose tests. Include cross-signed and rollover chains when defining path-selection behavior.

### P1 Receipt verification ignores declared transforms

[verifyReferences](../src/xml/ws-security.ts) checks SHA-256 for XML references but canonicalizes the target without validating the declared transform sequence. A receipt with an unsupported transform URI, signed correctly over that altered SignedInfo, still passed signature verification in a focused probe.

The same module skips attachment references before checking their digest algorithm and transforms. That branch is particularly relevant to receiving; a receipt verifier should also define whether such unresolved signature references are permitted.

[verifyNonRepudiationInformation](../src/receipt/verify.ts) compares URI and digest text only. A signed receipt with an unsupported transform in its acknowledgement was accepted. DigestMethod, transform parameters, and duplicate acknowledgement references are not fully compared with the outgoing references. AS4 receipts carry the original reference structures as evidence. [AS4 section 5.1.8](https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/profiles/AS4-profile/v1.0/AS4-profile-v1.0.html)

This is not a demonstration that an attacker without a trusted signing key can forge a receipt. It demonstrates that the verifier can report success for a signed structure whose declared processing semantics it did not validate.

**Proposed fix:** make the shared verifier return validated reference metadata including digest method, ordered transforms, and relevant parameters. Reject unsupported combinations before computing a digest. Give the receipt path an explicit policy for allowed signature targets and unresolved references. Compare acknowledgement reference semantics with the outbound artifact, including cardinality, without requiring identical namespace prefixes or byte-for-byte XML serialization.

**Regression:** unknown transforms, multiple transforms, wrong digest methods, altered transform parameters, duplicate references, unresolved receipt-signature references, and valid alternate namespace serialization.

### P2 Revocation deadlines end before the response body

[fetchWithTimeout](../src/pki/revocation.ts) clears its timer and removes the caller's cancellation listener as soon as `fetch` resolves with response headers. OCSP and CRL bodies are consumed afterward through unrestricted `arrayBuffer()` calls.

A probe returned headers immediately and held the body open. After the configured deadline and a caller abort, the fetch signal remained un-aborted. A slow body can therefore hold sender validation open indefinitely, and a large body can allocate unbounded memory. The HTTP send timeout cannot cover this separate operation.

**Proposed fix:** retain cancellation and the deadline through bounded body consumption. Apply separate size limits for OCSP and CRLs, cancel bodies on rejected responses, and keep certificate-service failure distinguishable from invalid or revoked certificates. If an overall operation deadline is offered, propagate its remaining budget to validation, payload preparation, signing, transmission, and receipt verification.

**Regression:** immediate headers with a stalled body, abort during body consumption, an oversized body, and cleanup of a rejected HTTP response.

### P2 Errors are classified without message correlation

[classifyResponse](../src/send.ts) returns any parsed error as `error-signal`. It does not compare `RefToMessageId` with the outgoing ID. The classifier can then treat it as a permanent rejection.

An end-to-end local HTTPS probe returned `EBMS:0004` with `PEPPOL:NOT_SERVICED` and an explicitly unrelated message reference. The result was `error-signal`, classified `fatal` for the current send.

**Proposed fix:** preserve correlation as a fact and check it before using an error to stop delivery attempts. A supplied mismatching reference must not establish rejection of the current message. Define handling for absent references separately: some failures occur before the receiver can recover a message identity. Preserve those diagnostics while keeping delivery status uncertain where appropriate.

Transport-authenticated errors and signature-verified receipts have different evidence properties. Expose those differences if needed, rather than requiring every error signal to carry a signature. This probe used the trusted local TLS endpoint; it does not demonstrate a network attacker bypassing TLS.

**Regression:** matching, absent, and mismatching references, plus malformed and mixed signal structures.

### P2 Cleanup failure can discard a verified receipt

The `finally` block in [sendAs4Internal](../src/send.ts) awaits workspace cleanup without isolating errors. An exception from `rm` replaces the already computed send result.

An end-to-end probe injected `EACCES` during cleanup. The receiver processed the document, receipt verification completed, and the public promise rejected instead of returning the receipt. This violates the expected-failures-as-values contract and loses the most important delivery evidence.

**Proposed fix:** preserve the primary send result and report cleanup failure through a separate diagnostic path. Retain enough operational information to remove the orphaned spool later without logging payload contents or key material. The workspace currently marks itself cleaned before removal succeeds; adjust that lifecycle if cleanup is intended to be retryable.

**Regression:** cleanup failures following a verified receipt, an error signal, a transport failure, and a local preparation failure. In each case the original delivery fact must survive.

## Additional correctness and resilience work

These items are narrower than the findings above or need further adversarial coverage before assigning the same priority.

| Area                     | Observation                                                                                                                                                                                                          | Proposed action                                                                                                                                                     |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Transport evidence       | `requestBytesWritten` is set from TLS connection or response state, although its public comment promises an actual request-body write.                                                                               | Report a conservative fact such as delivery being possible, or document the present semantics accurately. A successful local write still cannot prove peer receipt. |
| Local spool errors       | `spool.failed` exists in the outcome model, but ordinary filesystem failures currently become `internal.error`.                                                                                                      | Map preparation I/O failures deliberately, preserving the fact that HTTP transmission has not started.                                                              |
| Error descriptions       | The parser fills `shortDescription` from a child `Description`, ignoring the `shortDescription` attribute.                                                                                                           | Preserve the attribute and optional description as distinct fields where useful.                                                                                    |
| Signal structure         | The parser checks the root local name but not its SOAP namespace; descendant searches allow more shapes than direct-child validation. Mixed Receipt and Error elements become an error despite the stricter comment. | Validate the supported SOAP version, placement, cardinality, and supported signal combinations explicitly.                                                          |
| Shared verifier failures | A malformed embedded certificate can throw from the shared verifier. The sender catches this but reports it as an untrusted signer.                                                                                  | Return a structured malformed-certificate result; keep the receiving API from inheriting a throwing parser path.                                                    |
| XML and MIME limits      | The sender bounds total response bytes, but XML depth/node budgets and MIME part/header budgets are not explicit. MIME root selection uses heuristics.                                                               | Share bounded parsing primitives with the receiver, honoring root selection and MIME framing rules.                                                                 |
| Cancellation             | The remote signer interface has no cancellation parameter; HTTP deadlines cover only the HTTP phase.                                                                                                                 | Define operation versus phase budgets and a cancellable signer contract. Stop starting new phases after cancellation.                                               |
| Evidence retention       | The public result preserves the receipt but does not expose an outbound artifact sufficient to reconstruct the original signed message for retry or independent evidence review.                                     | Return or retain a caller-owned evidence bundle alongside the prepared message.                                                                                     |

The certificate subsystem also warrants a dedicated review of CRL scope, critical extensions, responder authorization, revocation freshness, and cache policy. Those concerns are not certified as correct by the sender tests or by the narrower probes above.

## Proposed outbound API direction

A preparation/transmission split addresses both reliable retries and evidence retention while keeping retry policy outside the library:

1. **Prepare** consumes the payload once and produces an immutable outbound artifact with signed reference metadata, recipient identity, envelope, and replayable encrypted content.
2. **Persist** lets the caller durably retain that artifact before its first transmission. Ownership, disposal, access permissions, format versioning, and retention are explicit.
3. **Transmit** performs one attempt and returns transport and protocol facts against that artifact. It does not rebuild the signed message.
4. **Classify** continues to map facts to caller policy. Scheduling and retry limits remain external.

The original timestamp belongs to the message; attempt start/end times belong to transmission evidence. Keep those separate. Persist the raw receipt, original signed references, endpoint, certificate fingerprints, validation time and policy, and relevant transport facts under caller-controlled retention. Retaining full payloads or certificates in ordinary logs is unnecessary.

Repeatable HTTP entities and a sent-message object containing both the original message and response evidence are useful implementation patterns. Adopt those capabilities without making the library a queue or server framework.

## Implementation order and acceptance checks

| Stage | Work                                                                                                  | Acceptance check                                                                                                                                                                                  |
| ----- | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1     | Repair shared certificate and signature verification.                                                 | Invalid path constraints, unknown critical extensions, and unsupported reference semantics fail closed; valid interoperability fixtures still pass.                                               |
| 2     | Add a replayable outbound artifact and durable retry contract.                                        | The original receipt verifies after a lost response, retry, and process restart; signed reference values remain stable.                                                                           |
| 3     | Repair error correlation, cleanup handling, revocation body limits, and factual outcome descriptions. | No unrelated error establishes rejection; no cleanup exception erases a receipt; stalled certificate bodies respect abort and timeout.                                                            |
| 4     | Add independent wire fixtures and end-to-end interoperability coverage.                               | Outbound messages are accepted by independent receivers; their receipts verify; rollover, multipart variants, lost responses, malformed signals, and negative security cases behave as specified. |

The existing fake receiver is useful for transport and lifecycle tests, but it shares XML and canonicalization utilities with production code. Keep it, and supplement it with independently produced fixtures and testbed runs so both sides cannot silently agree on the same defect.
