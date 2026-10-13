# Receiving API

`as4ts/receive` implements a two-step inbound contract: **verify and unpack** one
message with `openAs4Message`, durably accept it, then **produce the exact response
bytes** with `respondAs4Message`. The library stores nothing and makes no
acceptance decision. Expected failures are values, never throws.

The HTTP endpoint, durable storage, duplicate suppression and the
serviced-participant decision stay with the caller. A worked durable inbox is in
[`examples/receive-inbox.ts`](../examples/receive-inbox.ts).

## Entry point

```ts
import {
  openAs4Message,
  respondAs4Message,
  keyHolderFromKey,
  ebmsErrorFor,
  notServicedError,
  defaultInboundLimits,
} from 'as4ts/receive';
```

The type surface includes `OpenAs4MessageInput`, `OpenResult`/`OpenSuccess`/
`InboundFailure`, `InboundKeyHolder`, `PayloadHandle`, `RepresentationHandle`,
`EvidenceHandle`, `ReceiptContext`, `AcceptResponseInput`/`RejectResponseInput`,
`RespondResult`/`RespondSuccess`/`RespondFailure`, `InboundLimits`, `EbmsErrorSpec`,
`InboundCorrelation`, `SbdhConsistency`, `Profile`, `ScopedId`, `Signer` and
`ValidateCertificate`.

## Step 1 — `openAs4Message`

```ts
const opened = await openAs4Message({
  contentType, // the request Content-Type (carries the MIME boundary)
  body, // the request body, already transfer-decoded (AsyncIterable<Uint8Array>)
  keyHolder, // InboundKeyHolder, or a bounded array for rollover
  validateCertificate, // required: validates the sender (purpose 'message-signer')
  receiverIdentity, // required: our AP identity (ScopedId); To/PartyId must equal it
  profile, // optional; defaults to peppolProfile
  limits, // optional; defaults to defaultInboundLimits
  spoolDirectory, // optional; defaults to the OS temp directory
  signal, // optional AbortSignal
  onEvent, // optional observation hook (never receives secrets)
  now, // required clock
});
```

`open` performs the whole inbound path before it returns: bounded MIME parsing,
strict XML, WS-Security signature verification, the selected **coverage** rule
(`eb:Messaging`, the SOAP Body and every attachment), signer validation against
`validateCertificate`, session-key unwrap with the key holder, ciphertext-only
quarantine with a two-pass recovery, decompression and payload recovery.
**Success means the payload was fully processed** — a later read cannot discover a
bad digest or a truncated stream.

On success you get verified facts plus owned handles:

| Field                                                                        | Meaning                                                                                                     |
| ---------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `messageId`, `timestamp`                                                     | the verified ebMS message id and timestamp                                                                  |
| `senderId`, `receiverId`                                                     | the bound AP identities (signer CN and our identity)                                                        |
| `originalSender`, `finalRecipient`                                           | the integrated-SBDH business participants (`ScopedId`)                                                      |
| `service`, `action`, `agreement`, `conversationId`, `mpc`, `compressionType` | the verified header facts                                                                                   |
| `signerCertificate`, `credentialCertificate`                                 | the signer cert, and the AP cert that unwrapped the session key                                             |
| `payload`                                                                    | `PayloadHandle`: the decrypted, decompressed document (`byteLength`, `digestBase64`, `read()`, `dispose()`) |
| `representation`                                                             | `RepresentationHandle`: the authenticated compressed/original bytes and their digests                       |
| `evidence`                                                                   | `EvidenceHandle`: the original envelope bytes, the verified references and the signer cert                  |
| `receipt`                                                                    | `ReceiptContext`: the plain, serialisable context for step 2                                                |
| `sbdh`                                                                       | `SbdhConsistency`: `consistent` / `inconsistent` / `missing` / `malformed` / `too-large`                    |

`receipt` is deliberately **serialisable**, so a caller that committed the
document but crashed before responding can persist it and still build the receipt.
`dispose()` releases the payload, representation and evidence handles; it is
idempotent. Call it on every path.

### Limits

`defaultInboundLimits` bounds the request (`maxRequestBytes`), the envelope XML
(`maxEnvelopeBytes`), the MIME parts and headers, the decrypted representation
(`maxRepresentationBytes`), the decompressed output per attachment and in aggregate
(`maxDecompressedBytes`, `maxAggregateOutputBytes`), the XML handed to the DOM
parser (`maxXmlBytes`), and the number of decryption credentials tried
(`maxKeyCandidates`). Limits are applied before any trust decision and validated
as facts.

### Key holders and rollover

Implement `InboundKeyHolder` (a `certificate` and an `unwrap`) — separate from
`Signer`, because a managed key service may permit decryption or signing but not
both. `keyHolderFromKey(privateKeyObject, certificatePem)` wraps a local RSA key.
Pass a bounded array during certificate rollover; `open` reports which credential
unwrapped the session key in `credentialCertificate`. The holder must return a
fresh key buffer and honour `signal`.

### Failures

A failure is an `InboundFailure`: `{ ok: false, stage, reason, answerable,
correlation?, detail? }`. `stage` is where it happened (`transport`, `mime`,
`xml`, `signature`, `certificate`, `decrypt`, `decompress`, `addressing`,
`payload`, `internal`); `reason` is a machine-readable code. `answerable` is true
only once there is trustworthy correlation (the AP identity is bound), and
`correlation` carries the `messageId` when it is. `detail` is secret-free and for
logs, not the wire.

## Step 2 — `respondAs4Message`

Call **after** the document is durably accepted.

```ts
// Accepted: a signed receipt.
const response = await respondAs4Message({
  kind: 'accepted',
  receipt: opened.receipt, // serialisable; survives a restart
  decision: 'committed', // or 'already-committed' — required
  signer, // signs the receipt
  now,
});

// Rejected: a signed ebMS error. Needs only the recovered correlation.
const response = await respondAs4Message({
  kind: 'rejected',
  correlation: failure.correlation!, // from the InboundFailure
  error: ebmsErrorFor(failure), // or notServicedError()
  signer,
  now,
});
```

The `decision` is the caller's explicit assertion that the document is durable —
it cannot be omitted, and it cannot be proven by the library. The receipt echoes
the verified references (URI, digest, digest method, ordered transforms and
parameters) in its `NonRepudiationInformation`; the serialised output is verified
before it is returned.

`RespondResult`:

| Field      | Meaning                                                              |
| ---------- | -------------------------------------------------------------------- |
| `ok: true` | `status` (200), `contentType`, `headers`, and the exact `body` bytes |

or a distinguishable failure: `{ ok: false, reason, detail? }` — for example
`respond.decision-required`, `respond.invalid-receipt`, `respond.signing-failed`,
`respond.self-check-failed`, `aborted`.

### Mapping a failure to an error signal

`ebmsErrorFor(failure)` maps a receiving failure deliberately (using the shared,
direction-neutral error definitions): MIME → `EBMS:0007`, XML → `EBMS:0009`,
authentication/decryption → `EBMS:0101`/`0102`, decompression → `EBMS:0303`,
P-Mode mismatches → `EBMS:0010`, policy → `EBMS:0103`, otherwise `EBMS:0202`. It
puts no local diagnostics on the wire. `notServicedError()` packages the
Peppol-mandated `EBMS:0004` with `PEPPOL:NOT_SERVICED` for a participant/document/
process you do not service — that decision is yours.

Only answer when `failure.answerable` is true. A failure without trustworthy
correlation is a transport rejection, not an invented ebMS error; a malformed or
oversized upload, for example, may need a plain HTTP failure.

## HTTP adapter

Both a receipt and an ebMS error are carried as **HTTP 200** with content type
`application/soap+xml; charset=UTF-8`. The adapter must set `Content-Type` from
`response.contentType` and transmit `response.body` unchanged; persist those exact
bytes before writing them so a lost response can be replayed.

## Ordering

```
openAs4Message
  → validate the participant / required metadata (your policy)
  → commit the document, the evidence and the inbox record (durable)
  → respondAs4Message
  → persist the exact response bytes
  → write the HTTP response
```

If a request arrives while an earlier attempt for the same `MessageId` is still in
flight, serialise on that id so the document is delivered once. The
[durable-inbox example](../examples/receive-inbox.ts) shows per-id locking,
duplicate suppression, receipt replay and recovery when the response was lost.

## Status and caveats

Receiving is published as a pre-release (for example `0.2.0-rc.1`). The inbound
signature-coverage policy is **selected but not yet frozen**; it is pending
confirmation against captured wire bytes from independent senders (see
[`receiving-coverage.md`](receiving-coverage.md)). Peer interoperability and the
Peppol Testbed are not yet complete.
