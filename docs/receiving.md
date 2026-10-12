# Receiving AS4: design note

This is a design note, not a promise. It records how receiving is expected to
fit the package so that adding it later is not a breaking change. It is **not**
implemented.

## Status

**Planned, not implemented.** No `receive*` value or type is exported today, and
`test/package-surface.test.ts` fails if one appears before it is designed. The
shared building blocks (`xml/`, `pki/`, `crypto/`, the profile) and the
certificate purpose `message-signer` exist already; the two-step public shape
below is the plan.

## Principle

The same principle as sending: **one message in, facts out.** The package does
one receive attempt, reports what it found as a value union, and does nothing
else. It stores nothing, makes no decisions (no accepted/retryable policy), and
runs no web server. Expected failures are values, never thrown.

Everything a real access point does around a message — the HTTP endpoint,
storage, duplicate suppression, reporting — stays with the caller, exactly as
the sender leaves retry, queueing and persistence to the caller.

## Shape: two steps

Receiving cannot be a single call, because the receipt is a legal
acknowledgement that must not exist before the document it acknowledges has been
stored. So the caller drives two steps.

### 1. `open`

Takes the request headers and a body stream. It:

- verifies the WS-Security signature on the user message and the sender's
  certificate (purpose `message-signer`);
- checks the ebMS headers (party identifiers and roles, service, action,
  agreement, conversation id, mpc, payload info) against the profile;
- decrypts the session key with the caller's key and decrypts and decompresses
  the payload to a spool file;
- returns facts plus the location of the payload.

It returns facts, not a document object and not a receipt. Expected failures
(bad signature, wrong recipient, unsupported P-Mode, malformed headers,
decryption failure, decompression failure) come back as values that the caller
can turn into an ebMS error signal.

### 2. `respond`

Called by the caller **after** it has durably stored the document. It builds:

- the signed receipt, or
- an ebMS error signal with a given code.

`respond` takes the outcome of storage (or the error code) and the facts from
`open`, so the acknowledgment is produced only once the document is safe.

**Why two steps.** A receipt is a legal acknowledgement. Creating it inside
`open` would either force the package to store the document (it must not) or
risk acknowledging a document that is then lost before it is stored. Splitting
the call makes "store, then acknowledge" the only possible order.

## Left to the caller

- The HTTP endpoint and its framework.
- Duplicate detection on the AS4 `MessageId`.
- The "do we service this participant?" decision.
- Storage of the document and of the evidence.
- Reporting.
- Message Level Status (MLS) and any other policy.

## What is harder than sending

Sending talks to a peer the caller chose and trusts through SMP. Receiving
accepts bytes from anyone on the network, so:

- **Untrusted input before authentication.** Size limits, parser limits, slow
  clients and compression bombs must be handled before any trust decision,
  because the envelope is attacker-controlled at that point.
- **Every sender's XML serialisation.** The signature must verify over what
  other implementations actually put on the wire, not only what this project
  emits. Receipts already forced this for one direction; user messages are more
  varied.
- **No plaintext before the GCM tag verifies.** The payload must stay spooled as
  ciphertext and only be released once AES-GCM authentication succeeds.
- **Two keys during certificate rollover.** A receiver may have to hold the old
  and the new private key at once and try both.
- **A wrong receipt harms a third party.** A receipt that acknowledges a
  document the caller did not actually accept can expose the receiver (or the
  final recipient) to a claim. This is why `open` and `respond` are separate.

## Exit test for a future implementation

A future receiver is done only when it passes:

- receive from an **Oxalis** sender and a **phase4** sender;
- one negative case per failure, each answered with the correct ebMS error:
  bad signature, wrong recipient, tampered payload, replayed message id,
  oversized payload;
- the **Peppol Testbed** receiving suite.
