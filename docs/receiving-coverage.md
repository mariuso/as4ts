# Inbound signature coverage: the selected interpretation

Status: **selected, pending confirmation against captured wire bytes** from two
independent senders (see [receiving fixtures](receiving-fixtures.md)). This is a
protocol-policy decision, not something local fixtures can decide on their own.

## The question

What must the WS-Security signature of an inbound AS4 `UserMessage` cover before
the message is accepted?

## What the specifications say

- **AS4 §5.1.4 (SOAP messages)** signs the SOAP message: the `eb:Messaging`
  header and the SOAP **Body** — and the Body is explicitly allowed to be empty.
- **AS4 §5.1.5 (SOAP with Attachments)** signs the `eb:Messaging` header and each
  attachment (through the SwA content-signature transform). Peppol carries the
  business document as the first attachment and leaves the Body empty.

Inspected receivers differ in the empty-Body case: one requires Body, Messaging
and attachments; another requires Messaging and attachments when attachments
exist, and Messaging **plus Body** otherwise.

## Selected policy

The receiver requires, for a `UserMessage`:

1. **`eb:Messaging` coverage — always.** The ebMS headers are the message.
2. **Every accepted attachment — always.** Each accepted payload must be covered
   by a signed `cid:` reference whose transform-digest is verified against the
   decrypted content.
3. **SOAP Body coverage — required.** The Body is signed even when empty, per
   AS4 §5.1.4. Unexpected business content in the Body is rejected (Peppol
   carries the document as an attachment, not in the Body).

This is stricter than §5.1.5 read on its own. §5.1.4 (SOAP messages) signs the
Body; §5.1.5 (SOAP with Attachments) signs `eb:Messaging` and the attachments and
does not by itself require a Body reference. Requiring Messaging + Body +
attachments therefore accepts §5.1.4 senders and SwA senders that _also_ sign the
Body, but it **rejects** an SwA sender that omits the Body reference. It is not
true that combining the two sections accepts a conformant sender under either
one: the union of the signing rules is not the intersection of the acceptance
conditions. Whether the senders Peppol actually deploys sign the empty Body is
exactly the interoperability question the captures must answer, and it is not
settled on paper. There is no option to disable coverage checking.

## Attachment-digest rule

The signed `cid:` reference digest is a transform digest, not an unconditional
raw hash: a gzip or binary attachment is digested as raw bytes (so the receiver
checks it against the _compressed_ content after decryption and before
decompression), while an XML attachment is canonicalised first. See
`src/receive/attachment.ts`.

## Exit condition

Before this policy is frozen, the fixtures from two independent senders must
confirm: (a) both emit a signed empty Body, and (b) each attachment reference's
declared transform and digest match what the receiver computes. Capture behaviour
is interoperability evidence about deployed senders, not authority to relax a
specification requirement: a sender that omits the Body reference is reported as
a mismatch to resolve, not a licence to drop the Body rule. If a sender signs
under §5.1.5 without a Body reference, the Body requirement in step 3 must be
revisited with that evidence — not silently relaxed.
