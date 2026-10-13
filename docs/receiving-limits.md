# Receiving limits and the size envelope

This page states what the receiving path bounds, what it currently holds in
memory, and what a "500 MB document" claim would actually require. It is
deliberately conservative: raising the defaults does **not** by itself establish a
safe size envelope.

## Two size axes

A size limit only makes sense against one of two quantities, and compression
moves which one is reached first:

- **Wire size** — the HTTP request body (the encrypted attachment plus MIME
  framing). This is what `maxRequestBytes` bounds.
- **Document size** — the decrypted, decompressed business document. This is what
  `maxDecompressedBytes` (per attachment) and `maxAggregateOutputBytes` (entire
  message) bound.

A highly compressible document (repetitive XML) can be tiny on the wire and
enormous as a document; an incompressible one (already-compressed or binary) is
roughly the same size on both. State limits against the axis you mean.

## Limits and their defaults

`defaultInboundLimits` (see [`src/receive/types.ts`](../src/receive/types.ts)):

| Limit                     | Default | Bounds                                             |
| ------------------------- | ------: | -------------------------------------------------- |
| `maxRequestBytes`         |  64 MiB | the complete HTTP request body                     |
| `maxEnvelopeBytes`        |   1 MiB | the SOAP envelope bytes                            |
| `maxParts`                |       8 | MIME parts                                         |
| `maxHeaderBytes`          |  16 KiB | per-part MIME headers                              |
| `maxPartBytes`            |  64 MiB | a single MIME part                                 |
| `maxRepresentationBytes`  |  64 MiB | the decrypted, pre-decompression representation    |
| `maxDecompressedBytes`    | 256 MiB | decompressed output of one attachment              |
| `maxAggregateOutputBytes` | 512 MiB | decompressed output across the message             |
| `maxXmlBytes`             |  64 MiB | XML bytes handed to the DOM parser (the SBDH read) |
| `maxBoundaryLength`       |      70 | the MIME boundary token                            |
| `maxKeyCandidates`        |       4 | decryption credentials tried during rollover       |

The SBDH inspection additionally uses the strict XML budgets
(`defaultXmlLimits`): `maxBytes` 64 MiB, `maxDepth` 64, `maxNodes` 100 000, where
`maxNodes` counts **every** node type — text nodes included, so an invoice with
many small elements reaches it well before "large invoice" sizes.

## What is buffered today

The path is bounded but not streaming end to end:

- **MIME (`src/receive/mime.ts`).** The request is reassembled into one buffer and
  each part is copied out of it, so peak memory scales with the request size
  (`maxRequestBytes`) and involves more than one full-size allocation. Ciphertext
  spooling starts after this.
- **Ciphertext quarantine (`src/receive/payload.ts`).** The part bytes are written
  to a private spool file in one pass; a second pass decrypts and authenticates,
  then (for gzip) decompresses into a private document spool. These are streamed
  and bounded by the representation/decompression limits.
- **SOAP envelope.** Held in memory, bounded by `maxEnvelopeBytes`.
- **SBDH inspection.** A DOM of up to `maxXmlBytes` of the recovered payload is
  built, then the header is read from it. Bounded by `maxXmlBytes` and the XML
  node/depth budgets.
- **Uncompressed-XML attachment signature.** The SwA content transform for an XML
  attachment canonicalises the document, which currently requires a full DOM
  bounded by the representation size.

Consequence: peak memory is roughly the sum of the MIME request buffer, the SOAP
envelope, and the largest DOM built (the SBDH read, and — for uncompressed XML —
the attachment for signature verification). It is bounded by the limits above, but
it is not proportional to a small constant.

## Known gaps

- **Node/depth limits are enforced after the DOM is built.** `enforceBudget` walks
  the parsed tree, so it does not prevent the allocation it is meant to constrain;
  only the byte cap (`maxBytes`) rejects before parsing. A node bomb within the
  byte budget is still fully parsed.
- **SBDH inspection builds a DOM for the whole payload** (up to `maxXmlBytes`) to
  read a header that sits at the very start.
- **Uncompressed XML canonicalisation needs a full DOM**, so a large uncompressed
  XML attachment is bounded by memory, not streamed.

## The SBDH resource-limit outcome

When the SBDH read cannot complete within a budget, `sbdh.status` is
`'resource-limit'` with the parser's reason (`xml.too-large`, `xml.too-many-nodes`,
`xml.too-deep`). This is deliberately **different** from `'malformed'`: a resource
limit is a bounded-inspection outcome, not a claim that the business document is
malformed. The message itself may still be accepted (`ok: true`).

## A "500 MB document" contract

Not established today. To make such a claim, each of the following must hold, and
be specified against document vs wire size:

1. **Streaming MIME** — parse headers incrementally and stream each ciphertext
   part into its quarantine file, so memory does not scale with the request.
2. **Streaming SBDH inspection** — extract and validate the SBDH subtree under
   dedicated bounds without building a DOM for the rest of the document, and be
   explicit about whether the remainder is checked for well-formedness.
3. **Pre-DOM budget enforcement** — reject over-budget documents before
   allocation, or move to a streaming parser.
4. **A documented supported representation** — because an uncompressed XML
   attachment still needs a DOM for signature canonicalisation, either bound it
   explicitly or stream canonicalisation.

Until then, treat the defaults as the supported envelope and raise them only with
the measured peak-memory budget of the host in mind.

## Verifying a configuration

Receiving-specific tests to run when changing these limits (see
`test/receive-open.test.ts`, `test/receive-payload.test.ts`,
`test/receive-xml.test.ts`, `test/receive-sbdh.test.ts`):

- a large incompressible request at the `maxRequestBytes` boundary;
- a highly compressible document that exceeds a decompression limit on the
  document axis but not the wire axis;
- node- and depth-limit boundaries, asserting `resource-limit` (not `malformed`);
- cancellation at each stage, asserting no residue and no success fact;
- measured peak memory (for example `node --max-old-space-size` plus RSS sampling)
  rather than an assumption.
