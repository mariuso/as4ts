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

| Limit                     | Default | Bounds                                                                             |
| ------------------------- | ------: | ---------------------------------------------------------------------------------- |
| `maxRequestBytes`         |  64 MiB | the complete HTTP request body                                                     |
| `maxEnvelopeBytes`        |   1 MiB | the SOAP envelope bytes                                                            |
| `maxParts`                |       8 | MIME parts                                                                         |
| `maxHeaderBytes`          |  16 KiB | per-part MIME headers                                                              |
| `maxPartBytes`            |  64 MiB | a single MIME part                                                                 |
| `maxRepresentationBytes`  |  64 MiB | the decrypted, pre-decompression representation                                    |
| `maxDecompressedBytes`    | 256 MiB | decompressed output of one attachment                                              |
| `maxAggregateOutputBytes` | 512 MiB | decompressed output across the message                                             |
| `maxXmlBytes`             |  64 MiB | recovered XML bytes read by streaming SBDH inspection and the uncompressed-XML DOM |
| `maxBoundaryLength`       |      70 | the MIME boundary token                                                            |
| `maxKeyCandidates`        |       4 | decryption credentials tried during rollover                                       |

SBDH inspection streams the recovered document
([`src/receive/sbdh-stream.ts`](../src/receive/sbdh-stream.ts)); it does not build a
DOM. Its header budgets (`defaultSbdhStreamLimits`) are separate from the document
budget: `documentBytes` is `maxXmlBytes`, `documentDepth` 256, `headerBytes`
256 KiB (the UTF-8 byte span of the SBDH header element itself, including its
opening markup — not approximated from the document root), `headerNodes` 4096,
`headerDepth` 32, `attributes` 64, and `tokenBytes` 64 KiB bounds any one lexical
token (a text run, a tag and its attribute collection, a comment, a CDATA section
or a processing instruction), measured in UTF-8 bytes and enforced while input is
consumed rather than after the parser has accumulated it. A `DOCTYPE` is rejected
as soon as its opening is recognised (a malformed outcome, and the reason the
internal subset can never be accumulated), and the optional XML declaration is
read under its own bounded limit. Only **XML 1.0** is supported: an XML 1.1
declaration is rejected, because 1.1 changes the whitespace and line-separator
rules that the lexical scanner relies on.

## What is buffered today

The path is bounded but not streaming end to end:

- **MIME (`src/receive/multipart.ts`).** Headers and delimiters are parsed
  incrementally and each ciphertext part is streamed into a private spool file, so
  peak memory does not scale with the request size; only the bounded SOAP part is
  held in memory (`maxEnvelopeBytes`).
- **Ciphertext quarantine (`src/receive/payload.ts`).** The part bytes are written
  to a private spool file in one pass; a second pass decrypts and authenticates,
  then (for gzip) decompresses into a private document spool. These are streamed
  and bounded by the representation/decompression limits.
- **SOAP envelope.** Held in memory, bounded by `maxEnvelopeBytes`.
- **SBDH inspection.** Streamed: only the bounded header facts are retained, while
  the whole document is still parsed (so malformed content after the header and a
  second header are detected). Bounded by `maxXmlBytes` (document bytes) and the
  separate header/token budgets above.
- **Uncompressed-XML attachment signature.** The SwA content transform for an XML
  attachment canonicalises the document, which currently requires a full DOM
  bounded by the representation size.

Consequence: peak memory is the SOAP envelope (`maxEnvelopeBytes`) plus the one DOM
built to canonicalise an uncompressed XML attachment for signature verification
(bounded by the representation size); the request, the ciphertext and the
decompressed documents are spooled to disk rather than held in memory. It is
bounded by the limits above.

## Known gaps

- **Node/depth limits are enforced after the DOM is built.** `enforceBudget` walks
  the parsed tree, so it does not prevent the allocation it is meant to constrain;
  only the byte cap (`maxBytes`) rejects before parsing. A node bomb within the
  byte budget is still fully parsed.
- **Uncompressed XML canonicalisation needs a full DOM**, so a large uncompressed
  XML attachment is bounded by memory, not streamed.

## The SBDH resource-limit outcome

When the SBDH read cannot complete within a budget, `sbdh.status` is
`'resource-limit'` with the parser's reason (`xml.too-large`, `xml.too-many-nodes`,
`xml.too-deep`, `xml.too-many-attributes`, `xml.token-too-large`). This is
deliberately **different** from `'malformed'`: a resource limit is a
bounded-inspection outcome, not a claim that the business document is malformed.
The message itself may still be accepted (`ok: true`).

## A "500 MB document" contract

Not established today. To make such a claim, each of the following must hold, and
be specified against document vs wire size:

1. **Streaming MIME** — done: headers and delimiters are parsed incrementally and
   each ciphertext part is streamed into its quarantine file, so memory does not
   scale with the request.
2. **Streaming SBDH inspection** — done: the SBDH subtree is validated under
   dedicated bounds without building a DOM, and the remainder is still parsed for
   well-formedness.
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
`test/receive-xml.test.ts`, `test/receive-sbdh-stream.test.ts`):

- a large incompressible request at the `maxRequestBytes` boundary;
- a highly compressible document that exceeds a decompression limit on the
  document axis but not the wire axis;
- node- and depth-limit boundaries, asserting `resource-limit` (not `malformed`);
- cancellation at each stage, asserting no residue and no success fact;
- measured peak memory (for example `node --max-old-space-size` plus RSS sampling)
  rather than an assumption.
