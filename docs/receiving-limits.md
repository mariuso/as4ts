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

| Limit                     | Default | Bounds                                                                      |
| ------------------------- | ------: | --------------------------------------------------------------------------- |
| `maxRequestBytes`         |  64 MiB | the complete HTTP request body                                              |
| `maxEnvelopeBytes`        |   1 MiB | the SOAP envelope bytes                                                     |
| `maxParts`                |       8 | MIME parts                                                                  |
| `maxHeaderBytes`          |  16 KiB | per-part MIME headers                                                       |
| `maxPartBytes`            |  64 MiB | a single MIME part                                                          |
| `maxRepresentationBytes`  |  64 MiB | the decrypted, pre-decompression representation                             |
| `maxDecompressedBytes`    | 256 MiB | decompressed output of one attachment                                       |
| `maxAggregateOutputBytes` | 512 MiB | decompressed output across the message                                      |
| `maxXmlBytes`             |  64 MiB | recovered XML bytes read by streaming SBDH inspection                       |
| `maxDomXmlBytes`          |   8 MiB | uncompressed XML bytes eligible for DOM processing                          |
| `maxCanonicalBytes`       |  16 MiB | conservative upper bound on one canonicalisation's expansion                |
| `maxXmlDepth`             |      64 | element nesting enforced before the DOM parser is invoked                   |
| `maxXmlNodes`             | 100 000 | nodes (elements, text, CDATA, comments, PIs) enforced before the DOM parser |
| `maxXmlAttributes`        |      64 | attributes and namespace declarations per element                           |
| `maxXmlTokenBytes`        |  64 KiB | one lexical XML token, in UTF-8 bytes                                       |
| `maxBoundaryLength`       |      70 | the MIME boundary token                                                     |
| `maxKeyCandidates`        |       4 | decryption credentials tried during rollover                                |

The two XML byte budgets are deliberately separate. `maxXmlBytes` bounds a document
that is only inspected incrementally (streaming SBDH); `maxDomXmlBytes` bounds an
uncompressed XML attachment that must be materialised as a DOM, and is therefore
much smaller. Raising the streaming document budget **never** raises the DOM
budget. Only XML 1.0 is supported on both paths.

Receiving XML paths, all using the shared policy in
[`src/receive/xml-lexical.ts`](../src/receive/xml-lexical.ts):

- **SOAP envelope parsing.** [`src/receive/xml.ts`](../src/receive/xml.ts)
  validates configuration and the byte cap, decodes under the shared policy, runs
  a bounded SAX preflight (depth, nodes, attributes, lexical tokens; a real DTD is
  rejected while the same text in a comment or CDATA is not), and only then builds
  the DOM. Encoding, ASCII enforcement, the bounded declaration and the
  `<?xml`-versus-`xml-stylesheet` distinction are the same code the SBDH reader
  uses.
- **SOAP signature canonicalisation.** `verifyWsSecuritySignature` is given
  `maxCanonicalBytes`; each `SignedInfo` and reference canonicalisation checks its
  conservative expansion bound first (inclusive-prefix handling included).
- **Uncompressed XML attachment.** `attachmentDigestBase64` parses under the DOM
  budgets, then canonicalises only within `maxCanonicalBytes`, hashing the
  returned string directly.

The canonicalisation bound is a **conservative upper bound**, not an exact
output-size limit: it charges every element's markup and attributes, worst-case
escaping of text, CDATA and attribute values, and the namespaces an element
_visibly uses_ — including a declaration made on an ancestor outside the subtree
being canonicalised — plus the inclusive prefixes on the apex. Names are measured
in UTF-8 bytes. With per-character escaping the bound stays close to the input
size for ordinary XML, so the 16 MiB canonical default comfortably covers the
8 MiB DOM default; expansion-amplifying input (a long URI repeated on every
descendant) is rejected before the canonical string is allocated.

`maxXmlBytes` used to bound DOM parsing. For migration, a caller that supplies
`maxXmlBytes` but not `maxDomXmlBytes` gets
`maxDomXmlBytes = min(defaultDomXmlBytes, maxXmlBytes)`, so lowering `maxXmlBytes`
still tightens the DOM budget; raising it never raises the DOM budget. Any other
omitted limit falls back to its default, so a missing property never silently
removes a bound. Every limit must be a finite, non-negative safe integer (`0`
allows nothing); an invalid configuration makes `openAs4Message` return a
`limits.invalid` failure before any parsing.

The DOM preflight consumes the whole decoded document in one pass, so "chunk
independence" applies to the streaming SBDH reader and to the request body, not to
the DOM preflight.

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
- **Uncompressed-XML attachment signature.** Bounded by `maxDomXmlBytes`: the
  document is strictly parsed under the DOM budgets (before the DOM parser runs),
  then canonicalised only within `maxCanonicalBytes`.

Consequence: peak memory is the SOAP envelope (`maxEnvelopeBytes`) plus the one DOM
built to canonicalise an uncompressed XML attachment (`maxDomXmlBytes`); the
request, the ciphertext and the decompressed documents are spooled to disk rather
than held in memory. It is bounded by the limits above.

## Known gaps

- **Uncompressed XML canonicalisation needs a full DOM**, so a large uncompressed
  XML attachment is bounded by `maxDomXmlBytes` (and the canonicalisation bound),
  not streamed. The DOM itself is bounded before allocation by the SAX preflight;
  the post-DOM structural check remains only as defence in depth.

## The SBDH resource-limit outcome

When the SBDH read cannot complete within a budget, `sbdh.status` is
`'resource-limit'` with the parser's reason (`xml.too-large`, `xml.too-many-nodes`,
`xml.too-deep`, `xml.too-many-attributes`, `xml.token-too-large`). This is
deliberately **different** from `'malformed'`: a resource limit is a
bounded-inspection outcome, not a claim that the business document is malformed.
The message itself may still be accepted (`ok: true`).

## A "500 MiB document" contract

The four prerequisites are met: MIME and the SBDH check stream, the DOM path is
guarded by a pre-parse preflight and a canonicalisation budget, and the supported
representations are documented. ("MiB" throughout; never "MB".)

**Claim (required).** A receiver configured with the override block below can open
a gzip-delivered business document of up to **500 MiB** (524,288,000 recovered
bytes) at **4 concurrent `openAs4Message` calls in one process**, with peak
process memory bounded and **not growing with the document size**, and with
temporary disk growing with message size and returning to empty after `dispose()`.
Four separate processes would trade lower per-process memory for higher total
memory; this contract is stated for one process.

**What is measured.** The _recovered_ (decrypted, decompressed) document; the
_wire_ (compressed request) is reported alongside. For a gzip-delivered document
the wire size is roughly recovered/9.6 (compressible invoice XML) to
recovered/1.33 (barely-compressible base64 content).

**Supported representations.** gzip attachments are in the claim. Uncompressed XML
attachments are **not**: they are parsed into a DOM, bounded by `maxDomXmlBytes`
(8 MiB) and `maxCanonicalBytes` (16 MiB), and raising `maxXmlBytes` raises neither.
Uncompressed binary attachments are streamed but are not part of the claim.

**Override block** (the defaults stay conservative; large messages opt in). Note
`maxXmlBytes` must cover the recovered document because every successful open
streams it through the SBDH check, and it does **not** raise the DOM or
canonicalisation budgets (`maxDomXmlBytes`, `maxCanonicalBytes`).

```ts
import type { InboundLimits } from 'as4ts/receive';

// Rounded up from the largest measured wire size (404 MiB for 512 MiB base64)
// and recovered size (512 MiB); 1 GiB gives headroom. Remaining limits keep
// their defaults.
const limits: Partial<InboundLimits> = {
  maxRequestBytes: 1024 * 1024 * 1024,
  maxPartBytes: 1024 * 1024 * 1024,
  maxRepresentationBytes: 1024 * 1024 * 1024,
  maxDecompressedBytes: 1024 * 1024 * 1024,
  maxAggregateOutputBytes: 1024 * 1024 * 1024,
  maxXmlBytes: 1024 * 1024 * 1024,
};
```

**Host requirements.** Peak spool disk at concurrency 4, measured: 2474 MiB for a
512 MiB compressible document, 5132 MiB for a 512 MiB barely-compressible one
(about 1.25 GiB per concurrent receive). Point `spoolDirectory` at a volume sized
for it; the directory is empty after every open is disposed.

**Cost.** At 512 MiB × 4 concurrency: about 75 s for the compressible document and
45 s for the barely-compressible one — roughly 27 and 46 MiB/s recovered
(Linux/Docker on the same host: 107 s and 69 s).

**Measured status (this revision).** The functional assertions pass on both macOS
and Linux — every open succeeds, the SBDH check is `consistent`, the payload
digest matches, and the spool is cleaned up — but the **memory assertions do not
meet the contract**: peak RSS grows with the message size on both platforms, and
the barely-compressible runs exceed the provisional 384 MiB ceiling from 256 MiB
(up to 1674 MiB at 512 MiB). The measured figures and the full finding list are in
[receiving-measurements.md](receiving-measurements.md). The ceiling was not raised
to make the run pass; closing this is a follow-up fix.

**How to reproduce.**

```bash
AS4_MEASURE_SIZES=64,256,512 AS4_MEASURE_KINDS=xml,base64 AS4_MEASURE_CONCURRENCY=4 \
  npm run measure:receive
```

`AS4_MEASURE_DIR` selects the fixture/spool root (default: a fresh directory under
`os.tmpdir()`); `AS4_MEASURE_KEEP=1` retains the generated fixtures. See
[receiving-measurements.md](receiving-measurements.md) for the recorded results.

## Verifying a configuration

Receiving-specific tests to run when changing these limits (see
`test/receive-xml-preflight.test.ts`, `test/receive-xml.test.ts`,
`test/receive-payload.test.ts`, `test/receive-integration.test.ts`,
`test/receive-sbdh-stream.test.ts`):

- a large incompressible request at the `maxRequestBytes` boundary;
- a highly compressible document that exceeds a decompression limit on the
  document axis but not the wire axis;
- byte, depth, node, attribute and token boundaries, one budget at a time,
  asserting the exact cap passes and cap + 1 fails;
- that an over-budget document never reaches the DOM parser, and an
  expansion-amplifying document never reaches the canonicaliser (instrumented
  counters, not just the failure);
- chunk independence (whole input, one-byte chunks and delimiter/encoding splits);
- the encoding policy (BOM/declaration agreement, ASCII, XML 1.1 rejection,
  invalid UTF-8, `<?xml-stylesheet` versus the declaration);
- cancellation at each stage, asserting no residue and no success fact;
- measured peak memory and disk rather than an assumption: run `npm run measure:receive`
  (see [receiving-measurements.md](receiving-measurements.md)).
