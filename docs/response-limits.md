# Response limits: receipts, error signals and SMP lookups

The receiving path parses attacker-controlled XML under
[strict limits](receiving-limits.md). The sender's **responses** are also remote
input, so a receipt/error signal and an SMP lookup response are now parsed the
same strict way and canonicalised under a budget. Two optional overrides control
them; both default conservatively.

## Why strict parsing

`parseXml` (the sender's local builder) silently repairs malformed XML, ignores
the declared encoding and accepts a DOCTYPE. Remote responses must not be
repaired: a receipt that is malformed, encoding-mismatched, DOCTYPE-bearing or
over-limit is a `no-signal`, and an SMP response that fails the same checks is
`unavailable`. Both paths pass through `parseStrictXml` (`src/xml/strict.ts`), so
they share XML 1.0-only decoding, BOM/declaration agreement, a pre-DOM SAX
preflight and the export guard in `test/module-layout.test.ts`.

## Response limits (`ResponseLimits`, `sendAs4` / `transmitAs4`)

| Limit               | Default | Bounds                                            |
| ------------------- | ------: | ------------------------------------------------- |
| `maxXmlBytes`       |   1 MiB | the SOAP envelope, after MIME extraction          |
| `maxDepth`          |      64 | element nesting                                   |
| `maxNodes`          |  10 000 | elements, text, CDATA, comments, PIs              |
| `maxAttributes`     |      64 | attributes and namespace declarations per element |
| `maxTokenBytes`     |  64 KiB | one lexical token, in UTF-8 bytes                 |
| `maxCanonicalBytes` |  16 MiB | **total** across SignedInfo and every reference   |

The defaults are far above real responses: every captured receipt is under 10 KB,
63 nodes and depth 10. `maxCanonicalBytes` is a total because a receipt may
declare up to 64 references; a per-call bound alone would allow 64× the work. The
bound is a conservative upper bound checked _before_ any canonical string is
allocated.

A response that cannot be read strictly becomes `no-signal` with a secret-free
`detail` (`xml.too-large`, `xml.doctype`, `signal.shape`, ...). An over-budget
receipt that is otherwise well-formed is `receipt-unverified` with
`receipt.malformed`. Retry classification still depends only on the HTTP status.

## Lookup limits (`LookupLimits`, `lookupParticipant`)

| Limit                  | Default | Bounds                                                                |
| ---------------------- | ------: | --------------------------------------------------------------------- |
| `maxServiceGroupBytes` |   8 MiB | a ServiceGroup response (equals today's HTTP cap)                     |
| `maxServiceGroupNodes` | 200 000 | ServiceGroup nodes; a large participant publishes many document types |
| `maxMetadataBytes`     |   1 MiB | a SignedServiceMetadata response (first fetch and redirect)           |
| `maxMetadataNodes`     |  10 000 | SignedServiceMetadata nodes                                           |
| `maxDepth`             |      64 | element nesting (both shapes)                                         |
| `maxAttributes`        |      64 | attributes and namespace declarations per element                     |
| `maxTokenBytes`        |  64 KiB | one lexical token, in UTF-8 bytes                                     |
| `maxCanonicalBytes`    |   8 MiB | **total** for the document digest plus SignedInfo                     |

A lookup response that fails is `unavailable` with `<url>: <reason>`, before any
fact is read. The fixed HTTP caps (16 MiB for the sender in `src/http/send.ts`,
8 MiB for lookup in `src/lookup/http.ts`) are unchanged and not overridable;
exceeding them keeps today's `transport-failure` / `unavailable` behaviour.

`verifySmpSignature` checks the document-digest bound plus the SignedInfo bound
against `maxCanonicalBytes` **before** `cloneNode(true)` and before
canonicalising, so an expansion-amplifying response is rejected as not verifiable.

## Invalid overrides

An invalid value (negative, `NaN`, `Infinity`, non-integer) is a configuration
error, not an availability problem:

- `sendAs4` / `transmitAs4`: `not-sent` with `limits.invalid`, before any spool
  work or HTTP request;
- `lookupParticipant`: `unavailable` with `limits.invalid: ...`, before any DNS
  query.

## How to reproduce

`npm run measure:receive` covers the receiving contract. The response/lookup
bounds are exercised by `test/response-limits.test.ts`, `test/lookup.test.ts`,
`test/response-limits-cpu.test.ts` and the 24 000-document soundness fuzz in
`test/lookup-smp-bound.test.ts`.
