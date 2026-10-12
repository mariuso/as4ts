# Inbound wire fixtures

Phase 1 needs captured inbound `UserMessage` requests from **two independent
senders** (for example Oxalis and phase4), because the receiving parser and the
coverage policy must be proven against bytes this project did not produce. Local
fixtures establish interoperability evidence; they do not decide normative
requirements (see [coverage](receiving-coverage.md)).

## How to capture

Point an independent sender at a logging HTTP endpoint that writes the request
body and the relevant headers to disk, and capture the complete exchange:

- Use **synthetic documents and test credentials only** — never production
  material.
- Capture the **complete request body, byte-for-byte**. Do not edit or re-format
  signed XML; a sanitised capture is worthless as evidence.
- Record the sender implementation and version, the transport profile, and the
  configuration the sender used (participant identifiers, document type,
  process, endpoint).

## Layout

One directory per capture under `test/fixtures/inbound/<name>/`:

```
test/fixtures/inbound/<name>/
  request.bin      # the complete HTTP request body, transfer-decoded, unedited
  metadata.json    # context and expectations (below)
```

`metadata.json`:

```json
{
  "contentType": "multipart/related; type=\"application/soap+xml\"; boundary=\"...\"",
  "sender": { "implementation": "oxalis", "version": "..." },
  "transportProfile": "peppol-transport-as4-v2_0",
  "senderParticipant": { "scheme": "iso6523-actorid-upis", "value": "0192:...:" },
  "receiverParticipant": { "scheme": "iso6523-actorid-upis", "value": "0192:...:" },
  "documentType": { "scheme": "busdox-docid-qns", "value": "urn:oasis:...::...::2.1" },
  "process": { "scheme": "cenbii-procid-ubl", "value": "urn:fdc:peppol.eu:2017:poacc:billing:01:1.0" },
  "expectedParts": 2,
  "expectedPayloadSha256Base64": "...",
  "expectedSignedReferences": [
    { "uri": "#...", "digest": "..." },
    { "uri": "cid:...", "digest": "..." }
  ]
}
```

`expectedSignedReferences` and `expectedPayloadSha256Base64` are the values the
sender computed, used to check the receiver's independent computation.

## What the suite does with them

[`test/receiving-captures.test.ts`](../test/receiving-captures.test.ts) parses
each capture with the bounded MIME parser and asserts the SOAP part and part
count. As `openAs4Message` lands, the same fixtures gain signature coverage,
decryption, decompression and SBDH assertions. When no captures are present the
test skips, so the suite stays green until the fixtures are recorded.
