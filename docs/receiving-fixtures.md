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
  "expectedCoverage": { "messaging": true, "body": true },
  "expectedPayloadSha256Base64": "...",
  "expectedSignedReferences": [
    {
      "uri": "#...",
      "digest": "...",
      "digestMethod": "http://www.w3.org/2001/04/xmlenc#sha256",
      "transforms": [{ "algorithm": "http://www.w3.org/2001/10/xml-exc-c14n#", "inclusivePrefixes": [] }]
    },
    {
      "uri": "cid:...",
      "digest": "...",
      "digestMethod": "http://www.w3.org/2001/04/xmlenc#sha256",
      "transforms": [
        {
          "algorithm": "http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Signature-Transform",
          "inclusivePrefixes": []
        }
      ]
    }
  ]
}
```

`expectedSignedReferences` records the full reference semantics the sender
computed (digest algorithm and ordered transforms with parameters), not just URI
and digest. To let the eventual test verify the attachment digests, the capture
also includes the **receiver** AP key material as a test-only throwaway
(`receiver-key.pem`); use synthetic credentials only.

## What the suite does with them

[`test/receiving-captures.test.ts`](../test/receiving-captures.test.ts) parses
each capture with the real bounded MIME parser and strict XML parser, then
asserts:

- the WS-Security signature verifies;
- it covers `eb:Messaging` and the SOAP Body (per `expectedCoverage`);
- every `expectedSignedReferences` entry matches on URI, digest, **digest
  algorithm and ordered transforms** — so the capture proves reference semantics,
  not merely MIME selection.

Verifying the **attachment** digest requires decryption, so that assertion lands
with `openAs4Message` and the `receiver-key.pem` credential; until then the
loader covers envelope coverage and reference semantics. When no captures are
present the test skips, so the suite stays green.
