# Inbound wire fixtures

The receiving parser, the coverage policy and the interoperability claims must be
proven against bytes this project did not produce. Independent captures from two
senders (for example Oxalis and phase4) are the evidence; local fixtures exercise
the harness but do not decide normative questions (see
[coverage](receiving-coverage.md)).

## How to capture

Point an independent sender at a logging HTTP endpoint that writes the request
body and the relevant headers to disk, and capture the complete exchange:

- Use **synthetic documents and test credentials only** — never production
  material.
- Capture the **complete request body, byte-for-byte**. Do not edit or re-format
  signed XML; a sanitised capture is worthless as evidence.
- Record the sender implementation and version, the transport profile, and the
  configuration the sender used (participant identifiers, document type,
  process, endpoint), the capture time, and whether the sender accepted the
  receipt this receiver generated for it.

## Layout

One directory per capture under `test/fixtures/inbound/<name>/`:

```
test/fixtures/inbound/<name>/
  request.bin             # the complete HTTP request body, transfer-decoded, unedited
  metadata.json           # context and expectations (below)
  receiver-cert.pem       # the captured receiver's AP certificate (test-only throwaway)
  receiver-key.pem        # its private key, so the test can decrypt (test-only)
  trust-roots.pem         # trust anchor(s) that validate the sender's signing certificate
  trust-intermediates.pem # intermediate CA certificate(s) for the sender's chain
```

`receiver-key.pem` is a throwaway test key whose only purpose is to let the test
unwrap the session key and decrypt the payload. Never record production key
material.

`metadata.json`:

```json
{
  "schema": 1,
  "origin": "independent",
  "capturedAt": "2026-01-01T00:00:00.000Z",
  "contentType": "multipart/related; type=\"application/soap+xml\"; boundary=\"...\"",
  "sender": { "implementation": "oxalis", "version": "...", "configuration": "..." },
  "transportProfile": "peppol-transport-as4-v2_0",
  "senderParticipant": { "scheme": "urn:fdc:peppol.eu:2017:identifiers:ap", "value": "POP000001" },
  "receiverParticipant": { "scheme": "urn:fdc:peppol.eu:2017:identifiers:ap", "value": "POP000002" },
  "originalSender": { "scheme": "iso6523-actorid-upis", "value": "0192:111111111" },
  "finalRecipient": { "scheme": "iso6523-actorid-upis", "value": "0192:222222222" },
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
          "algorithm": "http://docs.oasis-open.org/wss/oasis-wss-SwaProfile-1.1#Attachment-Content-Signature-Transform",
          "inclusivePrefixes": []
        }
      ]
    }
  ],
  "senderAcceptsReceipt": true
}
```

`senderParticipant`/`receiverParticipant` are the **AS4 access-point identities**
used in `From`/`To` — the access-point certificate common names. The integrated
SBDH business participants are the separate `originalSender`/`finalRecipient`
(optional, but recorded so a capture can assert them too).

`expectedSignedReferences` records the full reference semantics the sender
computed — digest algorithm and ordered transforms with their inclusive-prefix
parameters — not just URI and digest.

`origin` distinguishes an `independent` capture from a locally generated one
(`local`). Only independent captures count for the Phase 6 validation gate.

## What the suite does with them

`test/helpers/capture.ts` runs each capture through the **real receiving path**
(`openAs4Message`): bounded MIME parse, strict XML, signature and coverage,
signer validation against the recorded trust chain, session-key unwrap with the
captured receiver credential, decryption and payload recovery; then it compares
the recovered payload hash and the complete reference set, and disposes every
handle.

- The ordinary suite (`npm test`) verifies whatever captures are present and
  skips when the directory holds none, so day-to-day work stays green.
- The Phase 6 validation command (`npm run validate:receive`) **fails** unless at
  least two **independent** captures are present and verify. A local capture is
  never counted as independent evidence.

`test/receiving-capture-local.test.ts` generates a local capture with this
project's sender and verifies it end to end, which exercises the harness without
committing a credential — but it is labelled `origin: "local"` and does not
satisfy the validation gate.
