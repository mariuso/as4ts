# as4ts

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Node: >=22](https://img.shields.io/badge/node-%3E%3D22-brightgreen.svg)](#development)

Peppol AS4 sending and participant discovery for TypeScript and Node.js.

`as4ts` signs and encrypts a document, sends it to a receiving access point,
checks the returned receipt, and reports the result. A separate lookup API
resolves participants through SML/SMP and verifies the signed service metadata.
Your application supplies credentials, trust configuration, and storage, and
controls what happens after each attempt.

**Sending and lookup are implemented. Receiving is planned.** The package uses
ES modules and requires Node.js 22 or later.

[Example](#example) · [API](#api) · [Certificate profile](docs/certificate-profile.md) · [Changelog](CHANGELOG.md)

## Install

Build a package from the repository:

```bash
git clone https://github.com/mariuso/as4ts.git
cd as4ts
npm ci
npm run build
npm pack
```

Install the generated `as4ts-<version>.tgz` in your application with
`npm install /path/to/as4ts-<version>.tgz`. Building first is required: the package
exports compiled JavaScript and declarations from `dist/`.

To try a local send with generated test certificates and a local HTTPS receiver:

```bash
npm run selftest
```

The self-test writes throwaway credentials to `.example-output/`. Use them only
for local testing.

## Example

Send a complete SBDH-wrapped document and keep the verified receipt. Replace the
sample participants and endpoint with your own, and supply the receiver's AP
certificate and endpoint from validated discovery. The trust files must belong
to the same Peppol environment as your AP credentials.

```ts
import { createPrivateKey, randomUUID } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { readFile, writeFile } from 'node:fs/promises';
import { sendAs4, signerFromKey } from 'as4ts';
import { createCertificateValidator, defaultRevocationPolicy } from 'as4ts/certificate-validator';
import { classify } from 'as4ts/classifier';

const pem = (path: string) => readFile(path, 'utf8');
const validator = createCertificateValidator({
  roots: [await pem('peppol-root.pem')],
  intermediates: [await pem('peppol-ap-ca.pem')],
  revocation: defaultRevocationPolicy(),
});
const signer = signerFromKey(createPrivateKey(await pem('sender-ap.key')), await pem('sender-ap.pem'));
const receiverCertificate = await pem('receiver-ap.pem');

const result = await sendAs4({
  payload: createReadStream('invoice.sbdh.xml'),
  endpointUrl: 'https://ap.example/as4',
  transportProfile: 'peppol-transport-as4-v2_0',
  receiverCertificate,
  senderParticipant: { scheme: 'iso6523-actorid-upis', value: '0192:111111111' },
  receiverParticipant: { scheme: 'iso6523-actorid-upis', value: '0192:222222222' },
  documentType: {
    scheme: 'busdox-docid-qns',
    value:
      'urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice##' +
      'urn:cen.eu:en16931:2017#compliant#urn:fdc:peppol.eu:2017:poacc:billing:3.0::2.1',
  },
  process: {
    scheme: 'cenbii-procid-ubl',
    value: 'urn:fdc:peppol.eu:2017:poacc:billing:01:1.0',
  },
  as4MessageId: `${randomUUID()}@sender.example`,
  signer,
  validateCertificate: (input) => validator.validate(input),
  http: { connectMs: 10_000, totalMs: 120_000 },
  now: () => new Date(),
});

if (result.outcome === 'receipt-verified') {
  await writeFile('receipt.xml', result.receipt.raw, { mode: 0o600 });
} else {
  console.log({ outcome: result.outcome, classification: classify(result) });
}
```

The payload is opaque to the sender. Your application creates the SBDH and
business document and supplies matching participant, document type, and process
identifiers. A verified AS4 receipt is transport evidence; business validation
and downstream processing have their own results.

For command-line usage, see [sending a document](examples/send-one.ts) and
[participant lookup](examples/smp-lookup.ts). The sender example accepts PEM
credentials or a modern PBES2 PKCS#12 container.

## Design

**Each call performs one operation.** `sendAs4` makes one transmission attempt;
`lookupParticipant` performs one discovery. Queueing, persistence, discovery
caching, and retry scheduling belong to the application. Sending takes an
explicit endpoint and certificate, so discovery can follow your own lifecycle.

**Results preserve what happened.** Sending returns a discriminated union with
the receipt, protocol errors, or transport facts available for that attempt.
The separate `classify` function maps those facts to `accepted`, `retryable`,
`fatal`, or `unknown`. Its policy table can be replaced without changing the
transport code.

**Trust and key custody are explicit.** A required certificate validator checks
the receiver before payload preparation and the receipt signer before
acceptance. The included validator enforces a
[constrained certificate profile](docs/certificate-profile.md), with OCSP/CRL
checks and a reusable revocation cache. Its default policy blocks acceptance
when revocation status cannot be established. Purpose-specific intermediate
sets let you separate AP and SMP trust.

The signer interface accepts an implementation backed by a local key, HSM, or
remote key service. `signerFromKey` provides the local RSA implementation. The
sender verifies the produced signature against the signer's certificate before
transmission.

**Payload preparation is streamed.** The pipeline compresses the payload,
hashes the compressed bytes, and encrypts them with AES-128-GCM into a private
spool file. RSA-OAEP with SHA-256 wraps the session key. The encrypted payload
then streams into the multipart request, keeping memory use independent of the
full payload size. Temporary files use mode `0600` inside a `0700` workspace.

**Receipt acceptance checks the evidence.** RSA-SHA256 signature verification
must cover the parsed signal. The signer must pass certificate validation and
match the receiving AP identity; `RefToMessageId` must match the sent message.
The receipt must acknowledge every signed part exactly once, with matching
digest methods, transforms, parameters, and digest values. HTTPS certificate
verification and the TLS 1.2 minimum remain enabled for every transmission.

## API

| Entry point                   | Exports                                                                    | Purpose                                                        |
| ----------------------------- | -------------------------------------------------------------------------- | -------------------------------------------------------------- |
| `as4ts`                       | `sendAs4`, `signerFromKey`, `peppolProfile`                                | Prepare and send one signed, encrypted UserMessage.            |
| `as4ts/lookup`                | `lookupParticipant` and identifier helpers                                 | Discover an endpoint and verify its signed SMP metadata.       |
| `as4ts/certificate-validator` | `createCertificateValidator`, `defaultRevocationPolicy`, `RevocationCache` | Apply the supported certificate profile and revocation policy. |
| `as4ts/classifier`            | `classify`, `classifyEbmsError`, policy tables                             | Map send facts to application decisions.                       |

The public types document the full [send input and results](src/types.ts) and
[lookup input and results](src/lookup/types.ts).

### Send results

| Outcome              | Evidence                                                                                                     |
| -------------------- | ------------------------------------------------------------------------------------------------------------ |
| `receipt-verified`   | Verified receipt, signer certificate, timestamp, and message reference.                                      |
| `receipt-unverified` | Raw receipt and verification failure reason.                                                                 |
| `error-signal`       | All parsed ebMS errors, the raw signal, and the signal's `RefToMessageId` correlation with the sent message. |
| `no-signal`          | HTTP status and whether the response body was empty.                                                         |
| `transport-failure`  | Transport error, cancellation state, and an indication that the request may have reached the receiver.       |
| `not-sent`           | Local failure reason and optional detail.                                                                    |

An HTTP success status alone does not establish receipt of the document.
`classify` returns `accepted` only for a verified receipt, and `unknown` when a
receipt cannot be verified. An error signal is classified by its codes unless it
names a different message (`mismatched`), in which case it is `unknown`: it cannot
establish a result for our message. See the [classification table](src/outcome.ts)
for HTTP, ebMS, and local failure handling.

### Discovery

`lookupParticipant` takes the participant, document type, process, SML zone,
certificate validator, and clock. It resolves the SMP through U-NAPTR, verifies
the signed metadata, and selects a matching endpoint within its service dates.
The result is `found`, `not-registered`, `not-supported`, `signature-invalid`,
or `unavailable`.

Configure the validator with the SMP intermediate CA for `smp-signer`. The
`found` result supplies `endpointUrl`, `receiverCertificate`, and
`transportProfile` for a subsequent send. DNS resolution and HTTP fetching are
injectable; your application owns discovery caching.

## Status

Pre-1.0. Sending, signed participant discovery, receipt verification, certificate
validation, cancellation, and phase timing hooks are implemented. The test suite
covers message construction, tampering, certificate constraints, transport
failures, cancellation, and streaming memory use.

Test-network sends have produced verified receipts from independent access
points. [Captured receipts](test/fixtures/captures/) are exercised offline for
signature, canonicalization, signer trust, and signal binding. Those fixtures
do not retain the original outbound messages, so they cannot independently
check the echoed digests against the original payloads.

**This is not a certified Peppol Access Point.** A deployed service must complete
the applicable [Peppol Testbed](https://www.testbed.peppol.org/) onboarding tests.

Current limits:

- **Receiving is planned.** The [receiving design](docs/receiving.md) separates
  verification from acknowledgement so the application can store a document
  durably before issuing its receipt. There is no receiving API yet.
- **Durable retransmission is not implemented.** Each send builds a fresh
  envelope. Reusing a message ID alone does not preserve the original signed
  references; a replayable outbound artifact is still needed for reliable
  AS4 retries.
- **Signal and outcome details remain.** Error signals are now correlated with the
  sent message (`matches` / `absent` / `mismatched`), and spool cleanup can no
  longer override a result. Some factual details still need tightening — for
  example `requestBytesWritten` semantics and mapping local spool I/O failures to
  `spool.failed`. The [sending review](docs/sending-review.md) records these; its
  earlier security findings describe the reviewed snapshot.
- **Discovery has open compatibility questions.** Wildcard document-type
  matching needs further specification validation, and SMP redirect
  `CertificateUID` matching is not implemented. Supply the correct SML zone
  explicitly; the production-zone helper in the examples remains unverified.
- **Payload MIME type is a profile choice.** The default is `application/xml`;
  it is not presented as a value mandated by the Peppol AS4 profile.

## Development

From the repository checkout:

```bash
npm ci
npm run typecheck
npm run lint
npm run format
npm test
npm run build
npm run audit
```

CI runs on Node.js 22 and 24. To exercise a larger payload, use
`AS4_LARGE_MB=512 npm test`. The local round-trip tests use generated certificates
and a fake receiver. [Golden fixtures](test/golden/) cover envelope and multipart
serialization. Their committed private key is a throwaway test key.

Useful commands:

```bash
npm run examples:send -- --help
npm run examples:smp -- --help
npm run examples:record-smp -- --help
```

Runtime dependencies are `@xmldom/xmldom` for XML parsing and serialization, and
`xml-crypto` for canonicalization. The high-level `SignedXml` API is not used.
Node provides the cryptography, HTTPS, streams, and compression. PKIjs and ASN1js
are development dependencies for fixtures and example credential loading.

The wire format targets the
[Peppol AS4 profile](https://docs.peppol.eu/edelivery/as4/specification/) and its
referenced standards. Algorithm and namespace constants carry specification
references in [src/constants.ts](src/constants.ts).

## Versioning and contributing

The API may change between minor versions before 1.0. See the
[changelog](CHANGELOG.md) for API and wire-behavior changes.

Issues and pull requests are welcome. Add regression coverage for behavior
changes and run the development checks before opening a PR. Report suspected
vulnerabilities through [private vulnerability reporting](SECURITY.md).

## License

[Apache-2.0](LICENSE). Contributions use the same license.
