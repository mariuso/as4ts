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

Install a published release directly from its GitHub asset, pinned by URL and
hash:

```bash
# The receiving entry point ships in the 0.2.0-rc.1 pre-release; the latest
# stable release, 0.1.0, is the sender-only surface.
VERSION=0.2.0-rc.1
curl -fsSL -o "as4ts-$VERSION.tgz" \
  "https://github.com/mariuso/as4ts/releases/download/v$VERSION/as4ts-$VERSION.tgz"
shasum -a 256 "as4ts-$VERSION.tgz"
# expect 5a909ea9b5ed329569bdaddaf07d8f3bc1038f44d18cf03adc4f08ba876e0e21
npm install "./as4ts-$VERSION.tgz"
```

Each release note records the commit it was built from and the asset's sha256.
Releases are immutable — a fix is a new version, never a replaced asset — so pin
the URL and the hash in your lockfile. New releases are listed on the
[releases page](https://github.com/mariuso/as4ts/releases); once the package is on
npm, install the plain version instead.

To build from source instead:

```bash
git clone https://github.com/mariuso/as4ts.git
cd as4ts
npm ci
npm run build
npm pack
npm install /path/to/as4ts-<version>.tgz
```

Building is required for the source path: the package exports compiled JavaScript
and declarations from `dist/`.

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

**Retries reuse a prepared message.** `prepareAs4` produces an immutable artifact
— the signed envelope, the encrypted payload, and the signed references — that
`transmitAs4` can send any number of times. A retry re-sends the exact same bytes
and verifies the receipt against the original references, so an uncertain outcome
can be retried without changing the signed message. The artifact lives in a
directory (`metadata.json` plus the encrypted attachment); persist that directory
to survive a restart and reload it with `loadPreparedMessage`. `sendAs4` is the
one-shot convenience over the two calls.

**Receipt acceptance checks the evidence.** RSA-SHA256 signature verification
must cover the parsed signal. The signer must pass certificate validation and
match the receiving AP identity; `RefToMessageId` must match the sent message.
The receipt must acknowledge every signed part exactly once, with matching
digest methods, transforms, parameters, and digest values. HTTPS certificate
verification and the TLS 1.2 minimum remain enabled for every transmission.

## API

| Entry point                   | Exports                                                                                         | Purpose                                                                    |
| ----------------------------- | ----------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| `as4ts`                       | `sendAs4`, `prepareAs4`, `transmitAs4`, `loadPreparedMessage`, `signerFromKey`, `peppolProfile` | Prepare and send one signed, encrypted UserMessage.                        |
| `as4ts/receive`               | `openAs4Message`, `respondAs4Message`, `keyHolderFromKey`, `ebmsErrorFor`, `notServicedError`   | Verify and unpack one inbound UserMessage, then build its signed response. |
| `as4ts/lookup`                | `lookupParticipant` and identifier helpers                                                      | Discover an endpoint and verify its signed SMP metadata.                   |
| `as4ts/certificate-validator` | `createCertificateValidator`, `defaultRevocationPolicy`, `RevocationCache`                      | Apply the supported certificate profile and revocation policy.             |
| `as4ts/classifier`            | `classify`, `classifyEbmsError`, policy tables                                                  | Map send facts to application decisions.                                   |

The public types document the full [send input and results](src/types.ts),
[receive input and results](src/receive/types.ts), and
[lookup input and results](src/lookup/types.ts). The two-step receiving flow
(`openAs4Message` / `respondAs4Message`) is documented in
[Receiving API](docs/receiving-api.md).

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

Pre-1.0. Sending, inbound verification and response construction, signed
participant discovery, receipt verification, certificate validation,
cancellation, and phase timing hooks are implemented. The test suite covers
message construction, tampering, certificate constraints, transport failures,
cancellation, and streaming memory use.

Test-network sends have produced verified receipts from independent access
points. [Captured receipts](test/fixtures/captures/) are exercised offline for
signature, canonicalization, signer trust, and signal binding. Those fixtures
do not retain the original outbound messages, so they cannot independently
check the echoed digests against the original payloads.

**This is not a certified Peppol Access Point.** A deployed service must complete
the applicable [Peppol Testbed](https://www.testbed.peppol.org/) onboarding tests.

Current limits:

- **Receiving is implemented.** The [`as4ts/receive`](docs/receiving.md) entry
  point separates verification (`openAs4Message`) from acknowledgement
  (`respondAs4Message`) so the application can store a document durably before
  issuing its receipt; [`examples/receive-inbox.ts`](examples/receive-inbox.ts)
  shows a durable inbox with duplicate suppression and lost-response recovery.
  The required signature coverage for an empty SOAP Body and the sender fixtures
  that freeze it are still open (see
  [`docs/receiving-coverage.md`](docs/receiving-coverage.md)); until then the
  inbound parser is exercised against locally generated messages, not live peers.
  Receiving is bounded but not streaming end to end; the limit table and the
  size-envelope limitations are in
  [`docs/receiving-limits.md`](docs/receiving-limits.md).
- **Durable retransmission is caller-driven.** `prepareAs4` + `transmitAs4`
  re-send an identical artifact, and the directory it writes can be persisted and
  reloaded with `loadPreparedMessage`. Persistence, retention and retry policy
  remain the application's responsibility.
- **Revocation has stated limits.** Delta and scoped/indirect CRLs are rejected
  rather than followed, a CRL must carry a `nextUpdate`, and a delegated OCSP
  responder's own revocation is not checked. See
  [`docs/certificate-profile.md`](docs/certificate-profile.md).
- **Sender conformance follow-up: attachment `ds:KeyInfo`.** The sender emits a
  `ds:KeyInfo` inside the attachment's `xenc:EncryptedData`; SwA §5.5 prohibits it
  when an `xenc:EncryptedKey` is used (the key is named by `ReferenceList`). The
  receiver accepts both layouts and validates consistency; the redundant
  `ds:KeyInfo` should be dropped.
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
npm run examples:receive
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

### Releases

Releases are cut from a tag whose commit carries matching versions in
`package.json`, `package-lock.json` and `src/version.ts`. The supported
procedure:

```bash
# 1. Bump without letting npm commit or tag; the `version` lifecycle script
#    rewrites src/version.ts from package.json.
npm version <version> --no-git-tag-version

# 2. Stage every version file, commit, and tag the tested commit.
git add package.json package-lock.json src/version.ts
git commit -m "release: <version>"
git tag -a v<version> -m "as4ts v<version>"
git push && git push origin v<version>
```

The [Release workflow](.github/workflows/release.yml) then verifies the tag
matches `package.json`, runs the checks, builds and packs
(`npm run build && npm pack`), and attaches `as4ts-<version>.tgz` to the GitHub
release. A tag containing `-` (for example `v0.2.0-rc.1`) is published as a
pre-release. Release assets are immutable: a fix is a new version, never a
replaced file. `test/release-procedure.test.ts` exercises this procedure in a
throwaway repository and asserts the versions inside the tag.

Issues and pull requests are welcome. Add regression coverage for behavior
changes and run the development checks before opening a PR. Report suspected
vulnerabilities through [private vulnerability reporting](SECURITY.md).

## License

[Apache-2.0](LICENSE). Contributions use the same license.
