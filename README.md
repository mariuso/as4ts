# as4ts

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Node: >=22](https://img.shields.io/badge/node-%3E%3D22-brightgreen.svg)](#10-how-to-run)

A single-shot Peppol AS4 sender in strict TypeScript on Node 22+ (ES modules, no
framework). It performs **exactly one** AS4 send attempt and reports, as facts,
what happened. It never retries, never queues, never does SMP/SML lookup, never
touches the SBDH, never touches a database, and never reads files or environment
variables for its configuration.

The public surface is one function:

```ts
import { sendAs4 } from 'as4ts';
const result = await sendAs4(input); // SendAs4Result
```

Expected failures are **values**, never thrown exceptions.

> **Not certified.** This library has interoperated with independent access point
> implementations on the Peppol test network, but it is **not** a certified
> Peppol Access Point and carries no conformance statement. Every user must pass
> the Peppol Testbed with their own certificate before production use. See
> [Interop status](#8-interop-status).

---

## Install

```bash
npm install as4ts
```

Pre-1.0: the API may change between minor versions until 1.0.

---

## 1. What it does, and what it deliberately does not

It does:

- Build one AS4 `UserMessage`, sign it (RSA-SHA256 / exclusive C14N) and encrypt
  the payload (AES-128-GCM, RSA-OAEP key transport) exactly as the Peppol AS4
  profile requires.
- Validate the receiver certificate through an **injected, required** validator
  before any bytes are spooled.
- Verify the returned receipt (signature, signer trust, `RefToMessageId`,
  non-repudiation digests) and return the evidence.
- Stream the payload: compress → hash → encrypt → temp file, so a payload of any
  size never fits in memory.
- Return the outcome as a discriminated union of facts and a pure `classify`
  mapping.

It deliberately does not:

- Retry, queue, or persist anything.
- Do SMP/SML discovery, or read trust anchors, keys or configuration from files
  or the environment. The caller supplies all of that.
- Treat a certificate as trusted just because the network reached it: trust is
  the caller's policy, injected as a function.
- Decide whether to retry: it reports facts, and `classify` maps them.

---

## 2. API

### `sendAs4(input): Promise<SendAs4Result>`

The input is data only (no file or environment reads):

| Field                                       | Meaning                                                        |
| ------------------------------------------- | -------------------------------------------------------------- |
| `payload`                                   | `Readable` of the complete SBDH + business document, verbatim. |
| `endpointUrl`                               | Receiver AS4 endpoint (must be `https:`).                      |
| `transportProfile`                          | From SMP, e.g. `peppol-transport-as4-v2_0`.                    |
| `receiverCertificate`                       | Receiver AP certificate (PEM).                                 |
| `senderParticipant` / `receiverParticipant` | `{ scheme, value }`.                                           |
| `documentType` / `process`                  | `{ scheme, value }`.                                           |
| `as4MessageId`                              | Caller-supplied RFC 2822 `msg-id`; reused on retry.            |
| `signer`                                    | `{ certificate, sign(data) }`. See `signerFromKey`.            |
| `validateCertificate`                       | **Required.** `(input) => Promise<CertificateValidation>`.     |
| `profile?`                                  | Network constants. Defaults to `peppolProfile`.                |
| `signal?`                                   | `AbortSignal`. Stops spooling, HTTP and validation.            |
| `http`                                      | `{ ca?, serverName?, connectMs, totalMs }`.                    |
| `spoolDirectory?`                           | Temp directory. Defaults to the OS temp directory.             |
| `onEvent?`                                  | Observe phase timings. Exceptions are swallowed.               |
| `now`                                       | Deterministic clock.                                           |

`sendAs4` returns one of these facts:

| `outcome`            | Carries                                        | Meaning                                 |
| -------------------- | ---------------------------------------------- | --------------------------------------- |
| `receipt-verified`   | `receipt`                                      | A full receipt that verified.           |
| `receipt-unverified` | `reason`, `raw`                                | A receipt we could not accept.          |
| `error-signal`       | `errors[]`, `raw`                              | **All** ebMS errors, in document order. |
| `no-signal`          | `status`, `bodyEmpty`                          | A response that was not a signal.       |
| `transport-failure`  | `errorCode?`, `requestBytesWritten`, `aborted` | No complete response.                   |
| `not-sent`           | `reason`, `detail?`                            | Nothing was sent (local reason).        |

### `signerFromKey(keyObject, certificatePem): Signer`

Wraps a local RSA private key. The produced signature is verified against the
certificate before anything is sent; a mismatch becomes `not-sent`.

### `classify(result, table?): 'accepted' | 'retryable' | 'fatal' | 'unknown'`

Pure. The default table treats ebMS errors, HTTP status and local reasons as:

- `receipt-verified` → `accepted`.
- `receipt-unverified` → `unknown`.
- `error-signal` → the **most severe** class of its errors. `EBMS:0004` is
  `fatal` only when its `ErrorDetail` is `PEPPOL:NOT_SERVICED`, otherwise
  `retryable`.
- `no-signal` → 2xx/3xx `unknown`, 4xx `fatal`, other 5xx `retryable`, but
  `502`/`504` `unknown` (a gateway in front of the access point may have
  forwarded the message before returning).
- `transport-failure` → before any request byte `retryable`, after (including an
  abort mid-upload or while waiting for the receipt) `unknown`.
- `not-sent` → `spool.failed`, `certificate.unavailable` and `aborted` are
  `retryable` (a local I/O failure is safe to retry); the rest are `fatal`.

### Certificate validator (`as4ts/certificate-validator`)

```ts
import { createCertificateValidator, defaultRevocationPolicy } from 'as4ts/certificate-validator';

const validator = createCertificateValidator({
  roots: [rootPem],
  intermediates: [apCaPem],
  revocation: defaultRevocationPolicy(), // unreachable: 'strict' by default
  // fetch: customFetch,                  // optional
});

const validateCertificate = (input) => validator.validate(input);
```

The validator owns a long-lived revocation cache. It checks OCSP first, then
CRL, accepts a delegated OCSP responder (`id-kp-OCSPSigning`), and enforces
`thisUpdate`/`nextUpdate`.

### `SMP lookup is not part of the package`

`examples/smp-lookup.ts` is caller-side tooling **and does not verify the XML
signature on the SMP response**. Do not treat its output as authenticated.

---

## 3. Security model

- **Trust is injected and mandatory.** The core has no built-in trust store. Every
  send calls the caller's `validateCertificate` for the receiver certificate
  (`purpose: 'receiver-encryption'`) before spooling, and for the receipt signer
  (`purpose: 'receipt-signer'`) before a receipt is accepted. A missing or
  throwing validator never results in a send.
- **Signer interface, not a private key.** The caller supplies a `Signer`. For a
  local key, `signerFromKey` keeps the key in a closure. The produced signature is
  verified against the certificate's public key before it goes on the wire.
- **TLS cannot be weakened.** TLS 1.2 is the floor and certificate verification
  cannot be disabled. The sender always uses its own agent; a caller-supplied
  `agent` is not accepted (an `https.Agent` can carry `rejectUnauthorized:false`),
  so there is no option that turns verification off.
- **Temp files are private and always removed.** Ciphertext is spooled with mode
  `0600` in a `0700` directory, and removed on every path, including abort.
- **No secret material leaves the process.** `onEvent` receives only phase names
  and durations. Raw signal bytes are returned as evidence; keys, payload bytes
  and certificates' private parts never are.
- **Duplicate detection.** When you retry an `unknown` outcome, pass the **same**
  `as4MessageId`: a conformant receiver recognises the duplicate and re-acknowledges
  rather than delivering twice ([CEF] §3.3.2, [AS4PROFILE] §3.2).

---

## 4. Receipt verification

A receipt is accepted only when **all** of these hold (otherwise
`receipt-unverified`, and the raw bytes are still returned):

1. A `ds:Signature` inside `wsse:Security` verifies with RSA-SHA256 over
   `ds:SignedInfo` canonicalised with exclusive C14N and inclusive prefix `env`.
2. The signature's own `#id` references resolve **uniquely** and their SHA-256
   digests match.
3. The signature **covers the exact `eb:Messaging`/`eb:SignalMessage` we read**.
4. The signer certificate passes the injected validator and its common name
   equals the receiver's.
5. `RefToMessageId` equals the `as4MessageId` we sent.
6. Every `ebbpsig:NonRepudiationInformation` reference carries the digest we
   signed for that URI.

Covered by `test/receipt.test.ts`: wrong `RefToMessageId`, altered digest, broken
signature, untrusted signer, a forged receipt wrapped around another signer's
signature, revoked signer, signer CN mismatch, a forged unsigned receipt
prepended to a genuine one, a signature that does not cover the signal, and a
duplicate element id.

---

## 5. Locking the wire format

Every source of randomness and time is injectable internally: clock, XML ids,
MIME boundary, content id, session key and IV. The entropy seam is **not** a
public input (a caller-pinned session key and IV would break encryption); tests
reach it through `src/internal.ts`. `test/golden.test.ts` pins a byte-identical
SOAP envelope and multipart body against committed files in `test/golden/`, and
`test/golden/generate.ts` regenerates them.

`test/golden/sender-key.pem` is a throwaway, self-signed key committed on
purpose so the golden fixtures are reproducible. It protects nothing and must
never be used outside tests.

---

## 6. Module layout

```
src/
  index.ts                 sender entry point: sendAs4(), signerFromKey, peppolProfile
  send.ts                  the send core (internal; takes the entropy seam)
  internal.ts              test-only internals: sendAs4Internal, defaultEntropy
  certificate-validator.ts validator entry point: createCertificateValidator
  classifier.ts            classifier entry point: classify
  types.ts                 public input/result types and the fact union
  entropy.ts               the internal randomness seam
  profile.ts               the Peppol profile constants
  signer.ts                signerFromKey
  constants.ts             every namespace, URI, algorithm and identifier (spec-cited)
  outcome.ts               ebMS error table + pure classification
  errors.ts                internal, non-thrown failure carriers
  util.ts                  PEM/cert helpers, digest helpers, secret-safe messages
  temp-file.ts             private scratch workspace, always removed
  multipart.ts             streaming multipart/related body + exact Content-Length
  crypto/                  session-key wrap, streaming payload preparation
  xml/                     DOM helpers, C14N, user message, security, envelope, signal
  http/send.ts             one HTTPS POST, TLS 1.2+, verification always on
  pki/                     DER reader, path building, revocation, validation
  receipt/verify.ts        full receipt verification
examples/
  send-one.ts              example: send one real file to one real endpoint
  smp-lookup.ts            example: SMP lookup (does not verify the SMP signature)
test/
  golden.test.ts           byte-identical envelope and multipart fixtures
  *.test.ts                unit, receipt, PKI, abort, round-trip and memory tests
```

---

## 7. Layout of the result / classification

`sendAs4` returns facts. `classify` is a separate, pure function. This keeps the
network code free of retry policy.

```ts
import { sendAs4, signerFromKey, peppolProfile } from 'as4ts';
import { createCertificateValidator, defaultRevocationPolicy } from 'as4ts/certificate-validator';
import { classify } from 'as4ts/classifier';

const validator = createCertificateValidator({
  roots: [rootPem],
  intermediates: [apCaPem],
  revocation: defaultRevocationPolicy(),
});

const result = await sendAs4({
  payload: createReadStream('document.sbdh.xml'),
  endpointUrl: 'https://ap.example/as4',
  transportProfile: 'peppol-transport-as4-v2_0',
  receiverCertificate: receiverPem,
  senderParticipant: { scheme: 'iso6523-actorid-upis', value: '0192:111111111' },
  receiverParticipant: { scheme: 'iso6523-actorid-upis', value: '0192:222222222' },
  documentType: { scheme: 'busdox-docid-qns', value: 'urn:oasis:...::Invoice##...::2.1' },
  process: { scheme: 'cenbii-procid-ubl', value: 'urn:www.cenbii.eu:profile:bii05:ver2.0' },
  as4MessageId: 'message-1@example',
  signer: signerFromKey(privateKeyObject, certificatePem),
  validateCertificate: (v) => validator.validate(v),
  profile: peppolProfile,
  http: { connectMs: 10_000, totalMs: 120_000 },
  now: () => new Date(),
});

switch (classify(result)) {
  case 'accepted':
    break;
  case 'retryable':
    break;
  case 'unknown':
    break;
  case 'fatal':
    break;
}
```

---

## 8. Interop status

Receipts from independent access point implementations have been verified on the
Peppol test network (`outcome: 'receipt-verified'`,
`signerMatchesSmPCertificate: true`). This is **not** a conformance or
certification claim; each user must pass the Peppol Testbed with their own
certificate.

Offline receipt captures from real access points are committed under
`test/fixtures/captures/` and verified by `test/captures.test.ts`. They were
produced by this project's own sender against the Peppol test network, so no
third-party material is involved. Each capture is verified offline against the
bundled G3 test anchors, at the receipt's own timestamp: signature, exclusive
C14N, signer chain and signature-to-signal binding. Adding another capture is
just dropping the raw signal message into `test/fixtures/captures/`.

---

## 9. Dependencies

Runtime (two, pinned with caret ranges):

| Package          | Range     | Why                                                                                                                                             |
| ---------------- | --------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `@xmldom/xmldom` | `^0.8.15` | XML parse/serialise for the SOAP envelope and signals.                                                                                          |
| `xml-crypto`     | `^6.3.3`  | **Only** the low-level `ExclusiveCanonicalization` class. Its high-level `SignedXml` has had signature-bypass advisories; **we do not use it.** |

Dev/test only (not shipped): `node-forge` (test PKI/CRL/OCSP fixtures and PKCS#12
parsing in the example), `typescript`, `tsx`, `eslint`, `prettier` and the Node
type packages.

`npm audit` reports one **dev-only** advisory: `node-forge`
([GHSA-86w9-cpqp-85rv](https://github.com/advisories/GHSA-86w9-cpqp-85rv), RSA
PKCS#1 v1.5 signature _verification_ accepts extra nested `DigestAlgorithm`
elements; no fix available). It is not shipped (the package contains only
`dist/`, whose runtime deps are `@xmldom/xmldom` and `xml-crypto`) and the
flagged code path is never reached: this project only uses node-forge to
_generate_ test certificates/CRLs and to _parse_ PKCS#12, never to verify a
signature. `npm run audit` (`npm audit --omit=dev`) is clean, and CI runs it.

If you want a zero-advisory development tree, node-forge can be replaced by
`@peculiar/x509` (certificates, CRLs) plus a PKCS#12 library for the example.

---

## 10. How to run

```bash
npm install
npm run typecheck          # tsc --noEmit, strict
npm run lint               # eslint
npm run format             # prettier --check
npm test                   # all tests
AS4_LARGE_MB=512 npm test  # include a 512 MB streaming memory test
npm run build              # emit dist/
```

The round-trip test starts a fake receiver that decrypts, decompresses and
verifies the signature, then returns a signed receipt. It proves the sender
agrees with itself; it is not a conformance test against a real access point.

### The examples

```bash
node --import tsx examples/smp-lookup.ts --participant 'iso6523-actorid-upis::0192:222222222' --env test
node --import tsx examples/send-one.ts --help
```

`examples/smp-lookup.ts` does not verify the SMP response signature and is not
part of the package.

---

## 11. Specification references

| Tag                   | Document                                                | Sections used                                                                                                                                                          |
| --------------------- | ------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [PEPPOLAS4]           | Peppol AS4 Profile v2.0.3                               | §4.2 TLS, §4.3 Agreement, §4.5 Party Identification/roles, §4.6 Service/Action/Role, §4.7 PKI, §4.8 MPC, §4.9 SBDH, §4.10 packaging, §5 P-Mode, §6.2 transport profile |
| [CEF]                 | eDelivery AS4 1.15                                      | §3.2.2 message structure/MessageId, §3.2.3 packaging, §3.2.6 TLS/algorithms, §3.2.5 sync errors, §3.3.2 Reception Awareness, §5 example                                |
| [EBMS3CORE]           | OASIS ebMS 3.0 Core                                     | §2.2.8 MEP, §5.2 UserMessage, §6.2 error codes, §7.12/A.3 Receipt                                                                                                      |
| [AS4PROFILE]          | AS4 Profile of ebMS 3.0 v1.0                            | §3.1 compression/MimeType, §3.6 additional errors, §5.1.4/§5.1.5 signing, §5.2 attachments                                                                             |
| [WSSSMS] / [WSSX509]  | WS-Security SOAP Message Security / X.509 Token Profile | BST usage                                                                                                                                                              |
| [WSSSWA]              | WS-Security SOAP with Attachments Profile 1.1           | attachment transforms                                                                                                                                                  |
| [XMLDSIG1]            | XML Signature 1.1                                       | `xml-exc-c14n`, `rsa-sha256`, SHA-256                                                                                                                                  |
| [XMLENC] / [XMLENC11] | XML Encryption 1.0 / 1.1                                | `aes128-gcm`, GCM cipher value, `rsa-oaep`, `mgf1sha256`                                                                                                               |
| [EBbpsig]             | ebBP Signals 2.0                                        | `NonRepudiationInformation`                                                                                                                                            |
| [RFC5280]             | X.509 PKI                                               | path validation, CRL/OCSP                                                                                                                                              |
| [RFC1952] / [RFC2822] | GZIP / Internet Message Format                          | compression, `msg-id`                                                                                                                                                  |

---

## 12. Contributing and licence

Issues and pull requests are welcome. Before opening a PR, `npm install` and
then `npm test`, `npm run lint` and `npm run format` must all pass; add tests for
behaviour changes and keep modules small and single-purpose. Report suspected
vulnerabilities privately (see [`SECURITY.md`](SECURITY.md)), not in a public
issue.

This project is licensed under **Apache-2.0** — see [`LICENSE`](LICENSE).
Contributions are accepted under the same licence.
