import test from 'node:test';
import assert from 'node:assert/strict';
import { ALGO_EXC_C14N, SWA_TRANSFORM_SIGNATURE } from '../src/constants.js';
import { defaultRevocationPolicy } from '../src/certificate-validator.js';
import { defaultResponseLimits } from '../src/response-limits.js';
import { parseSignal } from '../src/xml/signal.js';
import { verifyReceipt, type SignedReference } from '../src/receipt/verify.js';
import { xmlHooks } from '../src/xml/hooks.js';
import { createTestPki } from './helpers/pki.js';
import { buildSignedReceipt, type ReceiptReference } from './helpers/receipt.js';
import { testValidator } from './helpers/input.js';
import { mkdtemp, rm } from 'node:fs/promises';
import { readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { signerFromKey } from '../src/index.js';
import { defaultEntropy, sendAs4Internal } from '../src/internal.js';
import { transmitAs4 } from '../src/transmit.js';

/**
 * Item 6, Phase 2: a receipt or error signal is parsed and canonicalised under
 * limits, and a hostile or over-limit response is a `no-signal` rather than a
 * repaired document. The hooks prove the DOM parser and the canonicaliser never
 * ran on the over-limit vectors.
 */
const pki = createTestPki();
const MESSAGE_ID = 'the-message-we-sent@as4-sender.test';
const revocation = defaultRevocationPolicy({ ocsp: false, crl: false });

const refs: ReceiptReference[] = [
  { uri: '#body-id', transform: ALGO_EXC_C14N, digest: 'AAAA' },
  { uri: '#messaging-id', transform: ALGO_EXC_C14N, digest: 'BBBB' },
  { uri: 'cid:attachment@x', transform: SWA_TRANSFORM_SIGNATURE, digest: 'CCCC' },
];
const signedReferences: SignedReference[] = refs.map((reference) => ({ uri: reference.uri, digest: reference.digest }));

let domCalls = 0;
let canonicalizeCalls = 0;
xmlHooks.onDomParse = () => {
  domCalls += 1;
};
xmlHooks.onCanonicalize = () => {
  canonicalizeCalls += 1;
};
function reset(): void {
  domCalls = 0;
  canonicalizeCalls = 0;
}

function envelope(inner: string): Buffer {
  return Buffer.from(
    `<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope"><env:Header>${inner}</env:Header><env:Body/></env:Envelope>`,
    'utf8',
  );
}

const HOSTILE: ReadonlyArray<readonly [string, Buffer, string]> = [
  [
    'malformed XML that xmldom used to repair',
    Buffer.from('<env:Envelope><env:Header><a><b>t</env:Header>', 'utf8'),
    'xml.malformed',
  ],
  ['a DOCTYPE', Buffer.from('<!DOCTYPE a []><a/>', 'utf8'), 'xml.doctype'],
  ['trailing junk after the root', Buffer.from('<a/>trailing', 'utf8'), 'xml.malformed'],
  [
    'a UTF-8 declaration with invalid UTF-8 bytes',
    Buffer.from([0x3c, 0x61, 0x3e, 0xff, 0x3c, 0x2f, 0x61, 0x3e]),
    'xml.malformed',
  ],
  [
    'a UTF-8 BOM conflicting with an ISO-8859-1 declaration',
    Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('<?xml version="1.0" encoding="iso-8859-1"?><a/>')]),
    'xml.malformed',
  ],
];

test('hostile responses are rejected strictly and never reach the DOM parser', () => {
  reset();
  for (const [name, bytes, reason] of HOSTILE) {
    const parsed = parseSignal(bytes);
    assert.equal(parsed.ok, false, name);
    if (!parsed.ok) assert.equal(parsed.reason, reason, name);
  }
  assert.equal(domCalls, 0, 'no hostile response reached the DOM parser');
});

test('over-limit responses are rejected with the exact reason, before the DOM parser', () => {
  reset();
  const big = envelope(`<!--${'x'.repeat(200)}-->`);
  const vectors: ReadonlyArray<readonly [string, Buffer, Partial<typeof defaultResponseLimits>, string]> = [
    ['over maxXmlBytes', big, { maxXmlBytes: 16 }, 'xml.too-large'],
    ['over maxNodes', envelope('<n/>'.repeat(5)), { maxNodes: 2 }, 'xml.too-many-nodes'],
    ['over maxDepth', envelope('<a><b><c/></b></a>'), { maxDepth: 1 }, 'xml.too-deep'],
    ['over maxAttributes', envelope('<a b="1" c="2"/>'), { maxAttributes: 1 }, 'xml.too-many-attributes'],
    ['over maxTokenBytes', envelope(`<a>${'x'.repeat(300)}</a>`), { maxTokenBytes: 64 }, 'xml.token-too-large'],
  ];
  for (const [name, bytes, override, reason] of vectors) {
    const parsed = parseSignal(bytes, { ...defaultResponseLimits, ...override });
    assert.equal(parsed.ok, false, name);
    if (!parsed.ok) assert.equal(parsed.reason, reason, name);
  }
  assert.equal(domCalls, 0, 'no over-limit response reached the DOM parser');
});

test('a valid receipt still parses under the default response limits', () => {
  reset();
  const { signal } = buildSignedReceipt({ signer: pki.receiver, refToMessageId: MESSAGE_ID, references: refs });
  assert.equal(signal.kind, 'receipt');
  assert.equal(domCalls, 1);
});

test('a canonicalisation budget is enforced before the canonicaliser runs', async () => {
  const { signal } = buildSignedReceipt({ signer: pki.receiver, refToMessageId: MESSAGE_ID, references: refs });
  reset();
  const result = await verifyReceipt({
    signal,
    as4MessageId: MESSAGE_ID,
    receiverCertificatePem: pki.receiver.certPem,
    signedReferences,
    validateCertificate: testValidator(pki, { revocation }),
    limits: { ...defaultResponseLimits, maxCanonicalBytes: 8 },
    now: () => new Date(),
  });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'receipt.malformed');
  assert.equal(canonicalizeCalls, 0, 'the canonicaliser must not run over budget');
});

test('a receipt verifying normally still canonicalises and succeeds', async () => {
  const { signal } = buildSignedReceipt({ signer: pki.receiver, refToMessageId: MESSAGE_ID, references: refs });
  reset();
  const result = await verifyReceipt({
    signal,
    as4MessageId: MESSAGE_ID,
    receiverCertificatePem: pki.receiver.certPem,
    signedReferences,
    validateCertificate: testValidator(pki, { revocation }),
    now: () => new Date(),
  });
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.ok(canonicalizeCalls > 0);
});

test('transmitAs4 rejects an invalid override before any HTTP', async () => {
  const result = await transmitAs4({
    message: {} as never,
    validateCertificate: testValidator(pki),
    http: { connectMs: 10, totalMs: 10 },
    responseLimits: { maxXmlBytes: Number.NaN },
    now: () => new Date(),
  });
  assert.equal(result.outcome, 'not-sent');
  if (result.outcome === 'not-sent') assert.equal(result.reason, 'limits.invalid');
});

test('sendAs4 rejects an invalid override before creating any spool', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'as4-limits-'));
  try {
    const result = await sendAs4Internal(
      {
        payload: Readable.from([Buffer.from('<a/>')]),
        endpointUrl: 'https://ap.example/as4',
        transportProfile: 'peppol-transport-as4-v2_0',
        receiverCertificate: pki.receiver.certPem,
        senderParticipant: { scheme: 'iso6523-actorid-upis', value: '0192:111111111' },
        receiverParticipant: { scheme: 'iso6523-actorid-upis', value: '0192:222222222' },
        documentType: { scheme: 'busdox-docid-qns', value: 'urn:test' },
        process: { scheme: 'cenbii-procid-ubl', value: 'urn:test' },
        as4MessageId: 'm@x',
        signer: signerFromKey(pki.sender.keyObject, pki.sender.certPem),
        validateCertificate: testValidator(pki),
        http: { connectMs: 10, totalMs: 10 },
        spoolDirectory: dir,
        responseLimits: { maxCanonicalBytes: 1.5 },
        now: () => new Date(),
      },
      defaultEntropy(),
    );
    assert.equal(result.outcome, 'not-sent');
    if (result.outcome === 'not-sent') assert.equal(result.reason, 'limits.invalid');
    assert.deepEqual(readdirSync(dir), [], 'no spool work happened');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
