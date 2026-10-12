import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { Readable } from 'node:stream';
import { wrapSessionKey } from '../src/crypto/session-key.js';
import { preparePayload } from '../src/crypto/payload.js';
import { buildEnvelope } from '../src/xml/envelope.js';
import { signerFromKey, peppolProfile } from '../src/index.js';
import { sendAs4Internal } from '../src/internal.js';
import { AS4_COMPRESSION_TYPE } from '../src/constants.js';
import { serializeXml } from '../src/xml/nodes.js';
import { createTestPki, createTlsServerCert } from './helpers/pki.js';
import { startFakeReceiver } from './helpers/fake-receiver.js';
import { baseInput } from './helpers/input.js';
import { fixedEntropy } from './helpers/entropy.js';

const pki = createTestPki();

test('wrapSessionKey draws the session key from the injected entropy', () => {
  const { sessionKey } = wrapSessionKey(pki.receiver.cert.publicKey, fixedEntropy());
  const expected = Buffer.alloc(16);
  for (let i = 0; i < 16; i += 1) expected[i] = i & 0xff;
  assert.deepEqual(sessionKey, expected);
});

test('preparePayload draws the GCM IV from the injected entropy', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'as4-entropy-'));
  try {
    const file = join(dir, 'payload.enc');
    const { sessionKey, wrappedKey } = wrapSessionKey(pki.receiver.cert.publicKey, fixedEntropy());
    await preparePayload({
      source: Readable.from(Buffer.from('<doc/>')),
      sessionKey,
      wrappedKey,
      filePath: file,
      entropy: fixedEntropy(),
    });
    const written = await readFile(file);
    const expectedIv = Buffer.alloc(12);
    for (let i = 0; i < 12; i += 1) expectedIv[i] = i & 0xff;
    assert.deepEqual(written.subarray(0, 12), expectedIv);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('the same entropy produces a byte-identical envelope', async () => {
  const { wrappedKey } = wrapSessionKey(pki.receiver.cert.publicKey, fixedEntropy());
  const signer = signerFromKey(pki.sender.keyObject, pki.sender.certPem);
  const params = {
    userMessage: {
      messageId: 'entropy@test',
      timestamp: '2026-10-12T09:07:36.000Z',
      fromPartyId: pki.sender.commonName,
      toPartyId: pki.receiver.commonName,
      profile: peppolProfile,
      service: { scheme: 's', value: 'v' },
      action: 'a::b',
      originalSender: { scheme: 'iso6523-actorid-upis', value: '0192:1' },
      finalRecipient: { scheme: 'iso6523-actorid-upis', value: '0192:2' },
      payloadHref: 'cid:entropy@test',
      compressionType: AS4_COMPRESSION_TYPE,
    },
    signer,
    receiverCertificatePem: pki.receiver.certPem,
    wrappedKey,
    attachmentDigestBase64: 'DIGEST=',
  } as const;
  const first = await buildEnvelope({ ...params, entropy: fixedEntropy() });
  const second = await buildEnvelope({ ...params, entropy: fixedEntropy() });
  assert.equal(first.xml, second.xml);
});

test('the injected uuid reaches the attachment Content-ID end to end', async () => {
  const tls = createTlsServerCert();
  const receiver = await startFakeReceiver({ receiver: pki.receiver, tlsCertPem: tls.certPem, tlsKeyPem: tls.keyPem });
  try {
    const result = await sendAs4Internal(baseInput(pki, receiver.url, tls.caPem), fixedEntropy());
    assert.equal(result.outcome, 'receipt-verified');
    const raw = serializeXml(receiver.received[0]!.envelope);
    assert.ok(raw.includes('cid:11111111-2222-4333-8444-555555555555@'), 'attachment href carries the injected uuid');
  } finally {
    await receiver.close();
  }
});
