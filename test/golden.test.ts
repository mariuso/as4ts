import test from 'node:test';
import assert from 'node:assert/strict';
import { createPrivateKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { signerFromKey } from '../src/index.js';
import { buildEnvelope } from '../src/xml/envelope.js';
import { buildMultipartBody } from '../src/multipart.js';
import { peppolProfile } from '../src/profile.js';
import { AS4_COMPRESSION_TYPE } from '../src/constants.js';
import { fixedEntropy } from './helpers/entropy.js';

const here = dirname(fileURLToPath(import.meta.url));
const golden = (name: string): Buffer => readFileSync(join(here, 'golden', name));
const goldenText = (name: string): string => golden(name).toString('utf8');

const senderCertPem = goldenText('sender-cert.pem');
const receiverCertPem = goldenText('receiver-cert.pem');
const signer = signerFromKey(createPrivateKey(goldenText('sender-key.pem')), senderCertPem);
const wrappedKey = golden('wrapped-key.bin');

const USER_MESSAGE = {
  messageId: 'golden-message@as4-sender.test',
  timestamp: '2026-10-12T09:07:36.000Z',
  fromPartyId: 'POP000001',
  toPartyId: 'POP000002',
  profile: peppolProfile,
  service: { scheme: 'cenbii-procid-ubl', value: 'urn:www.cenbii.eu:profile:bii05:ver2.0' },
  action: 'busdox-docid-qns::urn:example:invoice::2.1',
  originalSender: { scheme: 'iso6523-actorid-upis', value: '0192:111111111' },
  finalRecipient: { scheme: 'iso6523-actorid-upis', value: '0192:222222222' },
  payloadHref: 'cid:11111111-2222-4333-8444-555555555555@golden.example',
  compressionType: AS4_COMPRESSION_TYPE,
} as const;

test('golden: fixed inputs produce a byte-identical SOAP envelope', async () => {
  const built = await buildEnvelope({
    userMessage: USER_MESSAGE,
    signer,
    receiverCertificatePem: receiverCertPem,
    wrappedKey,
    attachmentDigestBase64: 'GOLDENATTACHMENTDIGEST=',
    entropy: fixedEntropy(),
  });
  assert.equal(built.xml, goldenText('envelope.xml'));
});

test('golden: fixed inputs produce a byte-identical multipart body', async () => {
  const built = await buildEnvelope({
    userMessage: USER_MESSAGE,
    signer,
    receiverCertificatePem: receiverCertPem,
    wrappedKey,
    attachmentDigestBase64: 'GOLDENATTACHMENTDIGEST=',
    entropy: fixedEntropy(),
  });
  const multipart = buildMultipartBody({
    soapXml: built.xml,
    attachmentHref: USER_MESSAGE.payloadHref,
    attachmentFilePath: join(here, 'golden', 'attachment.bin'),
    attachmentByteLength: golden('attachment.bin').length,
    entropy: fixedEntropy(),
  });
  assert.equal(multipart.contentType, goldenText('multipart.content-type.txt'));
  const chunks: Buffer[] = [];
  for await (const chunk of multipart.stream) chunks.push(chunk as Buffer);
  assert.deepEqual(Buffer.concat(chunks), golden('multipart.bin'));
});
