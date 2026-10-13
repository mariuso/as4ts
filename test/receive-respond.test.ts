import test from 'node:test';
import assert from 'node:assert/strict';
import { constants, privateDecrypt } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { PEPPOL_PARTY_ID_TYPE } from '../src/constants.js';
import { signerFromKey } from '../src/index.js';
import { defaultEntropy, prepareAs4Internal } from '../src/internal.js';
import { buildMultipartBody } from '../src/multipart.js';
import { openAs4Message } from '../src/receive/open.js';
import { respondAs4Message } from '../src/receive/respond.js';
import { verifyReceipt } from '../src/receipt/verify.js';
import type { InboundKeyHolder, OpenAs4MessageInput, OpenSuccess, ReceiptContext } from '../src/receive/types.js';
import { parseSignal } from '../src/xml/signal.js';
import { createTestPki } from './helpers/pki.js';
import { testValidator } from './helpers/input.js';

const pki = createTestPki();
const SENDER = { scheme: 'iso6523-actorid-upis', value: '0192:111111111' };
const RECEIVER = { scheme: 'iso6523-actorid-upis', value: '0192:222222222' };
const DOC_TYPE = {
  scheme: 'busdox-docid-qns',
  value: 'urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice##urn:cen.eu:en16931:2017::2.1',
};
const PROCESS = { scheme: 'cenbii-procid-ubl', value: 'urn:fdc:peppol.eu:2017:poacc:billing:01:1.0' };
const AS4_MESSAGE_ID = 'inbound@as4-sender.test';

const holder: InboundKeyHolder = {
  certificate: pki.receiver.certPem,
  async unwrap(wrapped) {
    return privateDecrypt(
      { key: pki.receiver.keyObject, oaepHash: 'sha256', padding: constants.RSA_PKCS1_OAEP_PADDING },
      Buffer.from(wrapped),
    );
  },
};

async function openInbound(): Promise<{ opened: OpenSuccess; cleanup: () => Promise<void> }> {
  const dir = await mkdtemp(join(tmpdir(), 'as4-respond-'));
  const payload = Buffer.from(
    `<StandardBusinessDocument xmlns="http://www.unece.org/ebusiness/2010/MDA/StandardBusinessDocumentHeader">` +
      '<StandardBusinessDocumentHeader><HeaderVersion>1.0</HeaderVersion></StandardBusinessDocumentHeader>' +
      '</StandardBusinessDocument>',
    'utf8',
  );
  const prepared = await prepareAs4Internal(
    {
      payload: Readable.from(payload),
      endpointUrl: 'https://ap.example/as4',
      transportProfile: 'peppol-transport-as4-v2_0',
      receiverCertificate: pki.receiver.certPem,
      senderParticipant: SENDER,
      receiverParticipant: RECEIVER,
      documentType: DOC_TYPE,
      process: PROCESS,
      as4MessageId: AS4_MESSAGE_ID,
      signer: signerFromKey(pki.sender.keyObject, pki.sender.certPem),
      validateCertificate: testValidator(pki),
      artifactDirectory: dir,
      now: () => new Date(),
    },
    defaultEntropy(),
  );
  assert.equal(prepared.outcome, 'prepared', JSON.stringify(prepared));
  if (prepared.outcome !== 'prepared') throw new Error('unreachable');
  const message = prepared.message;
  try {
    const multipart = buildMultipartBody({
      soapXml: message.soapXml,
      attachmentHref: message.attachmentHref,
      attachmentFilePath: join(message.directory, 'attachment.bin'),
      attachmentByteLength: message.attachmentByteLength,
      boundary: message.boundary,
      soapContentId: message.soapContentId,
    });
    const chunks: Buffer[] = [];
    for await (const chunk of multipart.stream) chunks.push(chunk as Buffer);
    const input: OpenAs4MessageInput = {
      contentType: multipart.contentType,
      body: (async function* () {
        yield Buffer.concat(chunks);
      })(),
      keyHolder: [holder],
      validateCertificate: testValidator(pki),
      receiverIdentity: { scheme: PEPPOL_PARTY_ID_TYPE, value: pki.receiver.commonName },
      now: () => new Date(),
    };
    const result = await openAs4Message(input);
    assert.equal(result.ok, true, JSON.stringify(result));
    if (!result.ok) throw new Error('unreachable');
    return {
      opened: result,
      cleanup: async () => {
        await result.dispose();
        await rm(dir, { recursive: true, force: true });
      },
    };
  } catch (err) {
    await message.dispose();
    await rm(dir, { recursive: true, force: true });
    throw err;
  }
}

test('builds a signed receipt that the sender verifies', async () => {
  const { opened, cleanup } = await openInbound();
  try {
    const result = await respondAs4Message({
      kind: 'accepted',
      receipt: opened.receipt,
      decision: 'committed',
      signer: signerFromKey(pki.receiver.keyObject, pki.receiver.certPem),
      now: () => new Date(),
    });
    assert.equal(result.ok, true, JSON.stringify(result));
    if (!result.ok) return;
    assert.equal(result.status, 200);
    assert.match(result.contentType, /application\/soap\+xml/);

    const signal = parseSignal(Buffer.from(result.body));
    assert.ok(signal, 'the response parses as a signal');
    assert.equal(signal.kind, 'receipt');
    assert.equal(signal.refToMessageId, AS4_MESSAGE_ID);

    const check = await verifyReceipt({
      signal: signal!,
      as4MessageId: AS4_MESSAGE_ID,
      receiverCertificatePem: pki.receiver.certPem,
      signedReferences: opened.receipt.signedReferences,
      validateCertificate: testValidator(pki),
      now: () => new Date(),
    });
    assert.equal(check.ok, true, JSON.stringify(check));
  } finally {
    await cleanup();
  }
});

test('builds a signed error signal correlated to the failed message', async () => {
  const result = await respondAs4Message({
    kind: 'rejected',
    correlation: { messageId: AS4_MESSAGE_ID, senderId: 'x', receiverId: 'y' },
    error: { code: 'EB:09', severity: 'failure', shortDescription: 'Not serviced', detail: 'PEPPOL:NOT_SERVICED' },
    signer: signerFromKey(pki.receiver.keyObject, pki.receiver.certPem),
    now: () => new Date(),
  });
  assert.equal(result.ok, true, JSON.stringify(result));
  if (!result.ok) return;
  const signal = parseSignal(Buffer.from(result.body));
  assert.ok(signal, 'the response parses as a signal');
  assert.equal(signal.kind, 'error');
  assert.equal(signal.refToMessageId, AS4_MESSAGE_ID);
  assert.equal(signal.errors[0]?.code, 'EB:09');
  assert.equal(signal.errors[0]?.severity, 'failure');
});

test('a rejected response needs no receipt facts', async () => {
  const result = await respondAs4Message({
    kind: 'rejected',
    correlation: { messageId: 'unknown@peer' },
    error: { code: 'EB:12', severity: 'failure' },
    signer: signerFromKey(pki.receiver.keyObject, pki.receiver.certPem),
    now: () => new Date(),
  });
  assert.equal(result.ok, true, JSON.stringify(result));
});

test('a serialised receipt context is enough to rebuild the response', async () => {
  const { opened, cleanup } = await openInbound();
  try {
    const serialised = JSON.parse(JSON.stringify(opened.receipt)) as ReceiptContext;
    const result = await respondAs4Message({
      kind: 'accepted',
      receipt: serialised,
      decision: 'already-committed',
      signer: signerFromKey(pki.receiver.keyObject, pki.receiver.certPem),
      now: () => new Date(),
    });
    assert.equal(result.ok, true, JSON.stringify(result));
    if (!result.ok) return;
    const signal = parseSignal(Buffer.from(result.body));
    assert.ok(signal);
    const check = await verifyReceipt({
      signal: signal!,
      as4MessageId: AS4_MESSAGE_ID,
      receiverCertificatePem: pki.receiver.certPem,
      signedReferences: opened.receipt.signedReferences,
      validateCertificate: testValidator(pki),
      now: () => new Date(),
    });
    assert.equal(check.ok, true, JSON.stringify(check));
  } finally {
    await cleanup();
  }
});

test('a cancelled response is a value, not a throw', async () => {
  const { opened, cleanup } = await openInbound();
  try {
    const controller = new AbortController();
    controller.abort();
    const result = await respondAs4Message({
      kind: 'accepted',
      receipt: opened.receipt,
      decision: 'committed',
      signer: signerFromKey(pki.receiver.keyObject, pki.receiver.certPem),
      now: () => new Date(),
      signal: controller.signal,
    });
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.reason, 'aborted');
  } finally {
    await cleanup();
  }
});
