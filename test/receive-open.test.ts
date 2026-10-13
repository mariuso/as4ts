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
import type { InboundKeyHolder, OpenAs4MessageInput } from '../src/receive/types.js';
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

const holder: InboundKeyHolder = {
  certificate: pki.receiver.certPem,
  async unwrap(wrapped) {
    return privateDecrypt(
      { key: pki.receiver.keyObject, oaepHash: 'sha256', padding: constants.RSA_PKCS1_OAEP_PADDING },
      Buffer.from(wrapped),
    );
  },
};

function documentWith(senderIdentifier: string): Buffer {
  return Buffer.from(
    '<?xml version="1.0" encoding="UTF-8"?>' +
      '<StandardBusinessDocument xmlns="http://www.unece.org/ebusiness/2010/MDA/StandardBusinessDocumentHeader">' +
      '<StandardBusinessDocumentHeader><HeaderVersion>1.0</HeaderVersion>' +
      `<Sender><Identifier Authority="iso6523-actorid-upis">${senderIdentifier}</Identifier></Sender>` +
      `<Receiver><Identifier Authority="iso6523-actorid-upis">${RECEIVER.value}</Identifier></Receiver>` +
      `<DocumentIdentification><Standard>urn:oasis</Standard><Type>${DOC_TYPE.value}</Type></DocumentIdentification>` +
      `<BusinessScope><Scope><Type>${PROCESS.value}</Type></Scope></BusinessScope>` +
      '</StandardBusinessDocumentHeader>' +
      '</StandardBusinessDocument>',
    'utf8',
  );
}

async function buildRequest(payload: Buffer, dir: string): Promise<{ contentType: string; body: Buffer }> {
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
      as4MessageId: 'inbound@as4-sender.test',
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
    return { contentType: multipart.contentType, body: Buffer.concat(chunks) };
  } finally {
    await message.dispose();
  }
}

function openInput(
  request: { contentType: string; body: Buffer },
  overrides: Partial<OpenAs4MessageInput> = {},
): OpenAs4MessageInput {
  return {
    contentType: request.contentType,
    body: (async function* () {
      yield request.body;
    })(),
    keyHolder: [holder],
    validateCertificate: testValidator(pki),
    receiverIdentity: { scheme: PEPPOL_PARTY_ID_TYPE, value: pki.receiver.commonName },
    now: () => new Date(),
    ...overrides,
  };
}

async function collect(stream: Readable): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks);
}

test('opens a valid UserMessage and returns verified facts and handles', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'as4-open-'));
  const document = documentWith(SENDER.value);
  try {
    const request = await buildRequest(document, dir);
    const result = await openAs4Message(openInput(request));
    assert.equal(result.ok, true, JSON.stringify(result));
    if (!result.ok) return;
    try {
      assert.equal(result.messageId, 'inbound@as4-sender.test');
      assert.equal(result.senderId, pki.sender.commonName);
      assert.equal(result.receiverId, pki.receiver.commonName);
      assert.equal(result.service.value, PROCESS.value);
      assert.equal(result.service.scheme, PROCESS.scheme);
      assert.equal(result.action, `${DOC_TYPE.scheme}::${DOC_TYPE.value}`);
      assert.equal(result.credentialCertificate, pki.receiver.certPem);
      assert.equal(result.receipt.signedReferences.length, 3);
      assert.equal(result.sbdhMismatches, undefined, 'a consistent SBDH reports no mismatch');
      assert.deepEqual(await collect(result.payload.read()), document);
    } finally {
      await result.dispose();
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('reports an SBDH/header inconsistency as a fact, not a failure', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'as4-open-'));
  try {
    const request = await buildRequest(documentWith('0192:999999999'), dir);
    const result = await openAs4Message(openInput(request));
    assert.equal(result.ok, true, JSON.stringify(result));
    if (!result.ok) return;
    try {
      assert.ok(result.sbdhMismatches?.some((m) => m.includes('originalSender')));
    } finally {
      await result.dispose();
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('rejects a message whose To party is not our identity', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'as4-open-'));
  try {
    const request = await buildRequest(documentWith(SENDER.value), dir);
    const result = await openAs4Message(
      openInput(request, { receiverIdentity: { scheme: PEPPOL_PARTY_ID_TYPE, value: 'POP999999' } }),
    );
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.reason, 'addressing.party-mismatch');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('rejects a body that is not multipart/related', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'as4-open-'));
  try {
    const request = await buildRequest(documentWith(SENDER.value), dir);
    const result = await openAs4Message(openInput({ ...request, contentType: 'application/soap+xml' }));
    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(result.reason, 'mime.content-type-invalid');
      assert.equal(result.stage, 'mime');
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
