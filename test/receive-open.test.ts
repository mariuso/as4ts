import test from 'node:test';
import assert from 'node:assert/strict';
import { constants, privateDecrypt } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { PEPPOL_PARTY_ID_TYPE, DS_NS, ALGO_SHA256, SWA_TRANSFORM_SIGNATURE } from '../src/constants.js';
import { signerFromKey } from '../src/index.js';
import { defaultEntropy, prepareAs4Internal } from '../src/internal.js';
import { buildMultipartBody } from '../src/multipart.js';
import { openAs4Message } from '../src/receive/open.js';
import { payloadHooks } from '../src/receive/payload-hooks.js';
import { signSignedInfo } from '../src/xml/security.js';
import { append, element, firstByLocalName, parseXml, serializeXml } from '../src/xml/nodes.js';
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

function sbdhDocument(senderIdentifier: string): Buffer {
  return Buffer.from(
    '<?xml version="1.0" encoding="UTF-8"?>' +
      '<StandardBusinessDocument xmlns="http://www.unece.org/ebusiness/2010/MDA/StandardBusinessDocumentHeader">' +
      '<StandardBusinessDocumentHeader><HeaderVersion>1.0</HeaderVersion>' +
      `<Sender><Identifier Authority="${SENDER.scheme}">${senderIdentifier}</Identifier></Sender>` +
      `<Receiver><Identifier Authority="${RECEIVER.scheme}">${RECEIVER.value}</Identifier></Receiver>` +
      `<DocumentIdentification><Standard>urn:oasis</Standard><Type>Invoice</Type></DocumentIdentification>` +
      '<BusinessScope>' +
      `<Scope><Type>PROCESSID</Type><InstanceIdentifier>${PROCESS.value}</InstanceIdentifier><Identifier>${PROCESS.scheme}</Identifier></Scope>` +
      `<Scope><Type>DOCUMENTID</Type><InstanceIdentifier>${DOC_TYPE.value}</InstanceIdentifier><Identifier>${DOC_TYPE.scheme}</Identifier></Scope>` +
      '</BusinessScope>' +
      '</StandardBusinessDocumentHeader>' +
      '</StandardBusinessDocument>',
  );
}

async function buildRequest(
  payload: Buffer,
  dir: string,
  transformSoap?: (xml: string) => string | Promise<string>,
): Promise<{ contentType: string; body: Buffer }> {
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
    const soapXml = transformSoap ? await transformSoap(message.soapXml) : message.soapXml;
    const multipart = buildMultipartBody({
      soapXml,
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

async function withRequest<T>(
  payload: Buffer,
  fn: (request: { contentType: string; body: Buffer }) => Promise<T>,
  transformSoap?: (xml: string) => string | Promise<string>,
): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), 'as4-open-'));
  try {
    return await fn(await buildRequest(payload, dir, transformSoap));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test('opens a valid UserMessage and returns verified facts and handles', async () => {
  const document = sbdhDocument(SENDER.value);
  await withRequest(document, async (request) => {
    const result = await openAs4Message(openInput(request));
    assert.equal(result.ok, true, JSON.stringify(result));
    if (!result.ok) return;
    try {
      assert.equal(result.messageId, 'inbound@as4-sender.test');
      assert.equal(result.senderId, pki.sender.commonName);
      assert.equal(result.receiverId, pki.receiver.commonName);
      assert.deepEqual(result.originalSender, SENDER);
      assert.deepEqual(result.finalRecipient, RECEIVER);
      assert.equal(result.service.value, PROCESS.value);
      assert.equal(result.action, `${DOC_TYPE.scheme}::${DOC_TYPE.value}`);
      assert.equal(result.credentialCertificate, pki.receiver.certPem);
      assert.equal(result.receipt.signedReferences.length, 3);
      assert.equal(result.sbdh.status, 'consistent');
      assert.deepEqual(await collect(result.payload.read()), document);
    } finally {
      await result.dispose();
    }
  });
});

test('reports an SBDH inconsistency as a distinct fact', async () => {
  await withRequest(sbdhDocument('0192:999999999'), async (request) => {
    const result = await openAs4Message(openInput(request));
    assert.equal(result.ok, true, JSON.stringify(result));
    if (!result.ok) return;
    try {
      assert.equal(result.sbdh.status, 'inconsistent');
      if (result.sbdh.status === 'inconsistent') {
        assert.ok(result.sbdh.mismatches.some((mismatch) => mismatch.includes('originalSender')));
      }
    } finally {
      await result.dispose();
    }
  });
});

test('reports a missing or malformed SBDH distinctly', async () => {
  await withRequest(Buffer.from('<notSbdh/>', 'utf8'), async (request) => {
    const result = await openAs4Message(openInput(request));
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.sbdh.status, 'missing');
      await result.dispose();
    }
  });
  await withRequest(Buffer.from('<a>', 'utf8'), async (request) => {
    const result = await openAs4Message(openInput(request));
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.sbdh.status, 'malformed');
      await result.dispose();
    }
  });
});

test('rejects a message whose To party is not our identity, without trusting a claimed sender', async () => {
  await withRequest(sbdhDocument(SENDER.value), async (request) => {
    const result = await openAs4Message(
      openInput(request, { receiverIdentity: { scheme: PEPPOL_PARTY_ID_TYPE, value: 'POP999999' } }),
    );
    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(result.reason, 'addressing.party-mismatch');
      assert.equal(result.answerable, false);
      assert.equal(result.correlation, undefined);
    }
  });
});

test('rejects a body that is not multipart/related', async () => {
  await withRequest(sbdhDocument(SENDER.value), async (request) => {
    const result = await openAs4Message(openInput({ ...request, contentType: 'application/soap+xml' }));
    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(result.reason, 'mime.content-type-invalid');
      assert.equal(result.stage, 'mime');
    }
  });
});

test('rejects an additional unsigned MIME attachment', async () => {
  await withRequest(sbdhDocument(SENDER.value), async (request) => {
    const boundary = /boundary="?([^";]+)"?/.exec(request.contentType)![1]!;
    const closing = Buffer.from(`--${boundary}--`, 'latin1');
    const index = request.body.indexOf(closing);
    const extra = Buffer.from(
      `--${boundary}\r\nContent-Type: application/octet-stream\r\nContent-ID: <extra@x>\r\n\r\nunsigned\r\n`,
      'latin1',
    );
    const body = Buffer.concat([request.body.subarray(0, index), extra, request.body.subarray(index)]);
    const result = await openAs4Message(openInput({ ...request, body }));
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.reason, 'mime.malformed');
  });
});

test('preserves a cancellation during the payload read', async () => {
  await withRequest(sbdhDocument(SENDER.value), async (request) => {
    const controller = new AbortController();
    payloadHooks.onReadPayload = () => controller.abort();
    try {
      const result = await openAs4Message(openInput(request, { signal: controller.signal }));
      assert.equal(result.ok, false);
      if (!result.ok) assert.equal(result.reason, 'aborted');
    } finally {
      payloadHooks.onReadPayload = undefined;
    }
  });
});

test('preserves an I/O failure during the payload read', async () => {
  await withRequest(sbdhDocument(SENDER.value), async (request) => {
    payloadHooks.onReadPayload = () => {
      throw Object.assign(new Error('io'), { code: 'EIO' });
    };
    try {
      const result = await openAs4Message(openInput(request));
      assert.equal(result.ok, false);
      if (!result.ok) assert.equal(result.reason, 'payload.spool-failed');
    } finally {
      payloadHooks.onReadPayload = undefined;
    }
  });
});

/** Rename the SOAP root to a non-envelope element (the signature is not re-checked). */
function renameRoot(xml: string): string {
  return xml.replace('<env:Envelope', '<env:NotEnvelope').replace('</env:Envelope>', '</env:NotEnvelope>');
}

test('rejects a document whose root is not a SOAP envelope', async () => {
  await withRequest(
    sbdhDocument(SENDER.value),
    async (request) => {
      const result = await openAs4Message(openInput(request));
      assert.equal(result.ok, false);
      if (!result.ok) {
        assert.equal(result.stage, 'xml');
        assert.equal(result.reason, 'xml.malformed');
      }
    },
    renameRoot,
  );
});

test('rejects a second, unsigned SOAP Body', async () => {
  await withRequest(
    sbdhDocument(SENDER.value),
    async (request) => {
      const result = await openAs4Message(openInput(request));
      assert.equal(result.ok, false);
      if (!result.ok) assert.equal(result.reason, 'xml.malformed');
    },
    (xml) => xml.replace('</env:Envelope>', '<env:Body/></env:Envelope>'),
  );
});

test('rejects wsse:Security placed outside the SOAP Header', async () => {
  await withRequest(
    sbdhDocument(SENDER.value),
    async (request) => {
      const result = await openAs4Message(openInput(request));
      assert.equal(result.ok, false);
      if (!result.ok) assert.equal(result.reason, 'xml.malformed');
    },
    (xml) => {
      const match = /<wsse:Security[\s\S]*?<\/wsse:Security>/.exec(xml);
      assert.ok(match, 'the fixture has a wsse:Security element');
      return xml.replace(match[0], '').replace('</env:Envelope>', `${match[0]}</env:Envelope>`);
    },
  );
});

test('rejects an additional signed cid: reference with no attachment', async () => {
  await withRequest(
    sbdhDocument(SENDER.value),
    async (request) => {
      const result = await openAs4Message(openInput(request));
      assert.equal(result.ok, false);
      if (!result.ok) {
        assert.equal(result.stage, 'signature');
        assert.equal(result.reason, 'signature.coverage');
      }
    },
    async (xml) => {
      const doc = parseXml(xml);
      const signedInfo = firstByLocalName(doc, DS_NS, 'SignedInfo');
      assert.ok(signedInfo, 'the fixture has ds:SignedInfo');
      const reference = element(doc, 'ds', 'Reference', { URI: 'cid:missing@as4-sender.test' });
      const transforms = element(doc, 'ds', 'Transforms');
      append(transforms, element(doc, 'ds', 'Transform', { Algorithm: SWA_TRANSFORM_SIGNATURE }));
      append(reference, transforms);
      append(reference, element(doc, 'ds', 'DigestMethod', { Algorithm: ALGO_SHA256 }));
      append(reference, element(doc, 'ds', 'DigestValue', {}, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='));
      append(signedInfo, reference);
      const value = await signSignedInfo(signedInfo, signerFromKey(pki.sender.keyObject, pki.sender.certPem));
      const signatureValue = firstByLocalName(doc, DS_NS, 'SignatureValue');
      assert.ok(signatureValue, 'the fixture has ds:SignatureValue');
      while (signatureValue.firstChild) signatureValue.removeChild(signatureValue.firstChild);
      signatureValue.appendChild(doc.createTextNode(value));
      return serializeXml(doc);
    },
  );
});
