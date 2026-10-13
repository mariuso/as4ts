import test from 'node:test';
import assert from 'node:assert/strict';
import { constants, privateDecrypt } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { DS_NS, EBMS_NS, PEPPOL_PARTY_ID_TYPE, SOAP_ENV_NS, WSU_NS, XENC_NS } from '../src/constants.js';
import { signerFromKey } from '../src/index.js';
import { defaultEntropy, prepareAs4Internal } from '../src/internal.js';
import { buildMultipartBody } from '../src/multipart.js';
import { openAs4Message } from '../src/receive/open.js';
import { respondAs4Message } from '../src/receive/respond.js';
import { defaultInboundLimits } from '../src/receive/types.js';
import type { InboundKeyHolder, OpenAs4MessageInput } from '../src/receive/types.js';
import { verifyReceipt } from '../src/receipt/verify.js';
import { canonicalizeDigest } from '../src/xml/c14n.js';
import { elementsByLocalName, firstByLocalName, parseXml, serializeXml } from '../src/xml/nodes.js';
import { signSignedInfo } from '../src/xml/security.js';
import { parseSignal } from '../src/xml/signal.js';
import { createTestPki } from './helpers/pki.js';
import { testValidator } from './helpers/input.js';

/**
 * Protocol negatives and a peer-style interoperability exchange for the
 * receiving path (Phase 6). Each negative asserts the failure facts and whether
 * a signed ebMS error is answerable; the interoperability case runs a real
 * sender -> receiver -> receipt exchange and verifies the receipt with the
 * sender's own verifier.
 */
const pki = createTestPki();
const SENDER = { scheme: 'iso6523-actorid-upis', value: '0192:111111111' };
const RECEIVER = { scheme: 'iso6523-actorid-upis', value: '0192:222222222' };
const DOC_TYPE = {
  scheme: 'busdox-docid-qns',
  value: 'urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice##urn:cen.eu:en16931:2017::2.1',
};
const PROCESS = { scheme: 'cenbii-procid-ubl', value: 'urn:fdc:peppol.eu:2017:poacc:billing:01:1.0' };
const AS4_MESSAGE_ID = 'protocol@as4-sender';
const SBDH = Buffer.from(
  '<?xml version="1.0" encoding="UTF-8"?>' +
    '<StandardBusinessDocument xmlns="http://www.unece.org/cefact/namespaces/StandardBusinessDocumentHeader">' +
    '<StandardBusinessDocumentHeader><HeaderVersion>1.0</HeaderVersion></StandardBusinessDocumentHeader>' +
    '</StandardBusinessDocument>',
  'utf8',
);

const holder: InboundKeyHolder = {
  certificate: pki.receiver.certPem,
  async unwrap(wrapped) {
    return privateDecrypt(
      { key: pki.receiver.keyObject, oaepHash: 'sha256', padding: constants.RSA_PKCS1_OAEP_PADDING },
      Buffer.from(wrapped),
    );
  },
};

type SoapTransform = (xml: string) => string | Promise<string>;

function removeReferences(doc: Document, predicate: (uri: string) => boolean): void {
  const signedInfo = firstByLocalName(doc, DS_NS, 'SignedInfo');
  for (const reference of elementsByLocalName(signedInfo, DS_NS, 'Reference')) {
    const uri = reference.getAttribute('URI') ?? '';
    if (predicate(uri) && reference.parentNode) reference.parentNode.removeChild(reference);
  }
}

async function resign(xml: string, mutate: (doc: Document) => void): Promise<string> {
  const doc = parseXml(xml);
  mutate(doc);
  const signedInfo = firstByLocalName(doc, DS_NS, 'SignedInfo');
  const signatureValue = firstByLocalName(doc, DS_NS, 'SignatureValue');
  assert.ok(signedInfo && signatureValue, 'the fixture is signed');
  if (!signedInfo || !signatureValue) throw new Error('unreachable');
  const value = await signSignedInfo(signedInfo, signerFromKey(pki.sender.keyObject, pki.sender.certPem));
  while (signatureValue.firstChild) signatureValue.removeChild(signatureValue.firstChild);
  signatureValue.appendChild(doc.createTextNode(value));
  return serializeXml(doc);
}

/** Drop the SOAP Body reference and re-sign, so the Body is no longer covered. */
const dropBodyReference: SoapTransform = (xml) =>
  resign(xml, (doc) => {
    const body = elementsByLocalName(doc, SOAP_ENV_NS, 'Body')[0];
    const id = body?.getAttributeNS(WSU_NS, 'Id') ?? '';
    removeReferences(doc, (uri) => uri === `#${id}`);
  });

/** Drop the eb:Messaging reference and re-sign. */
const dropMessagingReference: SoapTransform = (xml) =>
  resign(xml, (doc) => {
    const messaging = firstByLocalName(doc, EBMS_NS, 'Messaging');
    const id = messaging?.getAttributeNS(WSU_NS, 'Id') ?? '';
    removeReferences(doc, (uri) => uri === `#${id}`);
  });

/** Drop the signed attachment (`cid:`) reference and re-sign. */
const dropAttachmentReference: SoapTransform = (xml) =>
  resign(xml, (doc) => removeReferences(doc, (uri) => uri.startsWith('cid:')));

/** Change the declared CompressionType and re-sign the Messaging reference. */
const changeCompression: SoapTransform = (xml) =>
  resign(xml, (doc) => {
    const signedInfo = firstByLocalName(doc, DS_NS, 'SignedInfo');
    const messaging = firstByLocalName(doc, EBMS_NS, 'Messaging');
    assert.ok(signedInfo && messaging, 'the fixture has Messaging and SignedInfo');
    if (!signedInfo || !messaging) throw new Error('unreachable');
    for (const property of elementsByLocalName(messaging, EBMS_NS, 'Property')) {
      if (property.getAttribute('name') !== 'CompressionType') continue;
      while (property.firstChild) property.removeChild(property.firstChild);
      property.appendChild(doc.createTextNode('application/zip'));
    }
    const messagingId = messaging.getAttributeNS(WSU_NS, 'Id');
    const digest = canonicalizeDigest(messaging);
    for (const reference of elementsByLocalName(signedInfo, DS_NS, 'Reference')) {
      if (reference.getAttribute('URI') !== `#${messagingId}`) continue;
      const digestValue = firstByLocalName(reference, DS_NS, 'DigestValue');
      if (!digestValue) continue;
      while (digestValue.firstChild) digestValue.removeChild(digestValue.firstChild);
      digestValue.appendChild(doc.createTextNode(digest));
    }
  });

/** Change the EncryptedData algorithm (it is outside the signature). */
const changeEncryptionAlgorithm: SoapTransform = (xml) => {
  const doc = parseXml(xml);
  const method = firstByLocalName(doc, XENC_NS, 'EncryptionMethod');
  assert.ok(method, 'the fixture is encrypted');
  method?.setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmlenc#aes256-cbc');
  return serializeXml(doc);
};

async function buildRequest(dir: string, transform?: SoapTransform): Promise<{ contentType: string; body: Buffer }> {
  const prepared = await prepareAs4Internal(
    {
      payload: Readable.from(SBDH),
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
    const soapXml = transform ? await transform(message.soapXml) : message.soapXml;
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

async function withRequest<T>(
  fn: (request: { contentType: string; body: Buffer }) => Promise<T>,
  transform?: SoapTransform,
): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), 'as4-protocol-'));
  try {
    return await fn(await buildRequest(dir, transform));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

async function collect(stream: NodeJS.ReadableStream): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(Buffer.from(chunk as Uint8Array));
  return Buffer.concat(chunks);
}

test('a real sender -> receiver -> receipt exchange verifies end to end', async () => {
  await withRequest(async (request) => {
    const opened = await openAs4Message(openInput(request));
    assert.equal(opened.ok, true, JSON.stringify(opened));
    if (!opened.ok) return;
    try {
      assert.deepEqual(await collect(opened.payload.read()), SBDH);
      const receipt = await respondAs4Message({
        kind: 'accepted',
        receipt: opened.receipt,
        decision: 'committed',
        signer: signerFromKey(pki.receiver.keyObject, pki.receiver.certPem),
        now: () => new Date(),
      });
      assert.equal(receipt.ok, true, JSON.stringify(receipt));
      if (!receipt.ok) return;
      const signal = parseSignal(Buffer.from(receipt.body));
      assert.ok(signal, 'the receipt parses');
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
      await opened.dispose();
    }
  });
});

test('a message that does not cover the SOAP Body is rejected', async () => {
  await withRequest(async (request) => {
    const result = await openAs4Message(openInput(request));
    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(result.stage, 'signature');
      assert.equal(result.reason, 'signature.coverage');
      // Coverage is checked before identity binding, so nothing is answerable yet.
      assert.equal(result.answerable, false);
    }
  }, dropBodyReference);
});

test('a message that does not cover eb:Messaging is rejected', async () => {
  await withRequest(async (request) => {
    const result = await openAs4Message(openInput(request));
    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(result.reason, 'signature.coverage');
      assert.equal(result.answerable, false);
    }
  }, dropMessagingReference);
});

test('a message whose attachment is not covered is rejected', async () => {
  await withRequest(async (request) => {
    const result = await openAs4Message(openInput(request));
    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(result.reason, 'signature.coverage');
      assert.equal(result.answerable, false);
    }
  }, dropAttachmentReference);
});

test('a message addressed to another AP is rejected without trusting a claimed sender', async () => {
  await withRequest(async (request) => {
    const result = await openAs4Message(
      openInput(request, { receiverIdentity: { scheme: PEPPOL_PARTY_ID_TYPE, value: 'POP999999' } }),
    );
    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(result.reason, 'addressing.party-mismatch');
      assert.equal(result.answerable, false);
    }
  });
});

test('a tampered ciphertext is rejected at decryption', async () => {
  await withRequest(async (request) => {
    const boundary = /boundary="?([^";]+)"?/.exec(request.contentType)?.[1];
    assert.ok(boundary, 'boundary');
    const marker = Buffer.from(`--${boundary}`, 'latin1');
    const body = Buffer.from(request.body);
    const second = body.indexOf(marker, body.indexOf(marker) + marker.length);
    body[second + 200] = body[second + 200]! ^ 0xff;
    const result = await openAs4Message(openInput({ contentType: request.contentType, body }));
    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(result.stage, 'decrypt');
      assert.match(result.reason, /^(decrypt|signature)\./);
    }
  });
});

test('an unsupported compression declaration is a P-Mode mismatch', async () => {
  await withRequest(async (request) => {
    const result = await openAs4Message(openInput(request));
    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(result.reason, 'addressing.pmode-mismatch');
      // Identity binding succeeded before the compression check, so this is answerable.
      assert.equal(result.answerable, true);
    }
  }, changeCompression);
});

test('an unsupported encryption algorithm is a decryption failure', async () => {
  await withRequest(async (request) => {
    const result = await openAs4Message(openInput(request));
    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(result.stage, 'decrypt');
      assert.match(result.reason, /^(decrypt|encryption)\./);
    }
  }, changeEncryptionAlgorithm);
});

test('size limits fail closed with size facts', async () => {
  await withRequest(async (request) => {
    const tooLarge = await openAs4Message(
      openInput(request, { limits: { ...defaultInboundLimits, maxRequestBytes: 64 } }),
    );
    assert.equal(tooLarge.ok, false);
    if (!tooLarge.ok) assert.equal(tooLarge.reason, 'body.too-large');

    const xmlTooLarge = await openAs4Message(
      openInput(request, { limits: { ...defaultInboundLimits, maxEnvelopeBytes: 16 } }),
    );
    assert.equal(xmlTooLarge.ok, false);
    if (!xmlTooLarge.ok) assert.equal(xmlTooLarge.reason, 'xml.too-large');

    const decompressTooLarge = await openAs4Message(
      openInput(request, { limits: { ...defaultInboundLimits, maxDecompressedBytes: 4 } }),
    );
    assert.equal(decompressTooLarge.ok, false);
    if (!decompressTooLarge.ok) assert.equal(decompressTooLarge.reason, 'payload.too-large');
  });
});
