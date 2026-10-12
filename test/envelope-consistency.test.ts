import test from 'node:test';
import assert from 'node:assert/strict';
import { verify as cryptoVerify, constants as cryptoConstants } from 'node:crypto';
import {
  ALGO_AES128_GCM,
  ALGO_EXC_C14N,
  ALGO_MGF1_SHA256,
  ALGO_RSA_OAEP,
  ALGO_RSA_SHA256,
  ALGO_SHA256,
  AS4_COMPRESSION_TYPE,
  DS_NS,
  EBMS_NS,
  EBMS_ROLE_INITIATOR,
  EBMS_ROLE_RESPONDER,
  PEPPOL_AGREEMENT_REF,
  PEPPOL_PARTY_ID_TYPE,
  SWA_ATTACHMENT_CONTENT_ONLY,
  SWA_TRANSFORM_CIPHERTEXT,
  SWA_TRANSFORM_SIGNATURE,
  WSSE_NS,
  WSS_X509_V3,
  WSU_NS,
  XENC11_NS,
  XENC_NS,
} from '../src/constants.js';
import { wrapSessionKey } from '../src/crypto/session-key.js';
import { buildEnvelope } from '../src/xml/envelope.js';
import { canonicalize } from '../src/xml/c14n.js';
import { attrOf, elementsByLocalName, firstByLocalName, parseXml, textOf } from '../src/xml/nodes.js';
import { signerFromKey, peppolProfile } from '../src/index.js';
import { createTestPki } from './helpers/pki.js';

const pki = createTestPki();
const ATTACHMENT_HREF = 'cid:att-123@example.test';

async function build() {
  const { wrappedKey } = wrapSessionKey(pki.receiver.cert.publicKey);
  const built = await buildEnvelope({
    userMessage: {
      messageId: 'msg-1@example.test',
      timestamp: '2026-10-12T09:07:36.000Z',
      fromPartyId: pki.sender.commonName,
      toPartyId: pki.receiver.commonName,
      profile: peppolProfile,
      service: { scheme: 'cenbii-procid-ubl', value: 'urn:www.cenbii.eu:profile:bii05:ver2.0' },
      action: 'busdox-docid-qns::urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice##x::2.1',
      originalSender: { scheme: 'iso6523-actorid-upis', value: '0192:111111111' },
      finalRecipient: { scheme: 'iso6523-actorid-upis', value: '0192:222222222' },
      payloadHref: ATTACHMENT_HREF,
      compressionType: AS4_COMPRESSION_TYPE,
    },
    signer: signerFromKey(pki.sender.keyObject, pki.sender.certPem),
    receiverCertificatePem: pki.receiver.certPem,
    wrappedKey,
    attachmentDigestBase64: 'ATTACHMENTDIGEST=',
  });
  return { built, doc: parseXml(built.xml) };
}

function resolveId(doc: Document, id: string): Element | null {
  const all = doc.getElementsByTagName('*');
  const found: Element[] = [];
  for (let i = 0; i < all.length; i += 1) {
    const el = all.item(i);
    if (!el) continue;
    if (el.getAttributeNS(WSU_NS, 'Id') === id || el.getAttribute('Id') === id || el.getAttribute('id') === id)
      found.push(el);
  }
  return found.length === 1 ? found[0]! : null;
}

test('generated envelope is internally consistent', async () => {
  const { built, doc } = await build();

  // One of everything.
  assert.equal(elementsByLocalName(doc, EBMS_NS, 'Messaging').length, 1);
  assert.equal(elementsByLocalName(doc, EBMS_NS, 'UserMessage').length, 1);
  assert.equal(elementsByLocalName(doc, EBMS_NS, 'PayloadInfo').length, 1);
  assert.equal(elementsByLocalName(doc, EBMS_NS, 'PartInfo').length, 1);
  const signatures = elementsByLocalName(doc, DS_NS, 'Signature');
  assert.equal(signatures.length, 1);

  // User message metadata.
  const userMessage = firstByLocalName(doc, EBMS_NS, 'UserMessage')!;
  assert.equal(textOf(firstByLocalName(userMessage, EBMS_NS, 'MessageId')), 'msg-1@example.test');
  assert.equal(textOf(firstByLocalName(userMessage, EBMS_NS, 'ConversationId')), 'msg-1@example.test');
  const from = firstByLocalName(userMessage, EBMS_NS, 'From')!;
  const to = firstByLocalName(userMessage, EBMS_NS, 'To')!;
  assert.equal(attrOf(firstByLocalName(from, EBMS_NS, 'PartyId'), 'type'), PEPPOL_PARTY_ID_TYPE);
  assert.equal(textOf(firstByLocalName(from, EBMS_NS, 'PartyId')), pki.sender.commonName);
  assert.equal(textOf(firstByLocalName(from, EBMS_NS, 'Role')), EBMS_ROLE_INITIATOR);
  assert.equal(textOf(firstByLocalName(to, EBMS_NS, 'PartyId')), pki.receiver.commonName);
  assert.equal(textOf(firstByLocalName(to, EBMS_NS, 'Role')), EBMS_ROLE_RESPONDER);
  assert.equal(textOf(firstByLocalName(userMessage, EBMS_NS, 'AgreementRef')), PEPPOL_AGREEMENT_REF);
  const service = firstByLocalName(userMessage, EBMS_NS, 'Service')!;
  assert.equal(attrOf(service, 'type'), 'cenbii-procid-ubl');
  assert.equal(textOf(service), 'urn:www.cenbii.eu:profile:bii05:ver2.0');
  assert.ok(textOf(firstByLocalName(userMessage, EBMS_NS, 'Action'))!.startsWith('busdox-docid-qns::'));
  const props = elementsByLocalName(userMessage, EBMS_NS, 'Property');
  assert.equal(
    attrOf(
      props.find((p) => attrOf(p, 'name') === 'originalSender')!,
      'type',
    ),
    'iso6523-actorid-upis',
  );
  assert.equal(textOf(props.find((p) => attrOf(p, 'name') === 'finalRecipient')!), '0192:222222222');

  // Payload description.
  const partInfo = firstByLocalName(userMessage, EBMS_NS, 'PartInfo')!;
  assert.equal(attrOf(partInfo, 'href'), ATTACHMENT_HREF);
  const partProps = elementsByLocalName(partInfo, EBMS_NS, 'Property');
  assert.equal(textOf(partProps.find((p) => attrOf(p, 'name') === 'CompressionType')!), AS4_COMPRESSION_TYPE);
  assert.ok(partProps.some((p) => attrOf(p, 'name') === 'MimeType'));

  // Security header structure and cross-references.
  const security = firstByLocalName(doc, WSSE_NS, 'Security')!;
  assert.equal(elementsByLocalName(security, WSSE_NS, 'BinarySecurityToken').length, 2);
  const encryptedKey = firstByLocalName(security, XENC_NS, 'EncryptedKey')!;
  assert.equal(attrOf(encryptedKey, 'Id'), built.encryptedKeyId);
  const keyMethod = firstByLocalName(encryptedKey, XENC_NS, 'EncryptionMethod')!;
  assert.equal(attrOf(keyMethod, 'Algorithm'), ALGO_RSA_OAEP);
  assert.equal(attrOf(firstByLocalName(keyMethod, DS_NS, 'DigestMethod'), 'Algorithm'), ALGO_SHA256);
  assert.equal(attrOf(firstByLocalName(keyMethod, XENC11_NS, 'MGF'), 'Algorithm'), ALGO_MGF1_SHA256);
  assert.equal(attrOf(firstByLocalName(encryptedKey, XENC_NS, 'DataReference'), 'URI'), `#${built.encryptedDataId}`);

  const encryptedData = firstByLocalName(security, XENC_NS, 'EncryptedData')!;
  assert.equal(attrOf(encryptedData, 'Id'), built.encryptedDataId);
  assert.equal(attrOf(encryptedData, 'MimeType'), AS4_COMPRESSION_TYPE);
  assert.equal(attrOf(encryptedData, 'Type'), SWA_ATTACHMENT_CONTENT_ONLY);
  assert.equal(attrOf(firstByLocalName(encryptedData, XENC_NS, 'EncryptionMethod'), 'Algorithm'), ALGO_AES128_GCM);
  assert.equal(attrOf(firstByLocalName(encryptedData, XENC_NS, 'CipherReference'), 'URI'), ATTACHMENT_HREF);
  assert.equal(attrOf(firstByLocalName(encryptedData, DS_NS, 'Transform'), 'Algorithm'), SWA_TRANSFORM_CIPHERTEXT);
  // EncryptedData key info points at the EncryptedKey.
  const dataRef = firstByLocalName(encryptedData, WSSE_NS, 'Reference')!;
  assert.equal(attrOf(dataRef, 'URI'), `#${built.encryptedKeyId}`);

  // The two BinarySecurityTokens are the receiver (encryption) and sender (signing) certs.
  const bsts = elementsByLocalName(security, WSSE_NS, 'BinarySecurityToken');
  const encBst = resolveId(
    doc,
    attrOf(firstByLocalName(firstByLocalName(encryptedKey, DS_NS, 'KeyInfo')!, WSSE_NS, 'Reference')!, 'URI')!.slice(1),
  );
  const signBst = resolveId(
    doc,
    attrOf(firstByLocalName(firstByLocalName(signatures[0]!, DS_NS, 'KeyInfo')!, WSSE_NS, 'Reference')!, 'URI')!.slice(
      1,
    ),
  );
  assert.ok(encBst && signBst && bsts.includes(encBst) && bsts.includes(signBst));
  assert.equal(attrOf(signBst, 'ValueType'), WSS_X509_V3);
  assert.deepEqual(Buffer.from(textOf(signBst)!.replace(/\s+/g, ''), 'base64'), Buffer.from(pki.sender.cert.raw));
  assert.deepEqual(Buffer.from(textOf(encBst)!.replace(/\s+/g, ''), 'base64'), Buffer.from(pki.receiver.cert.raw));

  // Signature: method, references, digests, transforms, binding, and self-check.
  const signedInfo = firstByLocalName(signatures[0]!, DS_NS, 'SignedInfo')!;
  assert.equal(attrOf(firstByLocalName(signedInfo, DS_NS, 'CanonicalizationMethod'), 'Algorithm'), ALGO_EXC_C14N);
  assert.equal(attrOf(firstByLocalName(signedInfo, DS_NS, 'SignatureMethod'), 'Algorithm'), ALGO_RSA_SHA256);
  const refs = elementsByLocalName(signedInfo, DS_NS, 'Reference');
  assert.deepEqual(
    refs.map((r) => attrOf(r, 'URI')),
    [`#${built.bodyId}`, `#${built.messagingId}`, ATTACHMENT_HREF],
  );
  assert.deepEqual(
    refs.map((r) => textOf(firstByLocalName(r, DS_NS, 'DigestValue'))),
    [built.bodyDigest, built.messagingDigest, 'ATTACHMENTDIGEST='],
  );
  assert.equal(attrOf(firstByLocalName(refs[2]!, DS_NS, 'Transform'), 'Algorithm'), SWA_TRANSFORM_SIGNATURE);
  // References resolve uniquely to the signed elements.
  const bodyEl = resolveId(doc, built.bodyId);
  const messagingEl = resolveId(doc, built.messagingId);
  assert.ok(bodyEl && bodyEl.localName === 'Body');
  assert.ok(messagingEl && messagingEl.localName === 'Messaging');
  // Signature value verifies over the canonical SignedInfo.
  const sigValue = Buffer.from(textOf(firstByLocalName(signatures[0]!, DS_NS, 'SignatureValue'))!.trim(), 'base64');
  assert.ok(
    cryptoVerify(
      'sha256',
      Buffer.from(canonicalize(signedInfo), 'utf8'),
      { key: pki.sender.cert.publicKey, padding: cryptoConstants.RSA_PKCS1_PADDING },
      sigValue,
    ),
  );
});
