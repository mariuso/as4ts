import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ALGO_AES128_GCM,
  ALGO_MGF1_SHA256,
  ALGO_SHA256,
  DS_NS,
  WSSE_NS,
  XENC_NS,
  XENC11_NS,
} from '../src/constants.js';
import { EncryptionFault, parseInboundEncryption } from '../src/receive/encryption.js';
import { addEncryption, createSecurityHeader } from '../src/xml/security.js';
import { append, element, firstByLocalName, parseXml } from '../src/xml/nodes.js';
import { createTestPki } from './helpers/pki.js';

const pki = createTestPki();

function buildGraph(): Document {
  const doc = parseXml('<root/>');
  const security = createSecurityHeader(doc);
  append(doc.documentElement!, security);
  addEncryption(doc, security, {
    receiverCertificatePem: pki.receiver.certPem,
    wrappedKey: Buffer.from([1, 2, 3, 4]),
    encryptedKeyId: 'EK-1',
    encryptedDataId: 'ED-1',
    encryptionTokenId: 'X509-1',
    attachmentHref: 'cid:att@example',
  });
  return doc;
}

const reason = (r: string) => (err: unknown) => err instanceof EncryptionFault && err.reason === r;

test('parses and validates a well-formed encryption graph', () => {
  const encryption = parseInboundEncryption(buildGraph());
  assert.equal(encryption.dataAlgorithm, ALGO_AES128_GCM);
  assert.equal(encryption.mediaType, 'application/gzip');
  assert.equal(encryption.attachmentHref, 'cid:att@example');
  assert.deepEqual(Buffer.from(encryption.wrappedKey), Buffer.from([1, 2, 3, 4]));
  assert.equal(encryption.oaep.digest, ALGO_SHA256);
  assert.equal(encryption.oaep.mgf, ALGO_MGF1_SHA256);
  assert.equal(encryption.oaep.label.byteLength, 0);
  assert.match(encryption.recipientCertificate ?? '', /BEGIN CERTIFICATE/);
});

test('rejects an external ciphertext reference without fetching it', () => {
  const doc = buildGraph();
  firstByLocalName(doc, XENC_NS, 'CipherReference')!.setAttribute('URI', 'http://evil.example/secret');
  assert.throws(() => parseInboundEncryption(doc), reason('encryption.invalid'));
});

test('rejects an unsupported data encryption algorithm', () => {
  const doc = buildGraph();
  const data = firstByLocalName(doc, XENC_NS, 'EncryptedData')!;
  firstByLocalName(data, XENC_NS, 'EncryptionMethod')!.setAttribute('Algorithm', 'http://example.com/evil');
  assert.throws(() => parseInboundEncryption(doc), reason('decrypt.unsupported-algorithm'));
});

test('rejects an omitted MGF rather than assuming SHA-256', () => {
  const doc = buildGraph();
  const key = firstByLocalName(doc, XENC_NS, 'EncryptedKey')!;
  const mgf = firstByLocalName(key, XENC11_NS, 'MGF')!;
  mgf.parentNode!.removeChild(mgf);
  assert.throws(() => parseInboundEncryption(doc), reason('decrypt.unsupported-algorithm'));
});

test('rejects non-empty OAEP parameters (empty-label contract)', () => {
  const doc = buildGraph();
  const key = firstByLocalName(doc, XENC_NS, 'EncryptedKey')!;
  const method = firstByLocalName(key, XENC_NS, 'EncryptionMethod')!;
  append(method, element(doc, 'xenc', 'OAEPparams', {}, 'AQID'));
  assert.throws(() => parseInboundEncryption(doc), reason('decrypt.unsupported-algorithm'));
});

test('rejects ambiguous encryption metadata', () => {
  const doc = buildGraph();
  const security = firstByLocalName(doc, WSSE_NS, 'Security')!;
  const data = firstByLocalName(doc, XENC_NS, 'EncryptedData')!;
  security.appendChild(data.cloneNode(true));
  assert.throws(() => parseInboundEncryption(doc), reason('encryption.invalid'));
});

test('resolves the attachment key through ReferenceList without the reverse link', () => {
  // SwA §5.5: when an EncryptedKey is used, EncryptedData carries no ds:KeyInfo.
  const doc = buildGraph();
  const data = firstByLocalName(doc, XENC_NS, 'EncryptedData')!;
  const keyInfo = firstByLocalName(data, DS_NS, 'KeyInfo')!;
  keyInfo.parentNode!.removeChild(keyInfo);
  const encryption = parseInboundEncryption(doc);
  assert.equal(encryption.attachmentHref, 'cid:att@example');
});

test('rejects an inconsistent reverse key link', () => {
  const doc = buildGraph();
  const data = firstByLocalName(doc, XENC_NS, 'EncryptedData')!;
  const str = firstByLocalName(firstByLocalName(data, DS_NS, 'KeyInfo')!, WSSE_NS, 'SecurityTokenReference')!;
  firstByLocalName(str, WSSE_NS, 'Reference')!.setAttribute('URI', '#NOPE');
  assert.throws(() => parseInboundEncryption(doc), reason('encryption.invalid'));
});

test('rejects conflicting declarations instead of selecting the first', () => {
  const doc = buildGraph();
  const data = firstByLocalName(doc, XENC_NS, 'EncryptedData')!;
  data.appendChild(firstByLocalName(data, XENC_NS, 'EncryptionMethod')!.cloneNode(true));
  assert.throws(() => parseInboundEncryption(doc), reason('encryption.invalid'));
});

test('rejects a CipherValue with invalid base64', () => {
  const doc = buildGraph();
  const key = firstByLocalName(doc, XENC_NS, 'EncryptedKey')!;
  const cipherValue = firstByLocalName(key, XENC_NS, 'CipherValue')!;
  while (cipherValue.firstChild) cipherValue.removeChild(cipherValue.firstChild);
  cipherValue.appendChild(doc.createTextNode('!!!!not base64!!!!'));
  assert.throws(() => parseInboundEncryption(doc), reason('encryption.invalid'));
});

test('accepts an explicitly empty OAEPparams as the empty label', () => {
  const doc = buildGraph();
  const key = firstByLocalName(doc, XENC_NS, 'EncryptedKey')!;
  append(firstByLocalName(key, XENC_NS, 'EncryptionMethod')!, element(doc, 'xenc', 'OAEPparams'));
  const encryption = parseInboundEncryption(doc);
  assert.equal(encryption.oaep.label.byteLength, 0);
});
