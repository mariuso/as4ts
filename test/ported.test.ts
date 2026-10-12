import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ALGO_AES128_GCM,
  ALGO_EXC_C14N,
  ALGO_MGF1_SHA256,
  ALGO_RSA_OAEP,
  ALGO_RSA_SHA256,
  ALGO_SHA256,
  EBMS_NS,
  SWA_ATTACHMENT_CONTENT_ONLY,
  SWA_TRANSFORM_CIPHERTEXT,
  SWA_TRANSFORM_SIGNATURE,
  WSSE_NS,
  WSS_ENCRYPTED_KEY_TOKEN_TYPE,
  WSS_X509_V3,
  WSU_NS,
} from '../src/constants.js';
import { classifyEbmsError, EBMS_ERROR_TABLE } from '../src/outcome.js';
import { extractSoapEnvelope, parseSignal } from '../src/xml/signal.js';
import { isValidMessageId } from '../src/util.js';

// Expectations extracted from the phase4 / Oxalis-NG crypto test suites
// (ECryptoAlgorithm*, OxalisAlgorithmSuite). These are the algorithm identifiers
// WSS4J / Apache XML Security put on the wire; a typo here breaks interop.

test('crypto algorithm identifiers match the XML Security / WSS4J values', () => {
  assert.equal(ALGO_EXC_C14N, 'http://www.w3.org/2001/10/xml-exc-c14n#');
  assert.equal(ALGO_RSA_SHA256, 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');
  assert.equal(ALGO_SHA256, 'http://www.w3.org/2001/04/xmlenc#sha256');
  assert.equal(ALGO_AES128_GCM, 'http://www.w3.org/2009/xmlenc11#aes128-gcm');
  assert.equal(ALGO_RSA_OAEP, 'http://www.w3.org/2009/xmlenc11#rsa-oaep');
  assert.equal(ALGO_MGF1_SHA256, 'http://www.w3.org/2009/xmlenc11#mgf1sha256');
});

test('WS-Security token and SwA identifiers match', () => {
  assert.equal(
    SWA_TRANSFORM_SIGNATURE,
    'http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Signature-Transform',
  );
  assert.equal(
    SWA_TRANSFORM_CIPHERTEXT,
    'http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Ciphertext-Transform',
  );
  assert.equal(
    SWA_ATTACHMENT_CONTENT_ONLY,
    'http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Only',
  );
  assert.equal(WSS_X509_V3, 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3');
  assert.equal(
    WSS_ENCRYPTED_KEY_TOKEN_TYPE,
    'http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKey',
  );
  assert.equal(WSSE_NS, 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd');
  assert.equal(WSU_NS, 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd');
  assert.equal(EBMS_NS, 'http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/');
});

// Cross-checked against Oxalis-NG's AS4ErrorCode and the ebMS/AS4 error tables.
test('ebMS error table covers the standard codes and defaults unknown to fatal', () => {
  const expected = [
    'EBMS:0001',
    'EBMS:0002',
    'EBMS:0003',
    'EBMS:0004',
    'EBMS:0005',
    'EBMS:0006',
    'EBMS:0007',
    'EBMS:0008',
    'EBMS:0009',
    'EBMS:0010',
    'EBMS:0011',
    'EBMS:0101',
    'EBMS:0102',
    'EBMS:0103',
    'EBMS:0201',
    'EBMS:0202',
    'EBMS:0301',
    'EBMS:0302',
    'EBMS:0303',
  ];
  for (const code of expected) assert.ok(code in EBMS_ERROR_TABLE, `missing ${code}`);
  assert.equal(classifyEbmsError({ code: 'EBMS:9999' }), 'fatal');
});

function multipart(contentType: string, parts: string[]): Buffer {
  const boundary = /boundary="?([^";]+)"?/.exec(contentType)![1]!;
  return Buffer.from(parts.map((p) => `--${boundary}\r\n${p}`).join('') + `--${boundary}--\r\n`, 'utf8');
}

const SOAP12 =
  `<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope" xmlns:eb="${EBMS_NS}">` +
  `<S12:Header><eb:Messaging><eb:SignalMessage><eb:MessageInfo><eb:MessageId>r@x</eb:MessageId></eb:MessageInfo><eb:Receipt/></eb:SignalMessage></eb:Messaging></S12:Header><S12:Body/></S12:Envelope>`;

const SOAP11 =
  `<S11:Envelope xmlns:S11="http://schemas.xmlsoap.org/soap/envelope/" xmlns:eb="${EBMS_NS}">` +
  `<S11:Header><eb:Messaging><eb:SignalMessage><eb:MessageInfo><eb:MessageId>r11@x</eb:MessageId></eb:MessageInfo><eb:Receipt/></eb:SignalMessage></eb:Messaging></S11:Header><S11:Body/></S11:Envelope>`;

test('multipart response: quoted boundary, extra part, SOAP 1.1 envelope', () => {
  const ct = 'multipart/related; type="application/soap+xml"; boundary="abc-123"';
  const body = multipart(ct, [
    'Content-Type: text/plain\r\n\r\nignore me\r\n',
    `Content-Type: application/soap+xml; charset=UTF-8\r\nContent-Transfer-Encoding: binary\r\n\r\n${SOAP11}\r\n`,
  ]);
  const soap = extractSoapEnvelope(ct, body);
  assert.ok(soap);
  const signal = parseSignal(soap!);
  assert.equal(signal?.kind, 'receipt');
  assert.equal(signal?.messageId, 'r11@x');
});

test('multipart response: base64 transfer encoding', () => {
  const ct = 'multipart/related; boundary="b64"';
  const encoded = Buffer.from(SOAP12, 'utf8')
    .toString('base64')
    .replace(/(.{76})/g, '$1\r\n');
  const body = multipart(ct, [
    `Content-Type: application/soap+xml\r\nContent-Transfer-Encoding: base64\r\n\r\n${encoded}\r\n`,
  ]);
  const signal = parseSignal(extractSoapEnvelope(ct, body)!);
  assert.equal(signal?.kind, 'receipt');
  assert.equal(signal?.messageId, 'r@x');
});

// Ported from Oxalis-NG MessageIdUtilTest: eb:MessageId must be an RFC 2822 msg-id.
test('message id validation (RFC 2822 msg-id)', () => {
  for (const ok of ['a@b', 'uuid-1234@example.com', 'john.doe@sub.example.org', 'id@[127.0.0.1]', 'x!y#z@host']) {
    assert.equal(isValidMessageId(ok), true, `expected valid: ${ok}`);
  }
  for (const bad of ['', 'no-at', 'a@b@c', 'has space@x', '<a@b>', 'a@', '@b', 'a@b ', ' a@b', 'a;b@c', 'a@b\n']) {
    assert.equal(isValidMessageId(bad), false, `expected invalid: ${JSON.stringify(bad)}`);
  }
});
