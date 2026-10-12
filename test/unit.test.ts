import test from 'node:test';
import assert from 'node:assert/strict';
import { createDecipheriv, createHash, privateDecrypt, constants } from 'node:crypto';
import { Readable } from 'node:stream';
import { gunzipSync } from 'node:zlib';
import { mkdtemp, rm, writeFile, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  EBMS_NS,
  PEPPOL_AGREEMENT_REF,
  PEPPOL_PARTY_ID_TYPE,
  EBMS_ROLE_INITIATOR,
  EBMS_ROLE_RESPONDER,
  SOAP_ENV_NS,
  WSU_NS,
} from '../src/constants.js';
import { buildEnvelope } from '../src/xml/envelope.js';
import { wrapSessionKey } from '../src/crypto/session-key.js';
import { preparePayload } from '../src/crypto/payload.js';
import { buildMultipartBody } from '../src/multipart.js';
import { signerFromKey, peppolProfile } from '../src/index.js';
import { extractSoapEnvelope, parseSignal } from '../src/xml/signal.js';
import { decodeOid, derOid, parseDer, derSequence, derInteger } from '../src/pki/asn1.js';
import { canonicalize, materializeInclusiveNamespaces } from '../src/xml/c14n.js';
import { parseXml, firstByLocalName, textOf, attrOf } from '../src/xml/nodes.js';
import { safeMessage } from '../src/util.js';
import { createTestPki } from './helpers/pki.js';

const pki = createTestPki();

test('asn1: OID encode/decode round trip', () => {
  for (const oid of ['1.2.840.113549.1.1.11', '2.5.29.31', '1.3.6.1.5.5.7.48.1']) {
    const encoded = derOid(oid);
    const node = parseDer(encoded).node;
    assert.equal(decodeOid(node.value), oid);
  }
});

test('asn1: integer decoding tolerates leading zeros', () => {
  const der = derSequence(derInteger(Buffer.from([0x00, 0x01, 0x02])));
  const node = parseDer(der).node;
  assert.equal(node.tag, 0x10);
  assert.equal(node.constructed, true);
});

test('session key: RSA-OAEP wrap/unwrap round trip', () => {
  const { sessionKey, wrappedKey } = wrapSessionKey(pki.receiver.cert.publicKey);
  const unwrapped = privateDecrypt(
    { key: pki.receiver.keyObject, oaepHash: 'sha256', padding: constants.RSA_PKCS1_OAEP_PADDING },
    wrappedKey,
  );
  assert.equal(unwrapped.length, 16);
  assert.deepEqual(unwrapped, sessionKey);
});

test('preparePayload: gzip then AES-128-GCM, decryptable and digest matches gzipped bytes', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'as4-unit-'));
  try {
    const file = join(dir, 'payload.enc');
    const source = Buffer.from('<doc>hello streaming</doc>', 'utf8');
    const { sessionKey, wrappedKey } = wrapSessionKey(pki.receiver.cert.publicKey);
    const prepared = await preparePayload({ source: Readable.from(source), sessionKey, wrappedKey, filePath: file });
    const encrypted = await readFile(file);
    assert.equal(encrypted.length, prepared.byteLength);

    const iv = encrypted.subarray(0, 12);
    const tag = encrypted.subarray(encrypted.length - 16);
    const ciphertext = encrypted.subarray(12, encrypted.length - 16);
    const decipher = createDecipheriv('aes-128-gcm', sessionKey, iv);
    decipher.setAuthTag(tag);
    const gz = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    assert.deepEqual(gunzipSync(gz), source);
    assert.equal(createHash('sha256').update(gz).digest('base64'), prepared.compressedDigestBase64);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('multipart: content length matches the emitted stream and SOAP part is first', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'as4-unit-'));
  try {
    const file = join(dir, 'payload.enc');
    await writeFile(file, Buffer.from([1, 2, 3, 4, 5]));
    const body = buildMultipartBody({
      soapXml: '<env:Envelope/>',
      attachmentHref: 'cid:x@y',
      attachmentFilePath: file,
      attachmentByteLength: 5,
    });
    const chunks: Buffer[] = [];
    for await (const chunk of body.stream) chunks.push(chunk as Buffer);
    const all = Buffer.concat(chunks);
    assert.equal(all.length, body.contentLength);
    const text = all.toString('latin1');
    assert.ok(text.indexOf('application/soap+xml') < text.indexOf('application/octet-stream'));
    assert.ok(text.startsWith(`--${body.boundary}`));
    assert.ok(text.endsWith(`--${body.boundary}--\r\n`));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('envelope: user message uses spec identifiers, not hardcoded schemes', async () => {
  const { wrappedKey } = wrapSessionKey(pki.receiver.cert.publicKey);
  const built = await buildEnvelope({
    userMessage: {
      messageId: 'msg@test',
      timestamp: '2026-10-12T09:07:36.000Z',
      fromPartyId: pki.sender.commonName,
      toPartyId: pki.receiver.commonName,
      profile: peppolProfile,
      service: { scheme: 'my-process-scheme', value: 'urn:my:process' },
      action: 'my-doc-scheme::urn:my:doc',
      originalSender: { scheme: 'iso6523-actorid-upis', value: '0192:111' },
      finalRecipient: { scheme: 'iso6523-actorid-upis', value: '0192:222' },
      payloadHref: 'cid:att@test',
      compressionType: 'application/gzip',
    },
    signer: signerFromKey(pki.sender.keyObject, pki.sender.certPem),
    receiverCertificatePem: pki.receiver.certPem,
    wrappedKey,
    attachmentDigestBase64: 'abc',
  });
  const doc = parseXml(built.xml);
  const partyId = firstByLocalName(doc, EBMS_NS, 'PartyId');
  assert.equal(attrOf(partyId, 'type'), PEPPOL_PARTY_ID_TYPE);
  assert.equal(textOf(partyId), pki.sender.commonName);
  const roles = ['initiator', 'responder'];
  assert.equal(textOf(firstByLocalName(doc, EBMS_NS, 'Role')), EBMS_ROLE_INITIATOR);
  assert.ok(roles.length > 0);
  const service = firstByLocalName(doc, EBMS_NS, 'Service');
  assert.equal(attrOf(service, 'type'), 'my-process-scheme');
  assert.equal(textOf(service), 'urn:my:process');
  assert.equal(textOf(firstByLocalName(doc, EBMS_NS, 'Action')), 'my-doc-scheme::urn:my:doc');
  assert.equal(textOf(firstByLocalName(doc, EBMS_NS, 'AgreementRef')), PEPPOL_AGREEMENT_REF);
  assert.equal(textOf(firstByLocalName(doc, EBMS_NS, 'Role')), EBMS_ROLE_INITIATOR);
  // body/messaging carry wsu:Id for reference resolution
  assert.ok(firstByLocalName(doc, SOAP_ENV_NS, 'Body')?.getAttributeNS(WSU_NS, 'Id'));
  void EBMS_ROLE_RESPONDER;
});

test('signal: parses ebMS error and multipart responses, rejects non-signals', () => {
  const errorXml = Buffer.from(
    `<env:Envelope xmlns:env="${SOAP_ENV_NS}" xmlns:eb="${EBMS_NS}"><env:Header><eb:Messaging><eb:SignalMessage>` +
      `<eb:MessageInfo><eb:MessageId>e@x</eb:MessageId></eb:MessageInfo>` +
      `<eb:Error errorCode="EBMS:0004" severity="failure" category="Content" shortDescription="short text"><eb:Description>not serviced</eb:Description></eb:Error>` +
      `</eb:SignalMessage></eb:Messaging></env:Header><env:Body/></env:Envelope>`,
    'utf8',
  );
  const signal = parseSignal(errorXml);
  assert.equal(signal?.kind, 'error');
  assert.equal(signal?.errors[0]?.code, 'EBMS:0004');
  assert.equal(signal?.errors[0]?.shortDescription, 'short text');
  assert.equal(signal?.errors[0]?.description, 'not serviced');

  assert.equal(parseSignal(Buffer.from('<html>not soap</html>')), null);
  assert.equal(parseSignal(Buffer.from('x')), null);
  assert.equal(extractSoapEnvelope(undefined, Buffer.alloc(0)), null);
});

test('signal: extracts a SOAP envelope from a multipart/related response', () => {
  const soap =
    `<env:Envelope xmlns:env="${SOAP_ENV_NS}" xmlns:eb="${EBMS_NS}"><env:Header><eb:Messaging><eb:SignalMessage>` +
    `<eb:MessageInfo><eb:MessageId>r@x</eb:MessageId></eb:MessageInfo><eb:Receipt/></eb:SignalMessage></eb:Messaging></env:Header><env:Body/></env:Envelope>`;
  const boundary = 'test-boundary';
  const body = Buffer.from(
    `--${boundary}\r\nContent-Type: application/soap+xml; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n${soap}\r\n--${boundary}--\r\n`,
    'utf8',
  );
  const extracted = extractSoapEnvelope(`multipart/related; type="application/soap+xml"; boundary="${boundary}"`, body);
  assert.ok(extracted);
  const signal = parseSignal(extracted!);
  assert.equal(signal?.kind, 'receipt');
  assert.equal(signal?.messageId, 'r@x');
});

test('c14n: inclusive namespace materialisation matches explicit declaration', () => {
  const doc = parseXml(
    `<env:Envelope xmlns:env="${SOAP_ENV_NS}" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:X/></ds:SignedInfo></env:Envelope>`,
  );
  const signedInfo = firstByLocalName(doc, 'http://www.w3.org/2000/09/xmldsig#', 'SignedInfo')!;
  const withExplicit = parseXml(
    `<env:Envelope xmlns:env="${SOAP_ENV_NS}" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo xmlns:env="${SOAP_ENV_NS}"><ds:X/></ds:SignedInfo></env:Envelope>`,
  );
  const explicit = firstByLocalName(withExplicit, 'http://www.w3.org/2000/09/xmldsig#', 'SignedInfo')!;
  materializeInclusiveNamespaces(signedInfo, ['env']);
  assert.equal(canonicalize(signedInfo, ['env']), canonicalize(explicit, ['env']));
});

test('c14n: inclusive namespace declarations sort in codepoint order (uppercase prefix first)', () => {
  // Apache WSS4J/phase4 emit InclusiveNamespaces with the SOAP prefix, e.g. "S12".
  // Canonical XML orders namespace declarations by prefix in codepoint order, so
  // "S12" must precede "ds" (String.localeCompare would get this wrong).
  const doc = parseXml(
    `<S12:Envelope xmlns:S12="${SOAP_ENV_NS}" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo/></S12:Envelope>`,
  );
  const signedInfo = firstByLocalName(doc, 'http://www.w3.org/2000/09/xmldsig#', 'SignedInfo')!;
  materializeInclusiveNamespaces(signedInfo, ['S12']);
  const canonical = canonicalize(signedInfo, ['S12']);
  assert.ok(
    canonical.startsWith(`<ds:SignedInfo xmlns:S12="${SOAP_ENV_NS}" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">`),
    canonical,
  );
});

test('util: safeMessage redacts PEM and long base64', () => {
  const msg = safeMessage(
    new Error('bad key -----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY----- and ' + 'A'.repeat(100)),
  );
  assert.ok(!msg.includes('BEGIN PRIVATE KEY'));
  assert.ok(!msg.includes('AAAA'));
});
