import test from 'node:test';
import assert from 'node:assert/strict';
import { EBMS_NS, SOAP_11_NS, SOAP_ENV_NS } from '../src/constants.js';
import { extractSoapEnvelope } from '../src/xml/signal.js';
import { parseSignalOrNull } from './helpers/signal.js';

/**
 * The signal parser must be strict about SOAP structure: it reads facts only
 * from the expected elements in the expected place. A response whose facts live
 * outside that structure (a nested Messaging, a mixed receipt and error, an
 * unknown envelope namespace) is not a signal and must return null.
 */
function envelope(header: string, options: { body?: string; ns?: string; prefix?: string } = {}): Buffer {
  const ns = options.ns ?? SOAP_ENV_NS;
  const p = options.prefix ?? 'env';
  const body = options.body ?? `<${p}:Body/>`;
  return Buffer.from(
    `<${p}:Envelope xmlns:${p}="${ns}" xmlns:eb="${EBMS_NS}">` +
      `<${p}:Header>${header}</${p}:Header>${body}</${p}:Envelope>`,
    'utf8',
  );
}

const MESSAGE_INFO = '<eb:MessageInfo><eb:MessageId>m@x</eb:MessageId></eb:MessageInfo>';
const RECEIPT = `<eb:Messaging><eb:SignalMessage>${MESSAGE_INFO}<eb:Receipt/></eb:SignalMessage></eb:Messaging>`;
const ERROR = `<eb:Messaging><eb:SignalMessage>${MESSAGE_INFO}<eb:Error errorCode="EBMS:0001" severity="failure"/></eb:SignalMessage></eb:Messaging>`;

test('accepts a SOAP 1.2 and a SOAP 1.1 receipt', () => {
  assert.equal(parseSignalOrNull(envelope(RECEIPT))?.kind, 'receipt');
  assert.equal(parseSignalOrNull(envelope(RECEIPT, { ns: SOAP_11_NS, prefix: 'SOAP-ENV' }))?.kind, 'receipt');
});

test('rejects an envelope outside a supported SOAP namespace', () => {
  assert.equal(parseSignalOrNull(envelope(RECEIPT, { ns: 'http://example.com/soap' })), null);
});

test('rejects a missing Header or Body', () => {
  const noBody = Buffer.from(
    `<env:Envelope xmlns:env="${SOAP_ENV_NS}" xmlns:eb="${EBMS_NS}"><env:Header>${RECEIPT}</env:Header></env:Envelope>`,
    'utf8',
  );
  assert.equal(parseSignalOrNull(noBody), null);

  const noHeader = Buffer.from(
    `<env:Envelope xmlns:env="${SOAP_ENV_NS}" xmlns:eb="${EBMS_NS}"><env:Body/></env:Envelope>`,
    'utf8',
  );
  assert.equal(parseSignalOrNull(noHeader), null);
});

test('rejects a Messaging element that is not a direct child of Header', () => {
  const nested = envelope(`<env:Wrapper>${RECEIPT}</env:Wrapper>`);
  assert.equal(parseSignalOrNull(nested), null);
});

test('rejects a SignalMessage that carries both a Receipt and an Error', () => {
  const mixed = `<eb:Messaging><eb:SignalMessage>${MESSAGE_INFO}<eb:Receipt/><eb:Error errorCode="EBMS:0001" severity="failure"/></eb:SignalMessage></eb:Messaging>`;
  assert.equal(parseSignalOrNull(envelope(mixed)), null);
});

test('rejects more than one Messaging or SignalMessage', () => {
  assert.equal(parseSignalOrNull(envelope(RECEIPT + ERROR)), null);
  const twoSignals = `<eb:Messaging><eb:SignalMessage>${MESSAGE_INFO}<eb:Receipt/></eb:SignalMessage><eb:SignalMessage>${MESSAGE_INFO}<eb:Receipt/></eb:SignalMessage></eb:Messaging>`;
  assert.equal(parseSignalOrNull(envelope(twoSignals)), null);
});

test('keeps the shortDescription attribute and the Description element distinct', () => {
  const attributeOnly = `<eb:Error errorCode="EBMS:0001" severity="failure" shortDescription="attr text"/>`;
  const childOnly = `<eb:Error errorCode="EBMS:0001" severity="failure"><eb:Description>child text</eb:Description></eb:Error>`;

  const withAttribute = parseSignalOrNull(
    envelope(`<eb:Messaging><eb:SignalMessage>${MESSAGE_INFO}${attributeOnly}</eb:SignalMessage></eb:Messaging>`),
  );
  assert.equal(withAttribute?.errors[0]?.shortDescription, 'attr text');
  assert.equal(withAttribute?.errors[0]?.description, null);

  const withChild = parseSignalOrNull(
    envelope(`<eb:Messaging><eb:SignalMessage>${MESSAGE_INFO}${childOnly}</eb:SignalMessage></eb:Messaging>`),
  );
  assert.equal(withChild?.errors[0]?.shortDescription, null);
  assert.equal(withChild?.errors[0]?.description, 'child text');
});

test('rejects a document type declaration', () => {
  const withDoctype = Buffer.from(
    `<!DOCTYPE env:Envelope []><env:Envelope xmlns:env="${SOAP_ENV_NS}" xmlns:eb="${EBMS_NS}">` +
      `<env:Header>${RECEIPT}</env:Header><env:Body/></env:Envelope>`,
    'utf8',
  );
  assert.equal(parseSignalOrNull(withDoctype), null);
});

test('rejects an element tree beyond the depth budget', () => {
  const deep = '<eb:X>'.repeat(70) + '</eb:X>'.repeat(70);
  const header = `<eb:Messaging><eb:SignalMessage>${MESSAGE_INFO}<eb:Receipt/>${deep}</eb:SignalMessage></eb:Messaging>`;
  assert.equal(parseSignalOrNull(envelope(header)), null);
});

test('bounds MIME part count and per-part header size', () => {
  const boundary = 'b';
  const manyParts = Array.from(
    { length: 40 },
    () => `--${boundary}\r\nContent-Type: application/octet-stream\r\n\r\nx`,
  ).join('\r\n');
  const tooMany = Buffer.from(`${manyParts}\r\n--${boundary}--\r\n`, 'utf8');
  assert.equal(extractSoapEnvelope(`multipart/related; boundary="${boundary}"`, tooMany), null);

  const oversizedHeader = Buffer.from(
    `--${boundary}\r\nContent-Type: application/soap+xml\r\nX-Big: ${'a'.repeat(20 * 1024)}\r\n\r\n<env:Envelope/>\r\n--${boundary}--\r\n`,
    'utf8',
  );
  assert.equal(extractSoapEnvelope(`multipart/related; boundary="${boundary}"`, oversizedHeader), null);
});
