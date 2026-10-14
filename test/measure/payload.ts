/**
 * Deterministic payload generation for the Item 5 measurement fixtures.
 *
 * The payload is a valid SBDH document whose header matches the AS4 headers the
 * fixture generator signs with (the same values as `sbdhDocument()` in
 * `test/receive-integration.test.ts`), followed by streamed business content and
 * the closing tags. Two content kinds:
 *
 *  - `xml`: a UBL-like invoice of repeated `cac:InvoiceLine` elements with varied
 *    text, so gzip sees realistic, compressible content.
 *  - `base64`: repeated `cbc:EmbeddedDocumentBinaryObject` elements holding
 *    barely-compressible base64 (like an embedded PDF). Each base64 run is 60 KiB,
 *    safely under the SBDH 64 KiB token limit, and the wire size is close to the
 *    recovered size.
 */
const SBDH_NS = 'http://www.unece.org/cefact/namespaces/StandardBusinessDocumentHeader';
const SENDER = { scheme: 'iso6523-actorid-upis', value: '0192:111111111' };
const RECEIVER = { scheme: 'iso6523-actorid-upis', value: '0192:222222222' };
const DOC_TYPE = {
  scheme: 'busdox-docid-qns',
  value: 'urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice##urn:cen.eu:en16931:2017::2.1',
};
const PROCESS = { scheme: 'cenbii-procid-ubl', value: 'urn:fdc:peppol.eu:2017:poacc:billing:01:1.0' };

export const SENDER_PARTICIPANT = SENDER;
export const RECEIVER_PARTICIPANT = RECEIVER;
export const DOCUMENT_TYPE = DOC_TYPE;
export const PROCESS_ID = PROCESS;

const HEADER =
  '<?xml version="1.0" encoding="UTF-8"?>' +
  `<StandardBusinessDocument xmlns="${SBDH_NS}">` +
  '<StandardBusinessDocumentHeader><HeaderVersion>1.0</HeaderVersion>' +
  `<Sender><Identifier Authority="${SENDER.scheme}">${SENDER.value}</Identifier></Sender>` +
  `<Receiver><Identifier Authority="${RECEIVER.scheme}">${RECEIVER.value}</Identifier></Receiver>` +
  '<DocumentIdentification><Standard>urn:oasis</Standard><Type>Invoice</Type></DocumentIdentification>' +
  '<BusinessScope>' +
  `<Scope><Type>PROCESSID</Type><InstanceIdentifier>${PROCESS.value}</InstanceIdentifier><Identifier>${PROCESS.scheme}</Identifier></Scope>` +
  `<Scope><Type>DOCUMENTID</Type><InstanceIdentifier>${DOC_TYPE.value}</InstanceIdentifier><Identifier>${DOC_TYPE.scheme}</Identifier></Scope>` +
  '</BusinessScope>' +
  '</StandardBusinessDocumentHeader>';

const INVOICE_OPEN =
  '<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2" ' +
  'xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2" ' +
  'xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">';
const INVOICE_CLOSE = '</Invoice>';
const FOOTER = '</StandardBusinessDocument>';

export type Kind = 'xml' | 'base64';

/** A deterministic 32-bit xorshift, so the same fixture is byte-reproducible. */
function xorshift(seed: number): () => number {
  let state = seed >>> 0 || 1;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };
}

/** 45 KiB of pseudo-random bytes, base64-encoded to 60 KiB. */
const BASE64_RAW_BYTES = 45 * 1024;
function randomBase64(next: () => number): string {
  const raw = Buffer.alloc(BASE64_RAW_BYTES);
  for (let i = 0; i < raw.length; i += 4) {
    const value = next();
    raw[i] = value & 0xff;
    if (i + 1 < raw.length) raw[i + 1] = (value >>> 8) & 0xff;
    if (i + 2 < raw.length) raw[i + 2] = (value >>> 16) & 0xff;
    if (i + 3 < raw.length) raw[i + 3] = (value >>> 24) & 0xff;
  }
  return raw.toString('base64');
}

function xmlLine(line: number, next: () => number): string {
  const amount = ((next() % 100_000) / 100).toFixed(2);
  const quantity = (next() % 1000) + 1;
  const description = `${line.toString(36)}-${next().toString(36)}-${next().toString(36)}`;
  return (
    `<cac:InvoiceLine><cbc:ID>${line}</cbc:ID>` +
    `<cbc:LineExtensionAmount currencyID="EUR">${amount}</cbc:LineExtensionAmount>` +
    `<cbc:InvoicedQuantity unitCode="EA">${quantity}</cbc:InvoicedQuantity>` +
    `<cbc:Note>${description}</cbc:Note></cac:InvoiceLine>`
  );
}

function base64Line(line: number, next: () => number): string {
  return (
    `<cac:InvoiceLine><cbc:ID>${line}</cbc:ID>` +
    `<cbc:EmbeddedDocumentBinaryObject mimeCode="application/pdf" filename="doc-${line}.pdf">` +
    `${randomBase64(next)}</cbc:EmbeddedDocumentBinaryObject></cac:InvoiceLine>`
  );
}

/**
 * Yield the recovered document in bounded chunks. The total recovered size is
 * `targetBytes` to within one line (never above it by more than a line).
 */
export function* payloadChunks(kind: Kind, targetBytes: number): Generator<Buffer> {
  const open = Buffer.from(`${HEADER}${INVOICE_OPEN}`, 'utf8');
  const close = Buffer.from(`${INVOICE_CLOSE}${FOOTER}`, 'utf8');
  yield open;
  let produced = open.length;
  const budget = targetBytes - close.length;
  const next = xorshift(kind === 'xml' ? 0x1234_5678 : 0x9e37_79b9);
  let line = 0;
  let pending = '';
  while (produced < budget) {
    const chunk = kind === 'xml' ? xmlLine(line, next) : base64Line(line, next);
    if (produced + chunk.length > budget) break;
    pending += chunk;
    produced += chunk.length;
    line += 1;
    if (pending.length >= 64 * 1024) {
      yield Buffer.from(pending, 'utf8');
      pending = '';
    }
  }
  if (pending.length > 0) yield Buffer.from(pending, 'utf8');
  yield close;
}
