import test from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { checkSbdhStream, defaultSbdhStreamLimits, type SbdhStreamLimits } from '../src/receive/sbdh-stream.js';

/**
 * Streaming SBDH inspection: bounded retention, whole-document structural parsing,
 * separate header vs document limits, and the consistent/inconsistent/missing/
 * resource-limit/malformed distinction.
 */
const SBDH_NS = 'http://www.unece.org/cefact/namespaces/StandardBusinessDocumentHeader';
const SENDER = { scheme: 'iso6523-actorid-upis', value: '0192:111111111' };
const RECEIVER = { scheme: 'iso6523-actorid-upis', value: '0192:222222222' };
const PROCESS = { scheme: 'cenbii-procid-ubl', value: 'urn:fdc:peppol.eu:2017:poacc:billing:01:1.0' };
const DOCUMENT = {
  scheme: 'busdox-docid-qns',
  value: 'urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice##urn:cen.eu:en16931:2017::2.1',
};
const expected = {
  originalSender: SENDER,
  finalRecipient: RECEIVER,
  process: PROCESS,
  documentType: DOCUMENT,
};

function header(): string {
  return (
    `<StandardBusinessDocument xmlns="${SBDH_NS}">` +
    '<StandardBusinessDocumentHeader><HeaderVersion>1.0</HeaderVersion>' +
    `<Sender><Identifier Authority="${SENDER.scheme}">${SENDER.value}</Identifier></Sender>` +
    `<Receiver><Identifier Authority="${RECEIVER.scheme}">${RECEIVER.value}</Identifier></Receiver>` +
    '<DocumentIdentification><Standard>urn:oasis</Standard><Type>Invoice</Type></DocumentIdentification>' +
    '<BusinessScope>' +
    `<Scope><Type>PROCESSID</Type><InstanceIdentifier>${PROCESS.value}</InstanceIdentifier><Identifier>${PROCESS.scheme}</Identifier></Scope>` +
    `<Scope><Type>DOCUMENTID</Type><InstanceIdentifier>${DOCUMENT.value}</InstanceIdentifier><Identifier>${DOCUMENT.scheme}</Identifier></Scope>` +
    '</BusinessScope>' +
    '</StandardBusinessDocumentHeader>' +
    '</StandardBusinessDocument>'
  );
}

function check(xml: string, overrides: Partial<SbdhStreamLimits> = {}, signal?: AbortSignal) {
  return checkSbdhStream(
    Readable.from([Buffer.from(xml, 'utf8')]),
    { ...defaultSbdhStreamLimits, documentBytes: 8 * 1024 * 1024, ...overrides },
    expected,
    signal,
  );
}

function withBody(extra: string): string {
  return header().replace('</StandardBusinessDocument>', `${extra}</StandardBusinessDocument>`);
}

test('a complete header is consistent', async () => {
  assert.deepEqual(await check(header()), { status: 'consistent' });
});

test('a large valid invoice with many business elements is consistent', async () => {
  assert.deepEqual(await check(withBody('<i>x</i>'.repeat(60_000))), { status: 'consistent' });
});

test('malformed XML after a valid header is malformed', async () => {
  assert.equal((await check(withBody('<broken><unclosed>'))).status, 'malformed');
});

test('a second header appearing later is malformed', async () => {
  const result = await check(withBody(`<StandardBusinessDocumentHeader xmlns="${SBDH_NS}"/>`));
  assert.equal(result.status, 'malformed');
});

test('a wrong-namespace root is missing', async () => {
  assert.deepEqual(await check(header().replace(SBDH_NS, 'urn:unrelated')), { status: 'missing' });
});

test('a lookalike header nested under a non-SBDH root is missing', async () => {
  const nested = `<Root xmlns="urn:unrelated">${header()}</Root>`;
  assert.deepEqual(await check(nested), { status: 'missing' });
});

test('a huge text token is a resource limit', async () => {
  const long = header().replace(SENDER.value, '9'.repeat(200));
  assert.deepEqual(await check(long, { tokenBytes: 16 }), { status: 'resource-limit', reason: 'xml.token-too-large' });
});

test('too many attributes is a resource limit', async () => {
  const many = header().replace('<Identifier Authority=', '<Identifier a="1" b="2" Authority=');
  assert.deepEqual(await check(many, { attributes: 2 }), {
    status: 'resource-limit',
    reason: 'xml.too-many-attributes',
  });
});

test('excessive header depth and document depth are resource limits', async () => {
  assert.deepEqual(await check(header(), { headerDepth: 3 }), { status: 'resource-limit', reason: 'xml.too-deep' });
  assert.deepEqual(await check(header(), { documentDepth: 3 }), { status: 'resource-limit', reason: 'xml.too-deep' });
});

test('excessive header nodes and document bytes are resource limits', async () => {
  assert.deepEqual(await check(header(), { headerNodes: 3 }), {
    status: 'resource-limit',
    reason: 'xml.too-many-nodes',
  });
  assert.deepEqual(await check(header(), { documentBytes: 16 }), { status: 'resource-limit', reason: 'xml.too-large' });
});

test('cancellation propagates instead of being reported as a document fact', async () => {
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(check(header(), {}, controller.signal));
});

test('a read error propagates instead of being reported as a document fact', async () => {
  const source: AsyncIterable<Uint8Array> = {
    [Symbol.asyncIterator]() {
      return {
        next(): Promise<IteratorResult<Uint8Array>> {
          return Promise.reject(Object.assign(new Error('EIO'), { code: 'EIO' }));
        },
      };
    },
  };
  await assert.rejects(checkSbdhStream(source, { ...defaultSbdhStreamLimits, documentBytes: 1024 }, expected));
});

test('omitted schemes fall back to the specified defaults', async () => {
  const xml = header()
    .replace(` Authority="${SENDER.scheme}"`, '')
    .replace(` Authority="${RECEIVER.scheme}"`, '')
    .replace(`<Identifier>${PROCESS.scheme}</Identifier>`, '')
    .replace(`<Identifier>${DOCUMENT.scheme}</Identifier>`, '');
  assert.deepEqual(await check(xml), { status: 'consistent' });
});

test('a missing required field is inconsistent', async () => {
  const result = await check(header().replace(/<Receiver>.*<\/Receiver>/, ''));
  assert.equal(result.status, 'inconsistent');
  if (result.status === 'inconsistent') assert.ok(result.mismatches.some((m) => m.includes('Receiver')));
});

test('a mismatched value is inconsistent', async () => {
  const result = await check(header().replace(SENDER.value, '0192:999999999'));
  assert.equal(result.status, 'inconsistent');
  if (result.status === 'inconsistent') assert.ok(result.mismatches.some((m) => m.includes('originalSender')));
});

test('an empty header is inconsistent (required comparisons are not possible)', async () => {
  const empty = `<StandardBusinessDocument xmlns="${SBDH_NS}"><StandardBusinessDocumentHeader/></StandardBusinessDocument>`;
  const result = await check(empty);
  assert.equal(result.status, 'inconsistent');
});

test('documentTypeFromAction splits the eb:Action scheme and value', async () => {
  const { documentTypeFromAction } = await import('../src/receive/sbdh.js');
  assert.deepEqual(documentTypeFromAction(`${DOCUMENT.scheme}::${DOCUMENT.value}`), DOCUMENT);
  assert.equal(documentTypeFromAction('no-separator'), null);
});
