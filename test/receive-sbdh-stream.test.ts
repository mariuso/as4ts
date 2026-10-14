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

function checkChunks(chunks: Buffer[], overrides: Partial<SbdhStreamLimits> = {}, signal?: AbortSignal) {
  return checkSbdhStream(
    Readable.from(chunks),
    { ...defaultSbdhStreamLimits, documentBytes: 8 * 1024 * 1024, ...overrides },
    expected,
    signal,
  );
}

function chunked(bytes: Buffer, size: number): Buffer[] {
  const chunks: Buffer[] = [];
  for (let offset = 0; offset < bytes.length; offset += size) chunks.push(bytes.subarray(offset, offset + size));
  return chunks;
}

/** A source that records how many chunks were pulled and whether it was closed. */
function trackingSource(chunks: readonly Buffer[]) {
  let closed = false;
  let reads = 0;
  const source: AsyncIterable<Uint8Array> = {
    async *[Symbol.asyncIterator]() {
      try {
        for (const chunk of chunks) {
          reads += 1;
          yield chunk;
        }
      } finally {
        closed = true;
      }
    },
  };
  return { source, closed: () => closed, reads: () => reads };
}

const settle = (): Promise<void> => new Promise((resolve) => setImmediate(resolve));

async function closedAfter(xml: string, overrides: Partial<SbdhStreamLimits> = {}) {
  const track = trackingSource([Buffer.from(xml, 'utf8')]);
  const result = await checkSbdhStream(
    track.source,
    { ...defaultSbdhStreamLimits, documentBytes: 8 * 1024 * 1024, ...overrides },
    expected,
  );
  await settle();
  return { result, closed: track.closed() };
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
  assert.deepEqual(await check(header(), { headerDepth: 2 }), { status: 'resource-limit', reason: 'xml.too-deep' });
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

// --- Gap 1: token bounds are enforced while input is consumed -----------------

test('an oversized token is rejected while it is consumed, not after accumulation', async () => {
  const xml = header().replace(` Authority="${SENDER.scheme}"`, ` Authority="${'a'.repeat(512 * 1024)}"`);
  const track = trackingSource(chunked(Buffer.from(xml, 'utf8'), 4 * 1024));
  const result = await checkSbdhStream(
    track.source,
    { ...defaultSbdhStreamLimits, documentBytes: 8 * 1024 * 1024, tokenBytes: 128 },
    expected,
  );
  assert.deepEqual(result, { status: 'resource-limit', reason: 'xml.token-too-large' });
  assert.ok(track.reads() <= 2, `pulled ${track.reads()} chunks before rejecting`);
});

test('an oversized business-body text token is rejected', async () => {
  assert.deepEqual(await check(withBody('x'.repeat(1024 * 1024))), {
    status: 'resource-limit',
    reason: 'xml.token-too-large',
  });
});

test('oversized comments, CDATA, processing instructions and attribute collections are bounded', async () => {
  const big = 'x'.repeat(4096);
  for (const body of [`<!--${big}-->`, `<![CDATA[${big}]]>`, `<?pi ${big}?>`, `<i a="${big}"/>`]) {
    assert.deepEqual(
      await check(withBody(body), { tokenBytes: 1024 }),
      { status: 'resource-limit', reason: 'xml.token-too-large' },
      body.slice(0, 16),
    );
  }
});

test('business-content Scope records are not retained outside the header', async () => {
  const body = Array.from(
    { length: 10_000 },
    () => '<Scope><Type>PROCESSID</Type><InstanceIdentifier>x</InstanceIdentifier></Scope>',
  ).join('');
  // The body has far more nodes than headerNodes allows and thousands of PROCESSID
  // scopes. If either were charged to the header this would be a resource limit or a
  // cardinality error; the header's own facts still compare cleanly.
  const result = await check(withBody(body), { headerNodes: 64 });
  assert.deepEqual(result, { status: 'consistent' });
});

// --- Gap 2: namespace, structure and character data --------------------------

test('an identifier in an unrelated namespace is inconsistent', async () => {
  const xml = header().replace(
    `<Identifier Authority="${SENDER.scheme}">`,
    `<Identifier xmlns="urn:unrelated" Authority="${SENDER.scheme}">`,
  );
  assert.equal((await check(xml)).status, 'inconsistent');
});

test('a duplicated identifier is a structural error, not a concatenation', async () => {
  const xml = header().replace(`</Sender>`, `<Identifier>${SENDER.value}</Identifier></Sender>`);
  assert.equal((await check(xml)).status, 'malformed');
});

test('a business scope nested under a wrapper is inconsistent', async () => {
  const xml = header()
    .replace('<BusinessScope>', '<Extra><BusinessScope>')
    .replace('</BusinessScope>', '</BusinessScope></Extra>');
  assert.equal((await check(xml)).status, 'inconsistent');
});

test('CDATA participates in the identifier value', async () => {
  const cdata = header().replace(`>${SENDER.value}</Identifier>`, `><![CDATA[${SENDER.value}]]></Identifier>`);
  assert.deepEqual(await check(cdata), { status: 'consistent' });
  const wrong = header().replace(
    `>${SENDER.value}</Identifier>`,
    `>${SENDER.value.slice(0, 4)}<![CDATA[WRONG]]></Identifier>`,
  );
  assert.equal((await check(wrong)).status, 'inconsistent');
});

test('a header nested under a wrapper inside an SBDH root is missing', async () => {
  const xml = `<StandardBusinessDocument xmlns="${SBDH_NS}"><Wrapper><StandardBusinessDocumentHeader/></Wrapper></StandardBusinessDocument>`;
  assert.deepEqual(await check(xml), { status: 'missing' });
});

// --- Gap 3: header budgets are independent of chunk boundaries ----------------

test('header bytes are counted identically regardless of chunk boundaries', async () => {
  const bytes = Buffer.from(header(), 'utf8');
  const small: Partial<SbdhStreamLimits> = { headerBytes: 10 };
  assert.deepEqual(await checkChunks([bytes], small), await checkChunks(chunked(bytes, 16), small));
  assert.deepEqual(await checkChunks([bytes], small), { status: 'resource-limit', reason: 'xml.too-large' });
  const generous: Partial<SbdhStreamLimits> = { headerBytes: 1024 * 1024 };
  assert.deepEqual(await checkChunks([bytes], generous), { status: 'consistent' });
  assert.deepEqual(await checkChunks(chunked(bytes, 16), generous), { status: 'consistent' });
});

test('shallow sibling elements do not exhaust the header depth', async () => {
  const siblings = Array.from({ length: 40 }, (_, index) => `<Extra${index}>x</Extra${index}>`).join('');
  const xml = header().replace('</StandardBusinessDocumentHeader>', `${siblings}</StandardBusinessDocumentHeader>`);
  assert.deepEqual(await check(xml), { status: 'consistent' });
});

test('document bytes are charged while the declaration prefix is read', async () => {
  const track = trackingSource([Buffer.from(header(), 'utf8').subarray(0, 64)]);
  const result = await checkSbdhStream(track.source, { ...defaultSbdhStreamLimits, documentBytes: 16 }, expected);
  assert.deepEqual(result, { status: 'resource-limit', reason: 'xml.too-large' });
  assert.equal(track.reads(), 1, 'waited for more than the first chunk');
});

test('tokenBytes measures UTF-8 bytes, not code units', async () => {
  // Four two-byte characters are eight bytes but only four code units.
  assert.deepEqual(await check(withBody(`<b>${'é'.repeat(4)}</b>`), { tokenBytes: 6 }), {
    status: 'resource-limit',
    reason: 'xml.token-too-large',
  });
});

// --- Gap 4: the source iterator is closed on every exit ----------------------

test('the source iterator is closed on a resource limit, malformed input and unsupported encoding', async () => {
  const limit = await closedAfter(header(), { documentBytes: 16 });
  assert.equal(limit.result.status, 'resource-limit');
  assert.ok(limit.closed, 'resource limit left the source open');

  const malformed = await closedAfter(withBody('<unclosed>'));
  assert.equal(malformed.result.status, 'malformed');
  assert.ok(malformed.closed, 'malformed input left the source open');

  const unsupported = await closedAfter(`<?xml version="1.0" encoding="utf-16"?>${header()}`);
  assert.equal(unsupported.result.status, 'malformed');
  assert.ok(unsupported.closed, 'unsupported encoding left the source open');
});

test('the source iterator is closed on cancellation', async () => {
  const controller = new AbortController();
  controller.abort();
  const track = trackingSource([Buffer.from(header(), 'utf8')]);
  await assert.rejects(
    checkSbdhStream(
      track.source,
      { ...defaultSbdhStreamLimits, documentBytes: 8 * 1024 * 1024 },
      expected,
      controller.signal,
    ),
  );
  await settle();
  assert.ok(track.closed(), 'cancellation left the source open');
});

// --- Gap 5: encoding validation ----------------------------------------------

test('an unsupported encoding declared beyond the first 256 bytes is malformed', async () => {
  const xml = `<?xml version="1.0"${' '.repeat(300)}encoding="utf-16"?>${header()}`;
  assert.equal((await check(xml)).status, 'malformed');
});

test('a UTF-8 byte order mark conflicting with the declaration is malformed', async () => {
  const xml = `\uFEFF<?xml version="1.0" encoding="iso-8859-1"?>${header()}`;
  assert.equal((await check(xml)).status, 'malformed');
});

test('a byte order mark and a conflicting declaration split across chunks are malformed', async () => {
  const bom = Buffer.from([0xef, 0xbb, 0xbf]);
  const declaration = Buffer.from('<?xml version="1.0" encoding="utf-16"?>', 'utf8');
  const result = await checkChunks([bom, declaration, Buffer.from(header(), 'utf8')]);
  assert.equal(result.status, 'malformed');
});

test('a byte order mark with a matching declaration is accepted', async () => {
  const xml = `\uFEFF<?xml version="1.0" encoding="utf-8"?>${header()}`;
  assert.deepEqual(await check(xml), { status: 'consistent' });
});

test('an incomplete UTF-8 sequence at end of document is malformed, not an internal error', async () => {
  const complete = Buffer.concat([Buffer.from(header(), 'utf8'), Buffer.from('\n', 'utf8')]);
  const truncated = Buffer.from([0x20, 0xe2, 0x82]);
  const result = await checkChunks([complete, truncated]);
  assert.equal(result.status, 'malformed');
});

test('an ASCII declaration is enforced', async () => {
  const xml = `<?xml version="1.0" encoding="us-ascii"?>${header().replace(
    '<HeaderVersion>1.0</HeaderVersion>',
    '<HeaderVersion>1.0\u00e9</HeaderVersion>',
  )}`;
  assert.equal((await check(xml)).status, 'malformed');
});

// --- Lexical scanner: token openings, terminators and boundaries -------------

test('a processing instruction is bounded even with markup-shaped content', async () => {
  const doc = withBody(`<?pi ${'<x>'.repeat(10_000)}?>`);
  assert.deepEqual(await check(doc, { tokenBytes: 128 }), { status: 'resource-limit', reason: 'xml.token-too-large' });
});

test('a comment whose content starts with ">" ends only at "-->";', async () => {
  const doc = withBody(`<!-->${'<x>'.repeat(10_000)}-->`);
  assert.deepEqual(await check(doc, { tokenBytes: 128 }), { status: 'resource-limit', reason: 'xml.token-too-large' });
});

test('token recognition does not depend on the previous token', async () => {
  const pi = `<?pi ${'<x>'.repeat(10_000)}?>`;
  const comment = `<!--${'<x>'.repeat(10_000)}-->`;
  assert.deepEqual(await check(withBody(`<a/>${pi}`), { tokenBytes: 128 }), {
    status: 'resource-limit',
    reason: 'xml.token-too-large',
  });
  assert.deepEqual(await check(withBody(`<a b="c"/>${comment}`), { tokenBytes: 128 }), {
    status: 'resource-limit',
    reason: 'xml.token-too-large',
  });
});

test('a short processing instruction followed by small elements is accepted', async () => {
  assert.deepEqual(await check(withBody('<?pi "?><i>x</i>')), { status: 'consistent' });
});

test('embedded >, < and quotes inside a comment or processing instruction are accepted', async () => {
  assert.deepEqual(await check(withBody('<!-- a > b < c " d --><?pi x > < y " z ?>')), { status: 'consistent' });
});

test('a text token at the byte boundary is accepted and one byte over is rejected', async () => {
  assert.deepEqual(await check(withBody(`<t>${'x'.repeat(128)}</t>`), { tokenBytes: 128 }), { status: 'consistent' });
  assert.deepEqual(await check(withBody(`<t>${'x'.repeat(129)}</t>`), { tokenBytes: 128 }), {
    status: 'resource-limit',
    reason: 'xml.token-too-large',
  });
});

test('an unfinished comment at end of document is bounded, or malformed when small', async () => {
  assert.deepEqual(await check(withBody(`<!--${'x'.repeat(200)}`), { tokenBytes: 128 }), {
    status: 'resource-limit',
    reason: 'xml.token-too-large',
  });
  assert.equal((await check(withBody('<!-- small'))).status, 'malformed');
});

// --- Declaration detection is chunk independent ------------------------------

async function assertStatusAcrossSplits(bytes: Buffer, status: string): Promise<void> {
  assert.equal((await checkChunks([bytes])).status, status, 'single chunk');
  assert.equal((await checkChunks(chunked(bytes, 1))).status, status, 'one-byte chunks');
  for (let split = 0; split <= Math.min(bytes.length, 64); split++) {
    const result = await checkChunks([bytes.subarray(0, split), bytes.subarray(split)]);
    assert.equal(result.status, status, `split at ${split}`);
  }
}

test('an unsupported declaration is malformed at every split position', async () => {
  const bytes = Buffer.from(`<?xml version="1.0" encoding="utf-16"?>${header()}`, 'utf8');
  await assertStatusAcrossSplits(bytes, 'malformed');
});

test('an over-long declaration is malformed regardless of chunk size', async () => {
  const bytes = Buffer.from(`<?xml version="1.0"${' '.repeat(2000)}encoding="utf-16"?>${header()}`, 'utf8');
  assert.equal((await checkChunks([bytes])).status, 'malformed', 'single chunk');
  assert.equal((await checkChunks(chunked(bytes, 64))).status, 'malformed', '64-byte chunks');
});

test('a matching declaration is consistent at every split position', async () => {
  const bytes = Buffer.from(`<?xml version="1.0" encoding="utf-8"?>${header()}`, 'utf8');
  await assertStatusAcrossSplits(bytes, 'consistent');
});

test('a byte order mark with a matching declaration is consistent at every split position', async () => {
  const bytes = Buffer.concat([
    Buffer.from([0xef, 0xbb, 0xbf]),
    Buffer.from(`<?xml version="1.0" encoding="utf-8"?>${header()}`, 'utf8'),
  ]);
  await assertStatusAcrossSplits(bytes, 'consistent');
});

test('a Latin-1 document is consistent at every split position', async () => {
  const bytes = Buffer.concat([
    Buffer.from(
      `<?xml version="1.0" encoding="iso-8859-1"?>${header().replace('</StandardBusinessDocument>', '<extra>')}`,
      'latin1',
    ),
    Buffer.from([0xe9]),
    Buffer.from('</extra></StandardBusinessDocument>', 'latin1'),
  ]);
  await assertStatusAcrossSplits(bytes, 'consistent');
});

// --- Simple-content fields and scope collection ------------------------------

test('a nested element inside an identifier is rejected, not silently ignored', async () => {
  const xml = header().replace(`>${SENDER.value}</Identifier>`, `>${SENDER.value}<x>WRONG</x></Identifier>`);
  assert.equal((await check(xml)).status, 'malformed');
});

test('a nested element inside a scope field is rejected', async () => {
  const xml = header().replace(
    `>${PROCESS.value}</InstanceIdentifier>`,
    `>${PROCESS.value}<x>WRONG</x></InstanceIdentifier>`,
  );
  assert.equal((await check(xml)).status, 'malformed');
});

test('closing an unrelated nested Scope does not end scope collection', async () => {
  const original = `<Scope><Type>PROCESSID</Type><InstanceIdentifier>${PROCESS.value}</InstanceIdentifier><Identifier>${PROCESS.scheme}</Identifier></Scope>`;
  const nested =
    `<Scope><Type>PROCESSID</Type><Extra><Scope/></Extra>` +
    `<InstanceIdentifier>${PROCESS.value}</InstanceIdentifier><Identifier>${PROCESS.scheme}</Identifier></Scope>`;
  assert.deepEqual(await check(header().replace(original, nested)), { status: 'consistent' });
});

// --- The header byte budget measures the actual header span ------------------

async function minHeaderBudget(bytes: Buffer, chunkSize: number): Promise<number> {
  const chunks = chunkSize > 0 ? chunked(bytes, chunkSize) : [bytes];
  const limited = async (budget: number): Promise<boolean> =>
    (await checkChunks(chunks, { headerBytes: budget })).status === 'resource-limit';
  let lo = 0;
  let hi = bytes.length + 32;
  if (await limited(hi)) return -1;
  while (lo < hi) {
    const mid = Math.floor((lo + hi) / 2);
    if (await limited(mid)) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

/** The exact UTF-8 byte span of the SBDH header element in `xml`. */
function headerBytesOf(xml: string): number {
  const start = xml.indexOf('<StandardBusinessDocumentHeader');
  const close = xml.indexOf('</StandardBusinessDocumentHeader>');
  const end = close >= 0 ? close + '</StandardBusinessDocumentHeader>'.length : xml.indexOf('/>', start) + 2;
  return Buffer.byteLength(xml.slice(start, end), 'utf8');
}

test('the header budget equals the header span for ordinary headers', async () => {
  const expected = headerBytesOf(header());
  const bytes = Buffer.from(header(), 'utf8');
  assert.equal(await minHeaderBudget(bytes, 0), expected);
  assert.equal(await minHeaderBudget(bytes, 1), expected);
  assert.equal(await minHeaderBudget(bytes, 7), expected);
  assert.equal((await checkChunks([bytes], { headerBytes: expected - 1 })).status, 'resource-limit');
  assert.notEqual((await checkChunks([bytes], { headerBytes: expected })).status, 'resource-limit');
});

test('a self-closing header counts its exact opening markup', async () => {
  const xml = `<StandardBusinessDocument xmlns="${SBDH_NS}"><StandardBusinessDocumentHeader ${'a'.repeat(200)}="x"/><Body/></StandardBusinessDocument>`;
  const expected = headerBytesOf(xml);
  assert.ok(expected > 200, `header span ${expected} did not include the 200-character attribute`);
  const bytes = Buffer.from(xml, 'utf8');
  assert.equal(await minHeaderBudget(bytes, 0), expected);
  assert.equal(await minHeaderBudget(bytes, 1), expected);
  assert.equal((await checkChunks([bytes], { headerBytes: 1 })).status, 'resource-limit');
});

test('content before the header is not charged to the header budget', async () => {
  const xml = header().replace(
    '<StandardBusinessDocumentHeader>',
    `<Other>${'x'.repeat(5000)}</Other><StandardBusinessDocumentHeader>`,
  );
  assert.deepEqual(await check(xml, { headerBytes: 1000 }), { status: 'consistent' });
});

test('the header budget applies to a header that follows another child', async () => {
  const xml = header().replace('<StandardBusinessDocumentHeader>', '<Other/><StandardBusinessDocumentHeader>');
  assert.deepEqual(await check(xml, { headerBytes: 1 }), { status: 'resource-limit', reason: 'xml.too-large' });
});

test('whitespace and comments before the header do not change the header span', async () => {
  const xml = header().replace(
    '<StandardBusinessDocumentHeader>',
    '\n  <!-- note -->\n  <StandardBusinessDocumentHeader>',
  );
  const expected = headerBytesOf(xml);
  const bytes = Buffer.from(xml, 'utf8');
  assert.equal(await minHeaderBudget(bytes, 0), expected);
  assert.equal(await minHeaderBudget(bytes, 1), expected);
});

test('a non-SBDH root with a lookalike header is missing, not a resource limit', async () => {
  const xml = `<Root xmlns="urn:unrelated"><StandardBusinessDocumentHeader ${'a'.repeat(500)}="x"/></Root>`;
  assert.deepEqual(await check(xml, { headerBytes: 1 }), { status: 'missing' });
});

/** Comment padding, small enough that no single token or node count trips first. */
function commentPadding(total: number): string {
  let remaining = total;
  const parts: string[] = [];
  while (remaining > 0) {
    const size = Math.min(remaining, 60_000);
    parts.push(`<!--${'p'.repeat(size - 7)}-->`);
    remaining -= size;
  }
  return parts.join('');
}

const CHUNK_SIZES = [0, 64 * 1024, 1, 7];

function chunksOf(xml: string, size: number): Buffer[] {
  const bytes = Buffer.from(xml, 'utf8');
  return size > 0 ? chunked(bytes, size) : [bytes];
}

test('a header over the byte limit is a resource limit even with a foreign lookalike after it', async () => {
  const base = header();
  const target = 295_299;
  const big = base.replace(
    '</StandardBusinessDocumentHeader>',
    `${commentPadding(target - headerBytesOf(base))}</StandardBusinessDocumentHeader>`,
  );
  assert.equal(headerBytesOf(big), target);
  assert.ok(target > defaultSbdhStreamLimits.headerBytes);
  const withLookalike = big.replace(
    '</StandardBusinessDocument>',
    '<StandardBusinessDocumentHeader xmlns="urn:other"/></StandardBusinessDocument>',
  );
  for (const size of CHUNK_SIZES) {
    assert.deepEqual(await checkChunks(chunksOf(big, size)), { status: 'resource-limit', reason: 'xml.too-large' });
    assert.deepEqual(
      await checkChunks(chunksOf(withLookalike, size)),
      { status: 'resource-limit', reason: 'xml.too-large' },
      `chunk size ${size} with a trailing lookalike`,
    );
  }
});

test('a large foreign lookalike is not charged to a valid header', async () => {
  const lookalike = `<StandardBusinessDocumentHeader xmlns="urn:other">${commentPadding(300_000)}</StandardBusinessDocumentHeader>`;
  const cases: ReadonlyArray<readonly [string, string]> = [
    ['after', header().replace('</StandardBusinessDocument>', `${lookalike}</StandardBusinessDocument>`)],
    ['before', header().replace('<StandardBusinessDocumentHeader>', `${lookalike}<StandardBusinessDocumentHeader>`)],
  ];
  for (const size of [0, 64 * 1024, 4096, 7]) {
    for (const [label, xml] of cases) {
      assert.deepEqual(
        await checkChunks(chunksOf(xml, size)),
        { status: 'consistent' },
        `${label}, chunk size ${size}`,
      );
    }
  }
});

test('the header span is bound to the validated element, not a lookalike', async () => {
  const expected = headerBytesOf(header());
  const lookalike = '<StandardBusinessDocumentHeader xmlns="urn:other"><A/></StandardBusinessDocumentHeader>';
  const cases = [
    header().replace('</StandardBusinessDocument>', `${lookalike}</StandardBusinessDocument>`),
    header().replace('<StandardBusinessDocumentHeader>', `${lookalike}<StandardBusinessDocumentHeader>`),
  ];
  for (const xml of cases) {
    const bytes = Buffer.from(xml, 'utf8');
    assert.equal(await minHeaderBudget(bytes, 0), expected);
    assert.equal(await minHeaderBudget(bytes, 1), expected);
  }
});

// --- Prefix and DOCTYPE accumulation -----------------------------------------

test('leading whitespace is not accumulated while waiting for a declaration', async () => {
  const bytes = Buffer.concat([Buffer.from(' '.repeat(1024 * 1024)), Buffer.from(header(), 'utf8')]);
  const track = trackingSource(chunked(bytes, 4096));
  const result = await checkSbdhStream(
    track.source,
    { ...defaultSbdhStreamLimits, documentBytes: 8 * 1024 * 1024, tokenBytes: 128 },
    expected,
  );
  assert.deepEqual(result, { status: 'resource-limit', reason: 'xml.token-too-large' });
  assert.ok(track.reads() <= 2, `pulled ${track.reads()} chunks`);
  await settle();
  assert.ok(track.closed());
});

test('a DOCTYPE is rejected as soon as its opening is recognised', async () => {
  const bytes = Buffer.from(`<!DOCTYPE foo [${'<!ENTITY a "b">'.repeat(10_000)}]>${header()}`, 'utf8');
  const track = trackingSource(chunked(bytes, 4096));
  const result = await checkSbdhStream(
    track.source,
    { ...defaultSbdhStreamLimits, documentBytes: 8 * 1024 * 1024 },
    expected,
  );
  assert.equal(result.status, 'malformed');
  assert.ok(track.reads() <= 2, `pulled ${track.reads()} chunks`);
});

test('an unfinished DOCTYPE is rejected early too', async () => {
  const bytes = Buffer.from(`<!DOCTYPE foo [${'<!ENTITY a "b">'.repeat(10_000)}`, 'utf8');
  const track = trackingSource(chunked(bytes, 4096));
  const result = await checkSbdhStream(
    track.source,
    { ...defaultSbdhStreamLimits, documentBytes: 8 * 1024 * 1024 },
    expected,
  );
  assert.equal(result.status, 'malformed');
  assert.ok(track.reads() <= 2, `pulled ${track.reads()} chunks`);
});

test('a conflicting declaration is malformed across every BOM and declaration split', async () => {
  for (const bom of [[], [0xef, 0xbb, 0xbf]]) {
    const bytes = Buffer.concat([
      Buffer.from(bom),
      Buffer.from(`<?xml version="1.0" encoding="utf-16"?>${header()}`, 'utf8'),
    ]);
    await assertStatusAcrossSplits(bytes, 'malformed');
  }
  const latin1 = Buffer.concat([
    Buffer.from([0xef, 0xbb, 0xbf]),
    Buffer.from(`<?xml version="1.0" encoding="iso-8859-1"?>${header()}`, 'utf8'),
  ]);
  await assertStatusAcrossSplits(latin1, 'malformed');
});

test('a processing instruction whose target begins with xml is not the declaration', async () => {
  const bytes = Buffer.from(`<?xml-stylesheet encoding="utf-16"?>${header()}`, 'utf8');
  await assertStatusAcrossSplits(bytes, 'consistent');
});

test('an XML 1.1 declaration is unsupported', async () => {
  const bytes = Buffer.from(`<?xml version="1.1"?>${header()}`, 'utf8');
  await assertStatusAcrossSplits(bytes, 'malformed');
});

test('XML 1.1 line separators cannot desynchronise the scanner', async () => {
  for (const separator of ['\u0085', '\u2028', '\u000b', '\u000c']) {
    const xml = `<?xml version="1.1"?>${header().replace(
      '<StandardBusinessDocumentHeader>',
      `<StandardBusinessDocumentHeader${separator}>`,
    )}`;
    await assertStatusAcrossSplits(Buffer.from(xml, 'utf8'), 'malformed');
  }
});

test('a separator that only the parser treats as whitespace fails closed', async () => {
  // Without an XML 1.1 declaration the streams still disagree; the association
  // must reject rather than silently skipping the header-byte budget.
  for (const separator of ['\u0085', '\u2028']) {
    const xml = header().replace('<StandardBusinessDocumentHeader>', `<StandardBusinessDocumentHeader${separator}>`);
    await assertStatusAcrossSplits(Buffer.from(xml, 'utf8'), 'malformed');
  }
});
