import test from 'node:test';
import assert from 'node:assert/strict';
import {
  MimeFault,
  parseMultipartRelated,
  selectSoapPart,
  type MimeLimits,
  type ParsedMultipart,
} from '../src/receive/mime.js';

const LIMITS: MimeLimits = {
  maxRequestBytes: 1_000_000,
  maxParts: 8,
  maxHeaderBytes: 4096,
  maxPartBytes: 500_000,
  maxBoundaryLength: 70,
};

const BOUNDARY = '----=_Part_test_boundary';
const CT = `multipart/related; type="application/soap+xml"; boundary="${BOUNDARY}"`;

function multipart(parts: readonly { headers: Record<string, string>; body: Buffer | string }[]): Buffer {
  const chunks: Buffer[] = [];
  for (const part of parts) {
    const headerLines = Object.entries(part.headers)
      .map(([name, value]) => `${name}: ${value}`)
      .join('\r\n');
    chunks.push(Buffer.from(`--${BOUNDARY}\r\n${headerLines}\r\n\r\n`, 'latin1'));
    chunks.push(Buffer.isBuffer(part.body) ? part.body : Buffer.from(part.body, 'utf8'));
    chunks.push(Buffer.from('\r\n', 'latin1'));
  }
  chunks.push(Buffer.from(`--${BOUNDARY}--\r\n`, 'latin1'));
  return Buffer.concat(chunks);
}

/** Yield a buffer in fixed-size slices, to exercise arbitrary chunk boundaries. */
async function* slices(buffer: Buffer, size: number): AsyncGenerator<Uint8Array> {
  for (let offset = 0; offset < buffer.length; offset += size) {
    yield buffer.subarray(offset, offset + size);
  }
}

function parse(buffer: Buffer, size = buffer.length): Promise<ParsedMultipart> {
  return parseMultipartRelated({ contentType: CT, body: slices(buffer, size), limits: LIMITS });
}

const SOAP = '<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope"/>';
const ATTACHMENT = 'the encrypted attachment bytes';
const WELL_FORMED = multipart([
  { headers: { 'Content-Type': 'application/soap+xml; charset=UTF-8', 'Content-ID': '<soap@x>' }, body: SOAP },
  { headers: { 'Content-Type': 'application/octet-stream', 'Content-ID': '<att@x>' }, body: ATTACHMENT },
]);

test('parses a multipart/related body and selects the SOAP part', async () => {
  const parsed = await parse(WELL_FORMED);
  assert.equal(parsed.parts.length, 2);
  assert.equal(parsed.parts[0]!.contentId, 'soap@x');
  assert.equal(parsed.parts[0]!.body.toString('utf8'), SOAP);
  assert.equal(parsed.parts[1]!.contentId, 'att@x');
  assert.equal(parsed.parts[1]!.body.toString('utf8'), ATTACHMENT);
  assert.equal(selectSoapPart(parsed).contentId, 'soap@x');
});

test('is byte-safe regardless of where the stream is split', async () => {
  const reference = await parse(WELL_FORMED);
  for (let size = 1; size <= WELL_FORMED.length; size += 1) {
    const parsed = await parse(WELL_FORMED, size);
    assert.equal(parsed.parts.length, 2, `split size ${size}`);
    assert.equal(parsed.parts[0]!.body.toString('utf8'), reference.parts[0]!.body.toString('utf8'));
    assert.equal(parsed.parts[1]!.body.toString('utf8'), reference.parts[1]!.body.toString('utf8'));
  }
});

test('does not split on boundary-like bytes that do not start a line', async () => {
  const binary = Buffer.concat([
    Buffer.from('prefix '),
    Buffer.from(`--${BOUNDARY}`, 'latin1'), // not preceded by CRLF
    Buffer.from(' suffix'),
  ]);
  const parsed = await parse(
    multipart([
      { headers: { 'Content-Type': 'application/soap+xml', 'Content-ID': '<soap@x>' }, body: SOAP },
      { headers: { 'Content-Type': 'application/octet-stream', 'Content-ID': '<att@x>' }, body: binary },
    ]),
  );
  assert.equal(parsed.parts.length, 2);
  assert.deepEqual(parsed.parts[1]!.body, binary);
});

test('handles folded headers', async () => {
  const body = multipart([
    {
      headers: {
        'Content-Type': 'application/soap+xml',
        'Content-ID': '<soap@x>',
      },
      body: SOAP,
    },
  ]);
  // Fold the Content-Type value across a continuation line.
  const folded = Buffer.from(
    body.toString('latin1').replace('Content-Type: application/soap+xml', 'Content-Type: application/\r\n soap+xml'),
    'latin1',
  );
  const parsed = await parse(folded);
  assert.equal(parsed.parts[0]!.contentType, 'application/ soap+xml');
});

test('rejects a missing closing boundary', async () => {
  const truncated = Buffer.from(WELL_FORMED.toString('latin1').replace(`\r\n--${BOUNDARY}--\r\n`, '\r\n'), 'latin1');
  await assert.rejects(parse(truncated), (err) => err instanceof MimeFault && err.reason === 'mime.malformed');
});

test('rejects duplicate Content-IDs', async () => {
  const duplicate = multipart([
    { headers: { 'Content-Type': 'application/soap+xml', 'Content-ID': '<same@x>' }, body: SOAP },
    { headers: { 'Content-Type': 'application/octet-stream', 'Content-ID': '<same@x>' }, body: ATTACHMENT },
  ]);
  await assert.rejects(
    parse(duplicate),
    (err) => err instanceof MimeFault && err.reason === 'mime.duplicate-content-id',
  );
});

test('rejects too many parts and oversized headers', async () => {
  const many = multipart(Array.from({ length: 9 }, (_, i) => ({ headers: { 'Content-ID': `<p${i}@x>` }, body: 'x' })));
  await assert.rejects(parse(many), (err) => err instanceof MimeFault && err.reason === 'mime.parts-too-many');

  const bigHeader = multipart([{ headers: { 'Content-ID': `<${'a'.repeat(5000)}@x>` }, body: 'x' }]);
  await assert.rejects(parse(bigHeader), (err) => err instanceof MimeFault && err.reason === 'mime.header-too-large');
});

test('rejects a non-multipart content type and an unmatched start', async () => {
  await assert.rejects(
    parseMultipartRelated({ contentType: 'application/soap+xml', body: slices(WELL_FORMED, 10), limits: LIMITS }),
    (err) => err instanceof MimeFault && err.reason === 'mime.content-type-invalid',
  );

  const withStart = `multipart/related; boundary="${BOUNDARY}"; start="<missing@x>"`;
  const parsed = await parseMultipartRelated({
    contentType: withStart,
    body: slices(WELL_FORMED, 10),
    limits: LIMITS,
  });
  assert.equal(parsed.startContentId, 'missing@x');
  assert.throws(
    () => selectSoapPart(parsed),
    (err) => err instanceof MimeFault && err.reason === 'mime.no-soap-part',
  );
});

test('honours cancellation while reading the body', async () => {
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(
    parseMultipartRelated({
      contentType: CT,
      body: slices(WELL_FORMED, 10),
      limits: LIMITS,
      signal: controller.signal,
    }),
    (err) => err instanceof MimeFault && err.reason === 'aborted',
  );
});
