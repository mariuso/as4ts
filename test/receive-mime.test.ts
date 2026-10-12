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

/** A body iterator the test drives by hand, to stall a read and observe cleanup. */
function manualStream(): {
  body: AsyncIterable<Uint8Array>;
  push: (chunk: Buffer) => void;
  wasReturned: () => boolean;
} {
  const queue: Buffer[] = [];
  let pending: ((result: IteratorResult<Uint8Array>) => void) | null = null;
  let finished = false;
  let returned = false;
  const body: AsyncIterable<Uint8Array> = {
    [Symbol.asyncIterator]() {
      return {
        next(): Promise<IteratorResult<Uint8Array>> {
          const queued = queue.shift();
          if (queued) return Promise.resolve({ value: queued, done: false });
          if (finished) return Promise.resolve({ value: undefined, done: true });
          return new Promise((resolve) => {
            pending = resolve;
          });
        },
        return(): Promise<IteratorResult<Uint8Array>> {
          returned = true;
          finished = true;
          pending?.({ value: undefined, done: true });
          pending = null;
          return Promise.resolve({ value: undefined, done: true });
        },
      };
    },
  };
  return {
    body,
    push: (chunk: Buffer) => {
      if (pending) {
        const resolve = pending;
        pending = null;
        resolve({ value: chunk, done: false });
      } else {
        queue.push(chunk);
      }
    },
    wasReturned: () => returned,
  };
}

test('cancellation interrupts a stalled read before the first chunk', async () => {
  const stream = manualStream();
  const controller = new AbortController();
  const pending = parseMultipartRelated({
    contentType: CT,
    body: stream.body,
    limits: LIMITS,
    signal: controller.signal,
  });
  setTimeout(() => controller.abort(), 10);
  await assert.rejects(pending, (err) => err instanceof MimeFault && err.reason === 'aborted');
  assert.ok(stream.wasReturned(), 'the source is cleaned up on abort');
});

test('cancellation interrupts a read stalled between chunks', async () => {
  const stream = manualStream();
  const controller = new AbortController();
  const pending = parseMultipartRelated({
    contentType: CT,
    body: stream.body,
    limits: LIMITS,
    signal: controller.signal,
  });
  stream.push(Buffer.from(`--${BOUNDARY}\r\nContent-Type: application/soap+xml\r\n\r\n<a/>`, 'latin1'));
  setTimeout(() => controller.abort(), 10);
  await assert.rejects(pending, (err) => err instanceof MimeFault && err.reason === 'aborted');
  assert.ok(stream.wasReturned(), 'the source is cleaned up on abort');
});

test('rejects an ambiguous root (two SOAP parts)', async () => {
  const body = multipart([
    { headers: { 'Content-Type': 'application/soap+xml' }, body: SOAP },
    { headers: { 'Content-Type': 'application/soap+xml' }, body: SOAP },
  ]);
  const parsed = await parse(body);
  assert.throws(
    () => selectSoapPart(parsed),
    (err) => err instanceof MimeFault && err.reason === 'mime.ambiguous-root',
  );
});

test('rejects a start parameter that does not name a SOAP part', async () => {
  const body = multipart([
    { headers: { 'Content-Type': 'application/soap+xml', 'Content-ID': '<soap@x>' }, body: SOAP },
    { headers: { 'Content-Type': 'application/octet-stream', 'Content-ID': '<att@x>' }, body: 'x' },
  ]);
  const parsed = await parseMultipartRelated({
    contentType: `multipart/related; boundary="${BOUNDARY}"; start="<att@x>"`,
    body: slices(body, 10),
    limits: LIMITS,
  });
  assert.throws(
    () => selectSoapPart(parsed),
    (err) => err instanceof MimeFault && err.reason === 'mime.no-soap-part',
  );
});

test('rejects a duplicate header within a part', async () => {
  const body = Buffer.from(
    `--${BOUNDARY}\r\nContent-Type: application/soap+xml\r\nContent-Type: text/plain\r\n\r\n<a/>\r\n--${BOUNDARY}--\r\n`,
    'latin1',
  );
  await assert.rejects(parse(body), (err) => err instanceof MimeFault && err.reason === 'mime.duplicate-header');
});

test('does not accept a mis-named boundary parameter', async () => {
  await assert.rejects(
    parseMultipartRelated({
      contentType: `multipart/related; notboundary="${BOUNDARY}"`,
      body: slices(WELL_FORMED, 10),
      limits: LIMITS,
    }),
    (err) => err instanceof MimeFault && err.reason === 'mime.boundary-invalid',
  );
});

test('stops at the first closing delimiter and ignores the epilogue', async () => {
  const withEpilogue = Buffer.concat([
    WELL_FORMED,
    Buffer.from(`\r\n--${BOUNDARY}\r\nContent-Type: text/plain\r\n\r\nignored`, 'latin1'),
  ]);
  const parsed = await parse(withEpilogue);
  assert.equal(parsed.parts.length, 2);
});
