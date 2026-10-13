import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable, Writable } from 'node:stream';
import { MimeFault, type MimeLimits } from '../src/receive/mime.js';
import { multipartHooks, parseMultipartMessage, selectSoapPart } from '../src/receive/multipart.js';
import { defaultInboundLimits } from '../src/receive/types.js';

/**
 * Incremental multipart parsing: the SOAP part is buffered, attachments are
 * spooled, and limits/cancellation/cleanup behave as the buffered parser did —
 * but memory does not scale with the attachment.
 */
const BOUNDARY = 'as4-boundary';
const CT = `multipart/related; type="application/soap+xml"; boundary="${BOUNDARY}"`;
const SOAP_XML = Buffer.from('<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope"/>', 'utf8');

const LIMITS: MimeLimits = {
  maxRequestBytes: defaultInboundLimits.maxRequestBytes,
  maxParts: defaultInboundLimits.maxParts,
  maxHeaderBytes: defaultInboundLimits.maxHeaderBytes,
  maxPartBytes: defaultInboundLimits.maxPartBytes,
  maxBoundaryLength: defaultInboundLimits.maxBoundaryLength,
};

interface Part {
  readonly headers: Record<string, string>;
  readonly body: Buffer;
}

function multipart(parts: readonly Part[]): Buffer {
  const chunks: Buffer[] = [];
  for (const part of parts) {
    chunks.push(Buffer.from(`--${BOUNDARY}\r\n`, 'latin1'));
    for (const [name, value] of Object.entries(part.headers))
      chunks.push(Buffer.from(`${name}: ${value}\r\n`, 'latin1'));
    chunks.push(Buffer.from('\r\n', 'latin1'));
    chunks.push(part.body);
    chunks.push(Buffer.from('\r\n', 'latin1'));
  }
  chunks.push(Buffer.from(`--${BOUNDARY}--\r\n`, 'latin1'));
  return Buffer.concat(chunks);
}

const soapPart = (): Part => ({
  headers: { 'Content-Type': 'application/soap+xml', 'Content-ID': '<soap@x>' },
  body: SOAP_XML,
});
const attachment = (body: Buffer): Part => ({
  headers: { 'Content-Type': 'application/octet-stream', 'Content-ID': '<att@x>' },
  body,
});

function parse(
  body: AsyncIterable<Uint8Array> | Buffer,
  overrides: Partial<MimeLimits> = {},
  extra: { signal?: AbortSignal; spoolDirectory?: string } = {},
) {
  const iterable = Buffer.isBuffer(body) ? Readable.from([body]) : body;
  return parseMultipartMessage({
    contentType: CT,
    body: iterable,
    limits: { ...LIMITS, ...overrides },
    ...extra,
  });
}

async function readAll(stream: Readable): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(Buffer.from(chunk as Uint8Array));
  return Buffer.concat(chunks);
}

function manualStream(options: { stallReturn?: boolean } = {}) {
  const queue: Buffer[] = [];
  let resolveNext: (() => void) | null = null;
  let closed = false;
  let returned = false;
  const body: AsyncIterable<Uint8Array> = {
    [Symbol.asyncIterator]() {
      return {
        async next(): Promise<IteratorResult<Uint8Array>> {
          for (;;) {
            if (queue.length > 0) return { value: queue.shift()!, done: false };
            if (closed) return { value: undefined, done: true };
            await new Promise<void>((resolve) => {
              resolveNext = resolve;
            });
          }
        },
        return(): Promise<IteratorResult<Uint8Array>> {
          returned = true;
          closed = true;
          resolveNext?.();
          return options.stallReturn ? new Promise(() => {}) : Promise.resolve({ value: undefined, done: true });
        },
      };
    },
  };
  return {
    body,
    push(chunk: Buffer): void {
      queue.push(chunk);
      resolveNext?.();
      resolveNext = null;
    },
    end(): void {
      closed = true;
      resolveNext?.();
      resolveNext = null;
    },
    wasReturned: (): boolean => returned,
  };
}

test('buffers the SOAP part and spools the attachment', async () => {
  const dir = await mkdtempSync(join(tmpdir(), 'as4-mp-'));
  try {
    const attachmentBody = Buffer.from('hello attachment');
    const message = await parse(multipart([soapPart(), attachment(attachmentBody)]), {}, { spoolDirectory: dir });
    try {
      assert.equal(message.parts.length, 2);
      const soap = selectSoapPart(message);
      assert.equal(soap.spoolPath, null);
      assert.deepEqual(await readAll(soap.read()), SOAP_XML);

      const part = message.parts.find((candidate) => candidate !== soap)!;
      assert.notEqual(part.spoolPath, null);
      assert.equal(part.byteLength, attachmentBody.length);
      assert.deepEqual(await readAll(part.read()), attachmentBody);

      // Ownership transfer: a matching Content-ID hands the spool over.
      const path = message.takeSpool(part, 'att@x');
      assert.equal(path, part.spoolPath);
      assert.equal(message.takeSpool(part, 'wrong@x'), null);
      await message.dispose();
      assert.equal(existsSync(path!), true, 'a taken spool survives dispose');
      rmSync(path!, { force: true });
    } finally {
      await message.dispose();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('spools an attachment that precedes the SOAP root', async () => {
  const message = await parse(multipart([attachment(Buffer.from('first')), soapPart()]));
  try {
    const soap = selectSoapPart(message);
    assert.deepEqual(await readAll(soap.read()), SOAP_XML);
    assert.equal(message.parts[0]!.spoolPath !== null, true, 'the attachment is spooled, not buffered');
  } finally {
    await message.dispose();
  }
});

test('selects the start part when the request names it', async () => {
  const second: Part = {
    headers: { 'Content-Type': 'application/soap+xml', 'Content-ID': '<other@x>' },
    body: Buffer.from('<b/>'),
  };
  const withStart = `multipart/related; boundary="${BOUNDARY}"; start="<other@x>"`;
  const message = await parseMultipartMessage({
    contentType: withStart,
    body: Readable.from([multipart([soapPart(), second])]),
    limits: LIMITS,
  });
  try {
    const soap = selectSoapPart(message);
    assert.equal(soap.contentId, 'other@x');
  } finally {
    await message.dispose();
  }
});

test('spools a large attachment delivered in small chunks', async () => {
  const size = 2 * 1024 * 1024;
  const body = Buffer.alloc(size, 0x42);
  const full = multipart([soapPart(), attachment(body)]);
  async function* chunked() {
    for (let offset = 0; offset < full.length; offset += 4096) yield full.subarray(offset, offset + 4096);
  }
  const message = await parse(chunked());
  try {
    const part = message.parts.find((candidate) => candidate.spoolPath !== null)!;
    assert.equal(part.byteLength, size);
    const recovered = await readAll(part.read());
    assert.equal(recovered.length, size);
    assert.equal(recovered[0], 0x42);
  } finally {
    await message.dispose();
  }
});

test('applies the part limit mid-part and removes the spool', async () => {
  const dir = await mkdtempSync(join(tmpdir(), 'as4-mp-'));
  try {
    await assert.rejects(
      parse(multipart([soapPart(), attachment(Buffer.alloc(4096))]), { maxPartBytes: 16 }, { spoolDirectory: dir }),
      (err) => err instanceof MimeFault && err.reason === 'mime.part-too-large',
    );
    assert.deepEqual(readdirSync(dir), [], 'no spool survives a mid-part failure');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('rejects more parts than the limit', async () => {
  await assert.rejects(
    parse(multipart([soapPart(), attachment(Buffer.from('a')), attachment(Buffer.from('b'))]), { maxParts: 2 }),
    (err) => err instanceof MimeFault && err.reason === 'mime.parts-too-many',
  );
});

test('rejects a duplicate Content-ID', async () => {
  const second: Part = {
    headers: { 'Content-Type': 'application/octet-stream', 'Content-ID': '<att@x>' },
    body: Buffer.from('x'),
  };
  await assert.rejects(
    parse(multipart([soapPart(), attachment(Buffer.from('a')), second])),
    (err) => err instanceof MimeFault && err.reason === 'mime.duplicate-content-id',
  );
});

test('rejects a missing closing boundary', async () => {
  const noClosing = Buffer.concat([
    Buffer.from(`--${BOUNDARY}\r\nContent-Type: application/soap+xml\r\n\r\n`, 'latin1'),
    SOAP_XML,
    Buffer.from('\r\n', 'latin1'),
  ]);
  await assert.rejects(parse(noClosing), (err) => err instanceof MimeFault && err.reason === 'mime.malformed');
});

test('cancellation mid-header and mid-part is a value, not a hang', async () => {
  const stream = manualStream();
  const controller = new AbortController();
  const pending = parse(stream.body, {}, { signal: controller.signal });
  stream.push(Buffer.from(`--${BOUNDARY}\r\nContent-Type: application/soap`, 'latin1'));
  setTimeout(() => controller.abort(), 10);
  await assert.rejects(pending, (err) => err instanceof MimeFault && err.reason === 'aborted');
  assert.ok(stream.wasReturned(), 'the source was cleaned up');

  const stream2 = manualStream();
  const controller2 = new AbortController();
  const pending2 = parse(stream2.body, {}, { signal: controller2.signal });
  stream2.push(multipart([soapPart(), attachment(Buffer.alloc(4096))]).subarray(0, 120));
  setTimeout(() => controller2.abort(), 10);
  await assert.rejects(pending2, (err) => err instanceof MimeFault && err.reason === 'aborted');
});

test('a stalled source return() cannot prevent failure completion', async () => {
  const stream = manualStream({ stallReturn: true });
  const pending = parse(stream.body, { maxPartBytes: 8 });
  stream.push(multipart([soapPart(), attachment(Buffer.alloc(4096))]));
  await assert.rejects(pending, (err) => err instanceof MimeFault && err.reason === 'mime.part-too-large');
  assert.ok(stream.wasReturned(), 'the stalled source was signalled for cleanup');
});

test('ciphertext reaches its spool before the request finishes', async () => {
  const dir = await mkdtempSync(join(tmpdir(), 'as4-mp-'));
  try {
    const full = multipart([soapPart(), attachment(Buffer.alloc(8192, 0x7a))]);
    const split = Math.floor(full.length * 0.75); // inside the attachment body
    const stream = manualStream();
    const pending = parse(stream.body, {}, { spoolDirectory: dir });
    stream.push(full.subarray(0, split));
    await new Promise((resolve) => setTimeout(resolve, 20));
    const files = readdirSync(dir);
    assert.equal(files.length, 1, 'the attachment spool exists mid-request');
    assert.ok(readFileSync(join(dir, files[0]!)).length > 0, 'bytes reached the spool before the request finished');
    stream.push(full.subarray(split));
    stream.end();
    const message = await pending;
    await message.dispose();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('slow storage applies backpressure (one write in flight)', async () => {
  let active = 0;
  let maxActive = 0;
  const slow = new Writable({
    write(_chunk, _encoding, callback) {
      active += 1;
      maxActive = Math.max(maxActive, active);
      setTimeout(() => {
        active -= 1;
        callback();
      }, 1);
    },
  });
  multipartHooks.createSpoolWriter = () => slow;
  try {
    const full = multipart([soapPart(), attachment(Buffer.alloc(64 * 1024, 0x5a))]);
    async function* chunked() {
      for (let offset = 0; offset < full.length; offset += 1024) yield full.subarray(offset, offset + 1024);
    }
    const message = await parse(chunked());
    await message.dispose();
    assert.equal(maxActive, 1, 'the parser awaits each write instead of buffering the attachment');
  } finally {
    delete multipartHooks.createSpoolWriter;
  }
});
