import test from 'node:test';
import assert from 'node:assert/strict';
import { appendFileSync, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable, Writable } from 'node:stream';
import { MimeFault, type MimeLimits } from '../src/receive/mime.js';
import { multipartHooks, parseMultipartMessage, selectSoapPart } from '../src/receive/multipart.js';
import { defaultInboundLimits } from '../src/receive/types.js';

/**
 * Incremental multipart parsing: the SOAP part is buffered under the envelope
 * budget, attachments are spooled, and limits/cancellation/cleanup/writer failure
 * behave as required — memory does not scale with the attachment.
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

function multipart(parts: readonly Part[], epilogue = ''): Buffer {
  const chunks: Buffer[] = [];
  for (const part of parts) {
    chunks.push(Buffer.from(`--${BOUNDARY}\r\n`, 'latin1'));
    for (const [name, value] of Object.entries(part.headers))
      chunks.push(Buffer.from(`${name}: ${value}\r\n`, 'latin1'));
    chunks.push(Buffer.from('\r\n', 'latin1'));
    chunks.push(part.body);
    chunks.push(Buffer.from('\r\n', 'latin1'));
  }
  chunks.push(Buffer.from(`--${BOUNDARY}--\r\n${epilogue}`, 'latin1'));
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

/** The request body through the attachment's header terminator, with no body bytes. */
function headersOnly(): Buffer {
  const full = multipart([soapPart(), attachment(Buffer.alloc(0))]);
  const first = full.indexOf('\r\n\r\n');
  const second = full.indexOf('\r\n\r\n', first + 4);
  return full.subarray(0, second + 4);
}

function isAsyncIterable(value: unknown): value is AsyncIterable<Uint8Array> {
  return typeof (value as { [Symbol.asyncIterator]?: unknown })[Symbol.asyncIterator] === 'function';
}

function parse(
  body: AsyncIterable<Uint8Array> | Buffer | readonly Buffer[],
  overrides: Partial<MimeLimits> = {},
  extra: { signal?: AbortSignal; spoolDirectory?: string; maxEnvelopeBytes?: number } = {},
) {
  const iterable = isAsyncIterable(body) ? body : Readable.from(body);
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
  const dir = mkdtempSync(join(tmpdir(), 'as4-mp-'));
  const dest = mkdtempSync(join(tmpdir(), 'as4-mp-dest-'));
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

      // A wrong Content-ID must not transfer ownership.
      assert.equal(await message.transferSpool(part, 'wrong@x', join(dest, 'c')), null);
      const moved = await message.transferSpool(part, 'att@x', join(dest, 'ciphertext.bin'));
      assert.notEqual(moved, null);
      assert.deepEqual(readFileSync(moved!), attachmentBody);
      await message.dispose();
      assert.equal(existsSync(moved!), true, 'a transferred spool survives dispose');
    } finally {
      await message.dispose();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
    rmSync(dest, { recursive: true, force: true });
  }
});

test('a transferred spool survives dispose of the default private directory', async () => {
  const dest = mkdtempSync(join(tmpdir(), 'as4-mp-dest-'));
  try {
    const message = await parse(multipart([soapPart(), attachment(Buffer.from('payload'))]));
    try {
      const part = message.parts.find((candidate) => candidate.spoolPath !== null)!;
      const moved = await message.transferSpool(part, 'att@x', join(dest, 'ciphertext.bin'));
      assert.notEqual(moved, null);
      await message.dispose(); // removes the parser's private directory
      assert.equal(existsSync(moved!), true, 'the moved file is not deleted with the private directory');
    } finally {
      await message.dispose();
    }
  } finally {
    rmSync(dest, { recursive: true, force: true });
  }
});

test('a failed transfer keeps ownership and dispose cleans up', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'as4-mp-'));
  try {
    const message = await parse(
      multipart([soapPart(), attachment(Buffer.from('payload'))]),
      {},
      { spoolDirectory: dir },
    );
    try {
      const part = message.parts.find((candidate) => candidate.spoolPath !== null)!;
      // A destination in a directory that does not exist makes the rename fail.
      const moved = await message.transferSpool(part, 'att@x', join(dir, 'missing', 'ciphertext.bin'));
      assert.equal(moved, null, 'a failed move returns null and the parser keeps ownership');
      assert.equal(existsSync(part.spoolPath!), true);
      await message.dispose();
      assert.equal(existsSync(part.spoolPath!), false, 'the retained spool is deleted on dispose');
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
    assert.equal(selectSoapPart(message).contentId, 'other@x');
  } finally {
    await message.dispose();
  }
});

test('spools a large attachment delivered in small chunks', async () => {
  const size = 2 * 1024 * 1024;
  const full = multipart([soapPart(), attachment(Buffer.alloc(size, 0x42))]);
  async function* chunked() {
    for (let offset = 0; offset < full.length; offset += 4096) yield full.subarray(offset, offset + 4096);
  }
  const message = await parse(chunked());
  try {
    const part = message.parts.find((candidate) => candidate.spoolPath !== null)!;
    assert.equal(part.byteLength, size);
    assert.equal((await readAll(part.read())).length, size);
  } finally {
    await message.dispose();
  }
});

test('exceeding the attachment limit mid-part removes the spool', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'as4-mp-'));
  try {
    // Allow the SOAP part (so no spool exists yet for it) and fail on the
    // attachment, after its spool has been created and written to.
    const maxPartBytes = SOAP_XML.length + 64;
    await assert.rejects(
      parse(multipart([soapPart(), attachment(Buffer.alloc(8192))]), { maxPartBytes }, { spoolDirectory: dir }),
      (err) => err instanceof MimeFault && err.reason === 'mime.part-too-large',
    );
    assert.deepEqual(readdirSync(dir), [], 'no spool survives an attachment failure');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('bounds the SOAP envelope while buffering', async () => {
  const bigSoap: Part = {
    headers: { 'Content-Type': 'application/soap+xml', 'Content-ID': '<soap@x>' },
    body: Buffer.alloc(4096, 0x3c),
  };
  await assert.rejects(
    parse(multipart([bigSoap, attachment(Buffer.from('x'))]), {}, { maxEnvelopeBytes: 1024 }),
    (err) => err instanceof MimeFault && err.reason === 'xml.too-large',
  );
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

test('discards a large epilogue without retaining it', async () => {
  let maxRetained = 0;
  multipartHooks.onRetained = (bytes) => {
    maxRetained = Math.max(maxRetained, bytes);
  };
  try {
    const epilogue = 'x'.repeat(1024 * 1024);
    const full = multipart([soapPart(), attachment(Buffer.from('body'))], epilogue);
    async function* chunked() {
      for (let offset = 0; offset < full.length; offset += 4096) yield full.subarray(offset, offset + 4096);
    }
    const message = await parse(chunked());
    await message.dispose();
    assert.equal(message.parts.length, 2);
    assert.ok(maxRetained < 16 * 1024, `retained bytes stayed bounded (peaked at ${maxRetained})`);
  } finally {
    delete multipartHooks.onRetained;
  }
});

test('accepts long transport padding without retaining it', async () => {
  let maxRetained = 0;
  multipartHooks.onRetained = (bytes) => {
    maxRetained = Math.max(maxRetained, bytes);
  };
  try {
    const padding = ' '.repeat(64 * 1024);
    const body = Buffer.concat([
      Buffer.from(`--${BOUNDARY}\r\nContent-Type: application/soap+xml\r\nContent-ID: <soap@x>\r\n\r\n`, 'latin1'),
      SOAP_XML,
      Buffer.from(
        `\r\n--${BOUNDARY}${padding}\r\nContent-Type: application/octet-stream\r\nContent-ID: <att@x>\r\n\r\n`,
        'latin1',
      ),
      Buffer.from('body'),
      Buffer.from(`\r\n--${BOUNDARY}${padding}--\r\n`, 'latin1'),
    ]);
    async function* chunked() {
      for (let offset = 0; offset < body.length; offset += 4096) yield body.subarray(offset, offset + 4096);
    }
    const message = await parse(chunked());
    await message.dispose();
    assert.equal(message.parts.length, 2);
    assert.ok(maxRetained < 16 * 1024, `retained bytes stayed bounded (peaked at ${maxRetained})`);
  } finally {
    delete multipartHooks.onRetained;
  }
});

test('header acceptance does not depend on chunk boundaries', async () => {
  const headers = { 'Content-Type': 'application/soap+xml', 'Content-ID': '<soap@x>', 'X-Pad': 'a'.repeat(40) };
  const full = multipart([{ headers, body: SOAP_XML }, attachment(Buffer.from('x'))]);
  // The first `\r\n\r\n` ends the SOAP part's header block; subtract the leading
  // delimiter line to get the header block length itself.
  const blockLength = full.indexOf('\r\n\r\n') - Buffer.byteLength(`--${BOUNDARY}\r\n`, 'latin1');
  for (let split = 1; split < full.length; split += 1) {
    const chunks = [full.subarray(0, split), full.subarray(split)];
    const message = await parse(chunks, { maxHeaderBytes: blockLength });
    await message.dispose();
    await assert.rejects(
      parse(chunks, { maxHeaderBytes: blockLength - 1 }),
      (err) => err instanceof MimeFault && err.reason === 'mime.header-too-large',
      `split at ${split}`,
    );
  }
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
  const pending = parse(stream.body, { maxPartBytes: SOAP_XML.length + 64 });
  stream.push(multipart([soapPart(), attachment(Buffer.alloc(4096))]));
  await assert.rejects(pending, (err) => err instanceof MimeFault && err.reason === 'mime.part-too-large');
  assert.ok(stream.wasReturned(), 'the stalled source was signalled for cleanup');
});

test('a spool write failure is a value, not a crash', async () => {
  multipartHooks.createSpoolWriter = () =>
    new Writable({
      write(_chunk, _encoding, callback) {
        callback(new Error('disk full'));
      },
    });
  try {
    await assert.rejects(
      parse(multipart([soapPart(), attachment(Buffer.alloc(4096))])),
      (err) => err instanceof Error && /disk full/.test(err.message),
    );
  } finally {
    delete multipartHooks.createSpoolWriter;
  }
});

test('a spool open failure is a value', async () => {
  multipartHooks.createSpoolWriter = () => {
    const writer = new Writable({
      write(_chunk, _encoding, callback) {
        callback();
      },
    });
    process.nextTick(() => writer.destroy(new Error('EACCES: cannot open spool')));
    return writer;
  };
  try {
    await assert.rejects(
      parse(multipart([soapPart(), attachment(Buffer.alloc(4096))])),
      (err) => err instanceof Error && /EACCES/.test(err.message),
    );
  } finally {
    delete multipartHooks.createSpoolWriter;
  }
});

test('cancellation interrupts a stalled write', async () => {
  multipartHooks.createSpoolWriter = () => new Writable({ write(_chunk, _encoding, _callback) {} });
  try {
    const stream = manualStream();
    const controller = new AbortController();
    const pending = parse(stream.body, {}, { signal: controller.signal });
    stream.push(multipart([soapPart(), attachment(Buffer.alloc(4096))]));
    setTimeout(() => controller.abort(), 20);
    await assert.rejects(pending, (err) => err instanceof MimeFault && err.reason === 'aborted');
  } finally {
    delete multipartHooks.createSpoolWriter;
  }
});

test('cancellation interrupts a stalled finalisation', async () => {
  multipartHooks.createSpoolWriter = () =>
    new Writable({
      write(_chunk, _encoding, callback) {
        callback();
      },
      final(_callback) {
        // never finalises
      },
    });
  try {
    const stream = manualStream();
    const controller = new AbortController();
    const pending = parse(stream.body, {}, { signal: controller.signal });
    stream.push(multipart([soapPart(), attachment(Buffer.from('small'))]));
    stream.end();
    setTimeout(() => controller.abort(), 20);
    await assert.rejects(pending, (err) => err instanceof MimeFault && err.reason === 'aborted');
  } finally {
    delete multipartHooks.createSpoolWriter;
  }
});

test('ciphertext reaches its spool before the request finishes', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'as4-mp-'));
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

test('backpressure bounds read-ahead until storage resumes', async () => {
  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  let firstWrite = true;
  multipartHooks.createSpoolWriter = () =>
    new Writable({
      write(_chunk, _encoding, callback) {
        if (firstWrite) {
          firstWrite = false;
          void gate.then(() => callback());
        } else {
          callback();
        }
      },
    });
  try {
    const full = multipart([soapPart(), attachment(Buffer.alloc(512 * 1024, 0x5a))]);
    const totalChunks = Math.ceil(full.length / 1024);
    let pulled = 0;
    async function* source() {
      for (let offset = 0; offset < full.length; offset += 1024) {
        pulled += 1;
        yield full.subarray(offset, offset + 1024);
      }
    }
    const pending = parse(source());
    await new Promise((resolve) => setTimeout(resolve, 20));
    const pulledWhileStalled = pulled;
    assert.ok(
      pulledWhileStalled < totalChunks / 2,
      `read-ahead stayed bounded (${pulledWhileStalled}/${totalChunks} chunks pulled while storage was stalled)`,
    );
    release();
    const message = await pending;
    await message.dispose();
    assert.equal(pulled, totalChunks, 'the source is drained once storage resumes');
  } finally {
    delete multipartHooks.createSpoolWriter;
  }
});

test('the per-part bound applies to the SOAP part, in both limit orderings', async () => {
  const soap = (size: number): Part => ({
    headers: { 'Content-Type': 'application/soap+xml', 'Content-ID': '<soap@x>' },
    body: Buffer.alloc(size, 0x20),
  });
  const withAttachment = (soapSize: number): Buffer => multipart([soap(soapSize), attachment(Buffer.from('x'))]);

  // maxPartBytes is the tighter bound.
  await assert.rejects(
    parse(withAttachment(20), { maxPartBytes: 8 }, { maxEnvelopeBytes: 1024 }),
    (err) => err instanceof MimeFault && err.reason === 'mime.part-too-large',
  );
  // maxEnvelopeBytes is the tighter bound.
  await assert.rejects(
    parse(withAttachment(20), { maxPartBytes: 1024 }, { maxEnvelopeBytes: 8 }),
    (err) => err instanceof MimeFault && err.reason === 'xml.too-large',
  );
  // Exact boundaries: size == cap passes, size == cap + 1 fails.
  const atLimit = await parse(withAttachment(16), { maxPartBytes: 16 }, { maxEnvelopeBytes: 1024 });
  await atLimit.dispose();
  await assert.rejects(
    parse(withAttachment(17), { maxPartBytes: 16 }, { maxEnvelopeBytes: 1024 }),
    (err) => err instanceof MimeFault && err.reason === 'mime.part-too-large',
  );
  const atEnvelope = await parse(withAttachment(16), { maxPartBytes: 1024 }, { maxEnvelopeBytes: 16 });
  await atEnvelope.dispose();
  await assert.rejects(
    parse(withAttachment(17), { maxPartBytes: 1024 }, { maxEnvelopeBytes: 16 }),
    (err) => err instanceof MimeFault && err.reason === 'xml.too-large',
  );
});

test('cleanup unlinks only after the writer has actually closed (delayed open)', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'as4-mp-'));
  multipartHooks.createSpoolWriter = (path) =>
    new Writable({
      write(_chunk, _encoding, callback) {
        callback();
      },
      // Simulate an open that completes only on destroy, creating the file late.
      destroy(error, callback) {
        setTimeout(() => {
          try {
            writeFileSync(path, 'late');
          } catch {
            // ignore
          }
          callback(error ?? null);
        }, 30);
      },
    });
  try {
    const stream = manualStream();
    const controller = new AbortController();
    const pending = parse(stream.body, {}, { spoolDirectory: dir, signal: controller.signal });
    stream.push(headersOnly());
    setTimeout(() => controller.abort(), 10);
    await assert.rejects(pending, (err) => err instanceof MimeFault && err.reason === 'aborted');
    await new Promise((resolve) => setTimeout(resolve, 80)); // let the late open/close complete
    assert.deepEqual(readdirSync(dir), [], 'a late-created spool is unlinked after the writer closes');
  } finally {
    delete multipartHooks.createSpoolWriter;
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a writer failure with no pending write interrupts the parser', async () => {
  multipartHooks.createSpoolWriter = () => {
    const writer = new Writable({
      write(_chunk, _encoding, callback) {
        callback();
      },
    });
    setTimeout(() => writer.destroy(new Error('storage failed')), 10);
    return writer;
  };
  try {
    const stream = manualStream();
    const pending = parse(stream.body); // no caller signal: the failure must interrupt
    stream.push(headersOnly());
    await assert.rejects(pending, (err) => err instanceof Error && /storage failed/.test(err.message));
    assert.ok(stream.wasReturned(), 'the source was signalled for cleanup');
  } finally {
    delete multipartHooks.createSpoolWriter;
  }
});

test('a delayed successful close delays parser success', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'as4-mp-'));
  let writerClosed = false;
  multipartHooks.createSpoolWriter = (path) => {
    const writer = new Writable({
      write(chunk, _encoding, callback) {
        appendFileSync(path, chunk);
        callback();
      },
      // 'finish' fires immediately; actual filesystem closure is delayed.
      destroy(error, callback) {
        setTimeout(() => callback(error ?? null), 50);
      },
    });
    writer.on('close', () => {
      writerClosed = true;
    });
    return writer;
  };
  try {
    const message = await parse(
      multipart([soapPart(), attachment(Buffer.from('payload'))]),
      {},
      { spoolDirectory: dir },
    );
    await message.dispose();
    assert.equal(writerClosed, true, 'the parser waits for actual writer closure before succeeding');
  } finally {
    delete multipartHooks.createSpoolWriter;
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a delayed failing close rejects parsing and cleans up', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'as4-mp-'));
  multipartHooks.createSpoolWriter = (path) =>
    new Writable({
      write(chunk, _encoding, callback) {
        appendFileSync(path, chunk);
        callback();
      },
      destroy(_error, callback) {
        setTimeout(() => callback(new Error('late filesystem close failure')), 50);
      },
    });
  try {
    await assert.rejects(
      parse(multipart([soapPart(), attachment(Buffer.from('payload'))]), {}, { spoolDirectory: dir }),
      (err) => err instanceof Error && /late filesystem close failure/.test(err.message),
    );
    assert.deepEqual(readdirSync(dir), [], 'the spool is removed after a close failure');
  } finally {
    delete multipartHooks.createSpoolWriter;
    rmSync(dir, { recursive: true, force: true });
  }
});
