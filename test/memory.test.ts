import test from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { createServer } from 'node:https';
import type { AddressInfo } from 'node:net';
import { sendAs4 } from '../src/index.js';
import { createTestPki, createTlsServerCert } from './helpers/pki.js';
import { baseInput } from './helpers/input.js';

const MEGABYTE = 1024 * 1024;
const TOTAL_MB = Number(process.env['AS4_LARGE_MB'] ?? 384);

/** A stream that yields `totalBytes` without ever holding them in memory. */
function generatedPayload(totalBytes: number): Readable {
  // One incompressible block, reused. Keeps gzip from collapsing the payload so
  // the byte counts on the wire are meaningful.
  const block = Buffer.alloc(64 * 1024);
  let seed = 0x12345678;
  for (let i = 0; i < block.length; i += 1) {
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    block[i] = seed & 0xff;
  }
  let sent = 0;
  return new Readable({
    read() {
      if (sent >= totalBytes) {
        this.push(null);
        return;
      }
      const remaining = totalBytes - sent;
      const size = Math.min(block.length, remaining);
      sent += size;
      this.push(size === block.length ? block : block.subarray(0, size));
    },
  });
}

test('streams a several-hundred-megabyte payload with flat memory', { timeout: 600_000 }, async () => {
  const pki = createTestPki();
  const tls = createTlsServerCert();
  let received = 0;
  const server = createServer({ cert: tls.certPem, key: tls.keyPem }, (req, res) => {
    req.on('data', (chunk: Buffer) => {
      received += chunk.length;
    });
    req.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('');
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;

  const totalBytes = TOTAL_MB * MEGABYTE;
  const samples: number[] = [];
  const baseline = process.memoryUsage().heapUsed;
  const sampler = setInterval(() => samples.push(process.memoryUsage().heapUsed), 100);

  try {
    const result = await sendAs4(
      baseInput(pki, `https://localhost:${port}/as4`, tls.caPem, {
        payload: generatedPayload(totalBytes),
        http: { connectMs: 10_000, totalMs: 570_000, ca: [tls.caPem] },
      }),
    );
    clearInterval(sampler);
    const peak = Math.max(baseline, ...samples);
    const growthMb = (peak - baseline) / MEGABYTE;
    // Streaming through gzip, hash, AES-GCM and the temp file must not buffer the
    // payload. If it did, heap growth would be on the order of the payload size.
    assert.ok(growthMb < 200, `heap grew by ${growthMb.toFixed(1)} MB, expected flat`);
    assert.ok(received > totalBytes * 0.9, `receiver saw ${received} of ${totalBytes} bytes`);
    assert.equal(result.outcome, 'no-signal');
  } finally {
    clearInterval(sampler);
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
