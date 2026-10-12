import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { Readable } from 'node:stream';
import { sendAs4, signerFromKey, type ValidateCertificate } from '../src/index.js';
import { createTestPki, createTlsServerCert } from './helpers/pki.js';
import { startFakeReceiver } from './helpers/fake-receiver.js';
import { baseInput } from './helpers/input.js';

async function withSpoolDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), 'as4-abort-'));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

function abortingValidator(): ValidateCertificate {
  return (input) =>
    new Promise((_resolve, reject) => {
      input.signal?.addEventListener('abort', () => {
        const err = new Error('aborted');
        err.name = 'AbortError';
        reject(err);
      });
    });
}

function gushingPayload(): Readable {
  return new Readable({
    read() {
      this.push(Buffer.alloc(64 * 1024, 1));
    },
  });
}

test('abort before the send: nothing is spooled and no temp files remain', async () => {
  await withSpoolDir(async (dir) => {
    const pki = createTestPki();
    const result = await sendAs4(
      baseInput(pki, 'https://localhost:1/as4', null, {
        signal: AbortSignal.abort(),
        spoolDirectory: dir,
      }),
    );
    assert.equal(result.outcome, 'not-sent');
    if (result.outcome === 'not-sent') assert.equal(result.reason, 'aborted');
    assert.deepEqual(await readdir(dir), []);
  });
});

test('abort during validation: never sends, no temp files', async () => {
  await withSpoolDir(async (dir) => {
    const pki = createTestPki();
    const controller = new AbortController();
    const pending = sendAs4(
      baseInput(pki, 'https://localhost:1/as4', null, {
        signal: controller.signal,
        spoolDirectory: dir,
        validateCertificate: abortingValidator(),
      }),
    );
    setTimeout(() => controller.abort(), 10);
    const result = await pending;
    assert.equal(result.outcome, 'not-sent');
    if (result.outcome === 'not-sent') assert.equal(result.reason, 'aborted');
    assert.deepEqual(await readdir(dir), []);
  });
});

test('abort during spooling: stops the pipeline and removes the temp files', async () => {
  await withSpoolDir(async (dir) => {
    const pki = createTestPki();
    const controller = new AbortController();
    const pending = sendAs4(
      baseInput(pki, 'https://localhost:1/as4', null, {
        signal: controller.signal,
        spoolDirectory: dir,
        payload: gushingPayload(),
      }),
    );
    setTimeout(() => controller.abort(), 20);
    const result = await pending;
    assert.equal(result.outcome, 'not-sent');
    if (result.outcome === 'not-sent') assert.equal(result.reason, 'aborted');
    assert.deepEqual(await readdir(dir), []);
  });
});

test('abort during HTTP: stops the request and removes the temp files', async () => {
  await withSpoolDir(async (dir) => {
    const pki = createTestPki();
    const tls = createTlsServerCert();
    const receiver = await startFakeReceiver({
      receiver: pki.receiver,
      tlsCertPem: tls.certPem,
      tlsKeyPem: tls.keyPem,
      mode: { kind: 'hang' },
    });
    try {
      const controller = new AbortController();
      const pending = sendAs4(
        baseInput(pki, receiver.url, tls.caPem, {
          signal: controller.signal,
          spoolDirectory: dir,
          http: { connectMs: 5_000, totalMs: 30_000, ca: [tls.caPem] },
        }),
      );
      setTimeout(() => controller.abort(), 50);
      const result = await pending;
      assert.equal(result.outcome, 'transport-failure');
      if (result.outcome === 'transport-failure') assert.equal(result.aborted, true);
      assert.deepEqual(await readdir(dir), []);
    } finally {
      await receiver.close();
    }
  });
});

test('abort during receipt verification: still reported as receipt-unverified with raw bytes', async () => {
  await withSpoolDir(async (dir) => {
    const pki = createTestPki();
    const tls = createTlsServerCert();
    const receiver = await startFakeReceiver({
      receiver: pki.receiver,
      tlsCertPem: tls.certPem,
      tlsKeyPem: tls.keyPem,
    });
    try {
      const controller = new AbortController();
      // Accept the receiver certificate, then hang on the receipt signer and
      // abort while it is being validated.
      const validateCertificate: ValidateCertificate = (input) => {
        if (input.purpose === 'receiver-encryption') return Promise.resolve({ ok: true });
        return new Promise((_resolve, reject) => {
          const fail = (): void => {
            const err = new Error('aborted');
            err.name = 'AbortError';
            reject(err);
          };
          if (input.signal?.aborted) {
            fail();
            return;
          }
          input.signal?.addEventListener('abort', fail, { once: true });
          setTimeout(() => controller.abort(), 5);
        });
      };

      const result = await sendAs4(
        baseInput(pki, receiver.url, tls.caPem, {
          signal: controller.signal,
          spoolDirectory: dir,
          validateCertificate,
        }),
      );

      assert.notEqual(result.outcome, 'not-sent');
      assert.equal(result.outcome, 'receipt-unverified');
      if (result.outcome === 'receipt-unverified') {
        assert.equal(result.reason, 'receipt.aborted');
        assert.ok(result.raw.length > 0);
      }
      assert.deepEqual(await readdir(dir), []);
    } finally {
      await receiver.close();
    }
  });
});

test('the sender passes its abort signal to the signer', async () => {
  const pki = createTestPki();
  const tls = createTlsServerCert();
  const receiver = await startFakeReceiver({ receiver: pki.receiver, tlsCertPem: tls.certPem, tlsKeyPem: tls.keyPem });
  const base = signerFromKey(pki.sender.keyObject, pki.sender.certPem);
  let sawSignal = false;
  try {
    const result = await sendAs4(
      baseInput(pki, receiver.url, tls.caPem, {
        signal: new AbortController().signal,
        signer: {
          certificate: base.certificate,
          async sign(data, signal) {
            sawSignal = signal !== undefined;
            return base.sign(data, signal);
          },
        },
      }),
    );
    assert.equal(result.outcome, 'receipt-verified');
    assert.equal(sawSignal, true);
  } finally {
    await receiver.close();
  }
});

test('abort while the signer runs: reported as aborted and nothing is sent', async () => {
  await withSpoolDir(async (dir) => {
    const pki = createTestPki();
    const tls = createTlsServerCert();
    const receiver = await startFakeReceiver({
      receiver: pki.receiver,
      tlsCertPem: tls.certPem,
      tlsKeyPem: tls.keyPem,
    });
    const controller = new AbortController();
    const base = signerFromKey(pki.sender.keyObject, pki.sender.certPem);
    try {
      const result = await sendAs4(
        baseInput(pki, receiver.url, tls.caPem, {
          signal: controller.signal,
          spoolDirectory: dir,
          signer: {
            certificate: base.certificate,
            sign: (_data, signal) =>
              new Promise((_resolve, reject) => {
                const fail = (): void => {
                  const err = new Error('aborted');
                  err.name = 'AbortError';
                  reject(err);
                };
                if (signal?.aborted) {
                  fail();
                  return;
                }
                signal?.addEventListener('abort', fail, { once: true });
                setTimeout(() => controller.abort(), 5);
              }),
          },
        }),
      );
      assert.equal(result.outcome, 'not-sent');
      if (result.outcome === 'not-sent') assert.equal(result.reason, 'aborted');
      assert.equal(receiver.received.length, 0, 'an aborted signer must not start the HTTP request');
      assert.deepEqual(await readdir(dir), []);
    } finally {
      await receiver.close();
    }
  });
});

test('signerFromKey refuses to sign once the signal is aborted', async () => {
  const pki = createTestPki();
  const signer = signerFromKey(pki.sender.keyObject, pki.sender.certPem);
  await assert.rejects(() => signer.sign(new Uint8Array([1, 2, 3]), AbortSignal.abort()), /abort/i);
});
