import test from 'node:test';
import assert from 'node:assert/strict';
import { SessionKeyFault, unwrapSessionKey } from '../src/receive/session-key.js';
import type { InboundKeyHolder } from '../src/receive/types.js';
import { createTestPki } from './helpers/pki.js';

const pki = createTestPki();

function holder(certificate: string, result: Uint8Array | Error, onCall?: () => void): InboundKeyHolder {
  return {
    certificate,
    async unwrap() {
      onCall?.();
      if (result instanceof Error) throw result;
      return result;
    },
  };
}

const KEY = Buffer.alloc(16, 7);
const reason = (r: string) => (err: unknown) => err instanceof SessionKeyFault && err.reason === r;
const delay = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

test('returns the 16-byte session key and the credential that produced it', async () => {
  const result = await unwrapSessionKey({
    wrappedKey: new Uint8Array([1]),
    holders: [holder(pki.receiver.certPem, KEY)],
    maxCandidates: 4,
  });
  assert.deepEqual(result.sessionKey, KEY);
  assert.equal(result.credentialCertificate, pki.receiver.certPem);
});

test('prefers the credential named by the EncryptedKey', async () => {
  const result = await unwrapSessionKey({
    wrappedKey: new Uint8Array([1]),
    recipientCertificate: pki.receiver.certPem,
    holders: [
      holder(pki.sender.certPem, Buffer.alloc(16, 1)),
      holder(pki.receiver.certPem, Buffer.alloc(16, 2)),
      holder('not-a-real-cert', Buffer.alloc(16, 3)),
    ],
    maxCandidates: 4,
  });
  assert.equal(result.credentialCertificate, pki.receiver.certPem);
  assert.deepEqual(result.sessionKey, Buffer.alloc(16, 2));
});

test('orders the named credential before applying the cap', async () => {
  // holders = [new, old], recipient names old, cap = 1 -> old must be the one tried.
  const result = await unwrapSessionKey({
    wrappedKey: new Uint8Array([1]),
    recipientCertificate: pki.receiver.certPem,
    holders: [holder(pki.sender.certPem, Buffer.alloc(16, 1)), holder(pki.receiver.certPem, Buffer.alloc(16, 2))],
    maxCandidates: 1,
  });
  assert.equal(result.credentialCertificate, pki.receiver.certPem);
  assert.deepEqual(result.sessionKey, Buffer.alloc(16, 2));
});

test('falls back to the candidate list when no certificate matches', async () => {
  const result = await unwrapSessionKey({
    wrappedKey: new Uint8Array([1]),
    recipientCertificate: pki.sender.certPem,
    holders: [holder('x', Buffer.alloc(16, 9))],
    maxCandidates: 4,
  });
  assert.deepEqual(result.sessionKey, Buffer.alloc(16, 9));
});

test('rejects a malformed key length', async () => {
  await assert.rejects(
    unwrapSessionKey({ wrappedKey: new Uint8Array([1]), holders: [holder('x', Buffer.alloc(12))], maxCandidates: 4 }),
    reason('decrypt.bad-key-length'),
  );
});

test('reports exhaustion when wrong credentials are tried', async () => {
  await assert.rejects(
    unwrapSessionKey({
      wrappedKey: new Uint8Array([1]),
      holders: [holder('a', new Error('bad key')), holder('b', new Error('bad key'))],
      maxCandidates: 4,
    }),
    reason('decrypt.key-unwrap'),
  );
});

test('reports provider unavailability distinctly from wrong credentials', async () => {
  const unavailable = Object.assign(new Error('provider down'), { code: 'KEY_UNAVAILABLE' });
  await assert.rejects(
    unwrapSessionKey({ wrappedKey: new Uint8Array([1]), holders: [holder('a', unavailable)], maxCandidates: 4 }),
    reason('decrypt.key-unavailable'),
  );
});

test('a non-positive candidate bound attempts no credential', async () => {
  let calls = 0;
  await assert.rejects(
    unwrapSessionKey({
      wrappedKey: new Uint8Array([1]),
      holders: [holder('a', KEY, () => (calls += 1))],
      maxCandidates: 0,
    }),
    reason('decrypt.key-unwrap'),
  );
  assert.equal(calls, 0);
});

test('bounds the number of credentials tried', async () => {
  let calls = 0;
  await assert.rejects(
    unwrapSessionKey({
      wrappedKey: new Uint8Array([1]),
      holders: [
        holder('a', new Error('no'), () => (calls += 1)),
        holder('b', new Error('no'), () => (calls += 1)),
        holder('c', KEY, () => (calls += 1)),
      ],
      maxCandidates: 2,
    }),
    reason('decrypt.key-unwrap'),
  );
  assert.equal(calls, 2, 'a candidate beyond the bound is never tried');
});

test('cancels a stalled provider and discards a late result', async () => {
  const controller = new AbortController();
  let release: (key: Uint8Array) => void = () => {};
  const stalled: InboundKeyHolder = {
    certificate: 'x',
    unwrap: () =>
      new Promise<Uint8Array>((resolve) => {
        release = resolve;
      }),
  };
  const pending = unwrapSessionKey({
    wrappedKey: new Uint8Array([1]),
    holders: [stalled],
    maxCandidates: 4,
    signal: controller.signal,
  });
  const settled = pending.then(
    () => 'resolved' as const,
    () => 'rejected' as const,
  );
  setTimeout(() => controller.abort(), 10);
  await assert.rejects(pending, reason('aborted'));
  assert.equal(await settled, 'rejected');

  // The late result must not turn the operation into a success.
  release(Buffer.alloc(16, 5));
  await delay(10);
  assert.equal(await settled, 'rejected');
});
