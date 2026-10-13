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
  const other = 'not-a-real-cert';
  const result = await unwrapSessionKey({
    wrappedKey: new Uint8Array([1]),
    recipientCertificate: pki.receiver.certPem,
    holders: [
      holder(pki.sender.certPem, Buffer.alloc(16, 1)),
      holder(pki.receiver.certPem, Buffer.alloc(16, 2)),
      holder(other, Buffer.alloc(16, 3)),
    ],
    maxCandidates: 4,
  });
  assert.equal(result.credentialCertificate, pki.receiver.certPem);
  assert.deepEqual(result.sessionKey, Buffer.alloc(16, 2));
});

test('falls back to the bounded candidate list when no certificate matches', async () => {
  const result = await unwrapSessionKey({
    wrappedKey: new Uint8Array([1]),
    recipientCertificate: pki.sender.certPem, // not among the holders
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

test('reports exhaustion when no credential can unwrap', async () => {
  await assert.rejects(
    unwrapSessionKey({
      wrappedKey: new Uint8Array([1]),
      holders: [holder('a', new Error('bad key')), holder('b', new Error('bad key'))],
      maxCandidates: 4,
    }),
    reason('decrypt.key-unwrap'),
  );
  await assert.rejects(
    unwrapSessionKey({ wrappedKey: new Uint8Array([1]), holders: [], maxCandidates: 4 }),
    reason('decrypt.key-unwrap'),
  );
});

test('propagates cancellation from a stalled provider', async () => {
  const abortError = Object.assign(new Error('aborted'), { name: 'AbortError' });
  await assert.rejects(
    unwrapSessionKey({ wrappedKey: new Uint8Array([1]), holders: [holder('a', abortError)], maxCandidates: 4 }),
    reason('aborted'),
  );
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
