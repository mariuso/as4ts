import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { sendAs4, type SendEvent } from '../src/index.js';
import { classify } from '../src/classifier.js';
import { sendAs4Internal, defaultEntropy } from '../src/internal.js';
import type { TempWorkspace, TempWorkspaceOptions } from '../src/temp-file.js';
import { createTestPki, createTlsServerCert } from './helpers/pki.js';
import { startFakeReceiver } from './helpers/fake-receiver.js';
import { baseInput } from './helpers/input.js';

/**
 * Delivery-lifecycle regressions from the sending review: error signals must be
 * correlated with the message we sent before they can establish a result, and a
 * spool cleanup failure must never mask an already-computed result.
 */
const MESSAGE_ID = 'test-message@as4-sender.test'; // baseInput's default as4MessageId

const pki = createTestPki();
const tls = createTlsServerCert();

async function withReceiver<T>(
  mode: Parameters<typeof startFakeReceiver>[0]['mode'],
  body: (url: string) => Promise<T>,
): Promise<T> {
  const receiver = await startFakeReceiver({
    receiver: pki.receiver,
    tlsCertPem: tls.certPem,
    tlsKeyPem: tls.keyPem,
    ...(mode ? { mode } : {}),
  });
  try {
    return await body(receiver.url);
  } finally {
    await receiver.close();
  }
}

test('an error signal that references our message is classified by its code', async () => {
  await withReceiver(
    { kind: 'error', status: 200, code: 'EBMS:0004', detail: 'PEPPOL:NOT_SERVICED', refToMessageId: MESSAGE_ID },
    async (url) => {
      const result = await sendAs4(baseInput(pki, url, tls.caPem));
      assert.equal(result.outcome, 'error-signal');
      if (result.outcome === 'error-signal') {
        assert.equal(result.correlation, 'matches');
        assert.equal(result.refToMessageId, MESSAGE_ID);
      }
      assert.equal(classify(result), 'fatal');
    },
  );
});

test('an error signal that references a different message cannot establish a result', async () => {
  await withReceiver(
    {
      kind: 'error',
      status: 200,
      code: 'EBMS:0004',
      detail: 'PEPPOL:NOT_SERVICED',
      refToMessageId: 'someone-else@test',
    },
    async (url) => {
      const result = await sendAs4(baseInput(pki, url, tls.caPem));
      assert.equal(result.outcome, 'error-signal');
      if (result.outcome === 'error-signal') {
        assert.equal(result.correlation, 'mismatched');
        assert.equal(result.refToMessageId, 'someone-else@test');
      }
      // A NOT_SERVICED error would be fatal, but not when it names a different message.
      assert.equal(classify(result), 'unknown');
    },
  );
});

test('an error signal with no reference is classified by its code', async () => {
  await withReceiver({ kind: 'error', status: 200, code: 'EBMS:0004', detail: 'PEPPOL:NOT_SERVICED' }, async (url) => {
    const result = await sendAs4(baseInput(pki, url, tls.caPem));
    assert.equal(result.outcome, 'error-signal');
    if (result.outcome === 'error-signal') {
      assert.equal(result.correlation, 'absent');
      assert.equal(result.refToMessageId, null);
    }
    assert.equal(classify(result), 'fatal');
  });
});

/** A workspace factory whose cleanup always fails, capturing the directory it leaks. */
function failingWorkspace(): { factory: (o: TempWorkspaceOptions) => Promise<TempWorkspace>; leaked: () => string } {
  let dir = '';
  return {
    leaked: () => dir,
    factory: async (options) => {
      dir = await mkdtemp(join(options.directory ?? tmpdir(), 'as4-cleanup-'));
      return {
        dir,
        path: (name: string) => join(dir, name),
        cleanup: async () => {
          throw Object.assign(new Error('EACCES: permission denied, rm'), { code: 'EACCES' });
        },
      };
    },
  };
}

test('a spool cleanup failure does not replace a verified receipt', async () => {
  const { factory, leaked } = failingWorkspace();
  const events: SendEvent[] = [];
  try {
    await withReceiver(undefined, async (url) => {
      const result = await sendAs4Internal(
        baseInput(pki, url, tls.caPem, { onEvent: (event) => events.push(event) }),
        defaultEntropy(),
        factory,
      );
      assert.equal(result.outcome, 'receipt-verified');
    });
    const cleanup = events.find((event) => event.phase === 'cleanup');
    assert.ok(cleanup, 'a cleanup event should report the failure');
    assert.match(cleanup.error ?? '', /EACCES|permission/);
  } finally {
    const dir = leaked();
    if (dir) await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
});

test('a spool cleanup failure does not replace an error signal', async () => {
  const { factory, leaked } = failingWorkspace();
  const events: SendEvent[] = [];
  try {
    await withReceiver({ kind: 'error', status: 200, code: 'EBMS:0001' }, async (url) => {
      const result = await sendAs4Internal(
        baseInput(pki, url, tls.caPem, { onEvent: (event) => events.push(event) }),
        defaultEntropy(),
        factory,
      );
      assert.equal(result.outcome, 'error-signal');
      if (result.outcome === 'error-signal') assert.equal(result.errors[0]?.code, 'EBMS:0001');
    });
    assert.ok(events.some((event) => event.phase === 'cleanup'));
  } finally {
    const dir = leaked();
    if (dir) await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
});

test('a spool I/O failure is reported as spool.failed and nothing is sent', async () => {
  const receiver = await startFakeReceiver({ receiver: pki.receiver, tlsCertPem: tls.certPem, tlsKeyPem: tls.keyPem });
  try {
    // A spool directory whose parent does not exist makes mkdtemp fail with ENOENT.
    const missing = join(tmpdir(), `as4-does-not-exist-${randomUUID()}`);
    const result = await sendAs4(baseInput(pki, receiver.url, tls.caPem, { spoolDirectory: missing }));
    assert.equal(result.outcome, 'not-sent');
    if (result.outcome === 'not-sent') assert.equal(result.reason, 'spool.failed');
    assert.equal(classify(result), 'retryable');
    assert.equal(receiver.received.length, 0, 'no request may be sent after a local spool failure');
  } finally {
    await receiver.close();
  }
});
