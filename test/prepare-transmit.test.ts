import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import {
  prepareAs4,
  transmitAs4,
  loadPreparedMessage,
  type PreparedMessage,
  type PrepareAs4Input,
  type SendEvent,
} from '../src/index.js';
import { prepareAs4Internal, defaultEntropy } from '../src/internal.js';
import type { TempWorkspace, TempWorkspaceOptions } from '../src/temp-file.js';
import { createTestPki, createTlsServerCert } from './helpers/pki.js';
import { startFakeReceiver, type FakeReceiverOptions } from './helpers/fake-receiver.js';
import { baseInput, testValidator } from './helpers/input.js';

/**
 * Stage 2: a prepared message is an immutable, replayable artifact. A retry must
 * re-send the exact same signed envelope and ciphertext, and receipt verification
 * must use the original signed references, not a rebuild.
 */
const pki = createTestPki();
const tls = createTlsServerCert();

function prepareInput(url: string, overrides: Partial<PrepareAs4Input> = {}): PrepareAs4Input {
  const base = baseInput(pki, url, tls.caPem);
  return {
    payload: base.payload,
    endpointUrl: url,
    transportProfile: base.transportProfile,
    receiverCertificate: base.receiverCertificate,
    senderParticipant: base.senderParticipant,
    receiverParticipant: base.receiverParticipant,
    documentType: base.documentType,
    process: base.process,
    as4MessageId: base.as4MessageId,
    signer: base.signer,
    validateCertificate: base.validateCertificate,
    now: () => new Date(),
    ...overrides,
  };
}

function transmitInput(message: PreparedMessage) {
  return {
    message,
    validateCertificate: testValidator(pki),
    http: { connectMs: 5_000, totalMs: 15_000, ca: [tls.caPem] },
    now: () => new Date(),
  };
}

function receiver(mode?: FakeReceiverOptions['mode']) {
  return startFakeReceiver({
    receiver: pki.receiver,
    tlsCertPem: tls.certPem,
    tlsKeyPem: tls.keyPem,
    ...(mode ? { mode } : {}),
  });
}

/** Prepare one artifact, let `fn` use it, then dispose it regardless. */
async function withPrepared(fn: (message: PreparedMessage) => Promise<void>): Promise<void> {
  const server = await receiver();
  const prepared = await prepareAs4(prepareInput(server.url));
  assert.equal(prepared.outcome, 'prepared');
  if (prepared.outcome !== 'prepared') return;
  try {
    await fn(prepared.message);
  } finally {
    await prepared.message.dispose().catch(() => {});
    await server.close();
  }
}

function mutateMetadata(message: PreparedMessage, mutate: (metadata: Record<string, unknown>) => void): void {
  const path = join(message.directory, 'metadata.json');
  const metadata = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;
  mutate(metadata);
  writeFileSync(path, JSON.stringify(metadata));
}

test('a prepared message is byte-identical across retries and verifies each time', async () => {
  const server = await receiver();
  const prepared = await prepareAs4(prepareInput(server.url));
  assert.equal(prepared.outcome, 'prepared');
  if (prepared.outcome !== 'prepared') return;
  const { message } = prepared;
  try {
    const first = await transmitAs4(transmitInput(message));
    const second = await transmitAs4(transmitInput(message));
    assert.equal(first.outcome, 'receipt-verified', JSON.stringify(first));
    assert.equal(second.outcome, 'receipt-verified', JSON.stringify(second));

    assert.equal(server.received.length, 2);
    assert.deepEqual(server.received[0]!.rawBody, server.received[1]!.rawBody, 'retry bytes are identical');
    assert.deepEqual(
      server.received[0]!.signedReferences,
      server.received[1]!.signedReferences,
      'signed references are stable',
    );
    // The stored references are exactly what the receiver saw.
    assert.deepEqual(
      message.signedReferences.map((r) => ({ uri: r.uri, digest: r.digest })),
      server.received[0]!.signedReferences.map((r) => ({ uri: r.uri, digest: r.digest })),
    );
  } finally {
    await message.dispose();
    await server.close();
  }
});

test('a persisted artifact reloads and still verifies', async () => {
  const server = await receiver();
  const prepared = await prepareAs4(prepareInput(server.url));
  assert.equal(prepared.outcome, 'prepared');
  if (prepared.outcome !== 'prepared') return;
  let reloaded: PreparedMessage | null = null;
  try {
    reloaded = await loadPreparedMessage(prepared.message.directory);
    assert.equal(reloaded.soapXml, prepared.message.soapXml);
    assert.deepEqual(reloaded.signedReferences, prepared.message.signedReferences);

    const result = await transmitAs4(transmitInput(reloaded));
    assert.equal(result.outcome, 'receipt-verified', JSON.stringify(result));
  } finally {
    await (reloaded ?? prepared.message).dispose();
    await server.close();
  }
});

test('a lost response is recovered by reloading the artifact and retrying', async () => {
  const server = await receiver({ kind: 'drop-first' });
  const prepared = await prepareAs4(prepareInput(server.url));
  assert.equal(prepared.outcome, 'prepared');
  if (prepared.outcome !== 'prepared') return;
  const { message } = prepared;
  let reloaded: PreparedMessage | null = null;
  try {
    const first = await transmitAs4(transmitInput(message));
    assert.equal(first.outcome, 'transport-failure', JSON.stringify(first));
    if (first.outcome === 'transport-failure') assert.equal(first.requestMayHaveBeenSent, true);

    // Simulate a restart: reload the persisted artifact and retry. The receiver
    // returns the exact receipt it generated for the first attempt, so the retry
    // only verifies if the references are unchanged.
    reloaded = await loadPreparedMessage(message.directory);
    assert.deepEqual(reloaded.signedReferences, message.signedReferences);
    const second = await transmitAs4(transmitInput(reloaded));
    assert.equal(second.outcome, 'receipt-verified', JSON.stringify(second));

    assert.equal(server.received.length, 2);
    assert.deepEqual(server.received[0]!.rawBody, server.received[1]!.rawBody);
    assert.deepEqual(server.received[0]!.signedReferences, server.received[1]!.signedReferences);
  } finally {
    await (reloaded ?? message).dispose();
    await server.close();
  }
});

test('preparation returns a value for an invalid message id and sends nothing', async () => {
  const server = await receiver();
  try {
    const prepared = await prepareAs4(prepareInput(server.url, { as4MessageId: 'not a valid id' }));
    assert.equal(prepared.outcome, 'not-prepared');
    if (prepared.outcome === 'not-prepared') assert.equal(prepared.reason, 'message-id.invalid');
    assert.equal(server.received.length, 0);
  } finally {
    await server.close();
  }
});

test('loading rejects an incomplete or inconsistent artifact', async () => {
  await withPrepared(async (message) => {
    mutateMetadata(message, (m) => {
      delete m.endpointUrl;
    });
    await assert.rejects(loadPreparedMessage(message.directory), /artifact metadata is missing endpointUrl/);
  });

  await withPrepared(async (message) => {
    mutateMetadata(message, (m) => {
      delete m.signedReferences;
    });
    await assert.rejects(loadPreparedMessage(message.directory), /invalid signed references/);
  });

  await withPrepared(async (message) => {
    // A different attachment name would make readAttachment() and transmission
    // read different files.
    mutateMetadata(message, (m) => {
      m.attachmentFile = 'other.bin';
    });
    await assert.rejects(loadPreparedMessage(message.directory), /unsupported artifact attachment name/);
  });

  await withPrepared(async (message) => {
    mutateMetadata(message, (m) => {
      m.attachmentByteLength = (m.attachmentByteLength as number) + 1;
    });
    await assert.rejects(loadPreparedMessage(message.directory), /does not match its metadata/);
  });
});

test('a preparation failure still reports a cleanup failure', async () => {
  const events: SendEvent[] = [];
  let leaked = '';
  const failingPayload = new Readable({
    read() {
      this.destroy(new Error('payload read failed'));
    },
  });
  const failingWorkspace = async (options: TempWorkspaceOptions): Promise<TempWorkspace> => {
    leaked = await mkdtemp(join(options.directory ?? tmpdir(), 'as4-prep-cleanup-'));
    return {
      dir: leaked,
      path: (name: string) => join(leaked, name),
      cleanup: async () => {
        throw Object.assign(new Error('EACCES: permission denied, rm'), { code: 'EACCES' });
      },
    };
  };
  try {
    const result = await prepareAs4Internal(
      prepareInput('https://localhost:1/as4', {
        payload: failingPayload,
        onEvent: (event) => events.push(event),
      }),
      defaultEntropy(),
      failingWorkspace,
    );
    assert.equal(result.outcome, 'not-prepared');
    const cleanup = events.find((event) => event.phase === 'cleanup');
    assert.ok(cleanup, 'a cleanup event should report the failure');
    assert.match(cleanup.error ?? '', /EACCES|permission/);
  } finally {
    if (leaked) await rm(leaked, { recursive: true, force: true }).catch(() => {});
  }
});

test('loading a directory that is not an artifact throws', async () => {
  await assert.rejects(loadPreparedMessage(tmpdir()), /not an as4ts artifact/);
});
