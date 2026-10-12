import test from 'node:test';
import assert from 'node:assert/strict';
import { tmpdir } from 'node:os';
import {
  prepareAs4,
  transmitAs4,
  loadPreparedMessage,
  type PreparedMessage,
  type PrepareAs4Input,
} from '../src/index.js';
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

test('a lost response is recovered by retrying the same prepared message', async () => {
  const server = await receiver({ kind: 'drop-first' });
  const prepared = await prepareAs4(prepareInput(server.url));
  assert.equal(prepared.outcome, 'prepared');
  if (prepared.outcome !== 'prepared') return;
  const { message } = prepared;
  try {
    const first = await transmitAs4(transmitInput(message));
    assert.equal(first.outcome, 'transport-failure', JSON.stringify(first));
    if (first.outcome === 'transport-failure') assert.equal(first.requestMayHaveBeenSent, true);

    const second = await transmitAs4(transmitInput(message));
    assert.equal(second.outcome, 'receipt-verified', JSON.stringify(second));

    assert.equal(server.received.length, 2);
    assert.deepEqual(server.received[0]!.rawBody, server.received[1]!.rawBody);
    assert.deepEqual(server.received[0]!.signedReferences, server.received[1]!.signedReferences);
  } finally {
    await message.dispose();
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

test('loading a directory that is not an artifact throws', async () => {
  await assert.rejects(loadPreparedMessage(tmpdir()), /not an as4ts artifact/);
});
