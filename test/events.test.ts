import test from 'node:test';
import assert from 'node:assert/strict';
import { sendAs4, type SendEvent } from '../src/index.js';
import { EBMS_NS } from '../src/constants.js';
import { firstByLocalName, textOf } from '../src/xml/nodes.js';
import { createTestPki, createTlsServerCert } from './helpers/pki.js';
import { startFakeReceiver } from './helpers/fake-receiver.js';
import { baseInput } from './helpers/input.js';

test('onEvent observes every phase, in order, and never receives secrets', async () => {
  const pki = createTestPki();
  const tls = createTlsServerCert();
  const receiver = await startFakeReceiver({ receiver: pki.receiver, tlsCertPem: tls.certPem, tlsKeyPem: tls.keyPem });
  const events: SendEvent[] = [];
  try {
    const result = await sendAs4(
      baseInput(pki, receiver.url, tls.caPem, {
        onEvent: (event) => events.push(event),
      }),
    );
    assert.equal(result.outcome, 'receipt-verified');
    assert.deepEqual(
      events.map((e) => e.phase),
      ['validate-receiver', 'prepare-payload', 'sign', 'http', 'verify-receipt'],
    );
    for (const event of events) {
      assert.deepEqual(Object.keys(event).sort(), ['durationMs', 'phase']);
      assert.ok(event.durationMs >= 0);
    }
  } finally {
    await receiver.close();
  }
});

test('an exception thrown by onEvent is swallowed', async () => {
  const pki = createTestPki();
  const tls = createTlsServerCert();
  const receiver = await startFakeReceiver({ receiver: pki.receiver, tlsCertPem: tls.certPem, tlsKeyPem: tls.keyPem });
  try {
    const result = await sendAs4(
      baseInput(pki, receiver.url, tls.caPem, {
        onEvent: () => {
          throw new Error('observer exploded');
        },
      }),
    );
    assert.equal(result.outcome, 'receipt-verified');
  } finally {
    await receiver.close();
  }
});

test('the timestamp placed on the wire matches the reported sentAt', async () => {
  const pki = createTestPki();
  const tls = createTlsServerCert();
  const receiver = await startFakeReceiver({ receiver: pki.receiver, tlsCertPem: tls.certPem, tlsKeyPem: tls.keyPem });
  try {
    const result = await sendAs4(baseInput(pki, receiver.url, tls.caPem));
    assert.equal(result.outcome, 'receipt-verified');
    const envelope = receiver.received[0]!.envelope;
    const timestamp = textOf(firstByLocalName(envelope, EBMS_NS, 'Timestamp'));
    assert.equal(timestamp, result.sentAt);
  } finally {
    await receiver.close();
  }
});
