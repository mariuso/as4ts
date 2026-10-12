import test from 'node:test';
import assert from 'node:assert/strict';
import { createPublicKey } from 'node:crypto';
import { Agent } from 'node:https';
import { sendAs4, signerFromKey, type SendAs4Result, type HttpOptions } from '../src/index.js';
import { classify } from '../src/classifier.js';
import { createTestPki, createTlsServerCert } from './helpers/pki.js';
import { startFakeReceiver } from './helpers/fake-receiver.js';
import { baseInput, testValidator } from './helpers/input.js';

const pki = createTestPki();
const tls = createTlsServerCert();

test('accepted: verified receipt', async () => {
  const receiver = await startFakeReceiver({ receiver: pki.receiver, tlsCertPem: tls.certPem, tlsKeyPem: tls.keyPem });
  try {
    const result = await sendAs4(baseInput(pki, receiver.url, tls.caPem));
    assert.equal(result.outcome, 'receipt-verified');
    if (result.outcome === 'receipt-verified') {
      assert.equal(result.receipt.signerMatchesSmPCertificate, true);
      assert.equal(result.receipt.refToMessageId, result.as4MessageId);
    }
    assert.equal(classify(result), 'accepted');
  } finally {
    await receiver.close();
  }
});

test('rejects an untrusted TLS server certificate: verification cannot be disabled', async () => {
  const receiver = await startFakeReceiver({ receiver: pki.receiver, tlsCertPem: tls.certPem, tlsKeyPem: tls.keyPem });
  try {
    // No pinned CA: the receiver's self-signed certificate must be refused.
    const result = await sendAs4(baseInput(pki, receiver.url, null));
    assert.equal(result.outcome, 'transport-failure');
    if (result.outcome === 'transport-failure') assert.equal(result.requestBytesWritten, false);
  } finally {
    await receiver.close();
  }
});

test('cannot bypass TLS verification with a caller-supplied agent', async () => {
  const receiver = await startFakeReceiver({ receiver: pki.receiver, tlsCertPem: tls.certPem, tlsKeyPem: tls.keyPem });
  try {
    const sneakyAgent = new Agent({ rejectUnauthorized: false });
    const result = await sendAs4(
      baseInput(pki, receiver.url, null, {
        // The option no longer exists; cast to prove it is ignored even when injected.
        http: { connectMs: 5_000, totalMs: 15_000, agent: sneakyAgent } as unknown as HttpOptions,
      }),
    );
    assert.equal(result.outcome, 'transport-failure');
    assert.notEqual(result.outcome, 'receipt-verified');
  } finally {
    await receiver.close();
  }
});

test('transport-failure: DNS failure, nothing sent, retryable', async () => {
  const result = await sendAs4(
    baseInput(pki, 'https://does-not-exist.invalid/as4', null, { http: { connectMs: 5_000, totalMs: 10_000 } }),
  );
  assert.equal(result.outcome, 'transport-failure');
  if (result.outcome === 'transport-failure') {
    assert.equal(result.errorCode, 'ENOTFOUND');
    assert.equal(result.requestBytesWritten, false);
    assert.equal(result.aborted, false);
  }
  assert.equal(classify(result), 'retryable');
});

test('no-signal: 5xx that is not a signal message', async () => {
  const receiver = await startFakeReceiver({
    receiver: pki.receiver,
    tlsCertPem: tls.certPem,
    tlsKeyPem: tls.keyPem,
    mode: { kind: 'status', status: 503, body: 'service unavailable' },
  });
  try {
    const result = await sendAs4(baseInput(pki, receiver.url, tls.caPem));
    assert.equal(result.outcome, 'no-signal');
    if (result.outcome === 'no-signal') assert.equal(result.status, 503);
    assert.equal(classify(result), 'retryable');
  } finally {
    await receiver.close();
  }
});

test('no-signal: 4xx that is not a signal message, fatal', async () => {
  const receiver = await startFakeReceiver({
    receiver: pki.receiver,
    tlsCertPem: tls.certPem,
    tlsKeyPem: tls.keyPem,
    mode: { kind: 'status', status: 400, body: 'bad request' },
  });
  try {
    const result = await sendAs4(baseInput(pki, receiver.url, tls.caPem));
    assert.equal(result.outcome, 'no-signal');
    assert.equal(classify(result), 'fatal');
  } finally {
    await receiver.close();
  }
});

test('no-signal: 2xx that is not a signal message, unknown', async () => {
  const receiver = await startFakeReceiver({
    receiver: pki.receiver,
    tlsCertPem: tls.certPem,
    tlsKeyPem: tls.keyPem,
    mode: { kind: 'status', status: 200, body: 'not xml' },
  });
  try {
    const result = await sendAs4(baseInput(pki, receiver.url, tls.caPem));
    assert.equal(result.outcome, 'no-signal');
    assert.equal(classify(result), 'unknown');
  } finally {
    await receiver.close();
  }
});

test('no-signal: empty 2xx response records bodyEmpty', async () => {
  const receiver = await startFakeReceiver({
    receiver: pki.receiver,
    tlsCertPem: tls.certPem,
    tlsKeyPem: tls.keyPem,
    mode: { kind: 'status', status: 200, body: '' },
  });
  try {
    const result = await sendAs4(baseInput(pki, receiver.url, tls.caPem));
    assert.equal(result.outcome, 'no-signal');
    if (result.outcome === 'no-signal') assert.equal(result.bodyEmpty, true);
  } finally {
    await receiver.close();
  }
});

test('error-signal: EBMS:0004 with PEPPOL:NOT_SERVICED is fatal', async () => {
  const receiver = await startFakeReceiver({
    receiver: pki.receiver,
    tlsCertPem: tls.certPem,
    tlsKeyPem: tls.keyPem,
    mode: { kind: 'error', status: 200, code: 'EBMS:0004', detail: 'PEPPOL:NOT_SERVICED' },
  });
  try {
    const result = await sendAs4(baseInput(pki, receiver.url, tls.caPem));
    assert.equal(result.outcome, 'error-signal');
    if (result.outcome === 'error-signal') {
      assert.equal(result.errors[0]?.code, 'EBMS:0004');
      assert.equal(result.errors[0]?.detail, 'PEPPOL:NOT_SERVICED');
    }
    assert.equal(classify(result), 'fatal');
  } finally {
    await receiver.close();
  }
});

test('error-signal: EBMS:0004 without NOT_SERVICED is retryable', async () => {
  const receiver = await startFakeReceiver({
    receiver: pki.receiver,
    tlsCertPem: tls.certPem,
    tlsKeyPem: tls.keyPem,
    mode: { kind: 'error', status: 500, code: 'EBMS:0004' },
  });
  try {
    const result = await sendAs4(baseInput(pki, receiver.url, tls.caPem));
    assert.equal(result.outcome, 'error-signal');
    assert.equal(classify(result), 'retryable');
  } finally {
    await receiver.close();
  }
});

test('error-signal: returns every error, most severe class wins', async () => {
  const receiver = await startFakeReceiver({
    receiver: pki.receiver,
    tlsCertPem: tls.certPem,
    tlsKeyPem: tls.keyPem,
    mode: { kind: 'error', status: 500, code: 'EBMS:0005', extraCodes: ['EBMS:0001'] },
  });
  try {
    const result = await sendAs4(baseInput(pki, receiver.url, tls.caPem));
    assert.equal(result.outcome, 'error-signal');
    if (result.outcome === 'error-signal') {
      assert.deepEqual(
        result.errors.map((e) => e.code),
        ['EBMS:0005', 'EBMS:0001'],
      );
    }
    assert.equal(classify(result), 'fatal');
  } finally {
    await receiver.close();
  }
});

test('receipt-unverified: tampered NonRepudiationInformation digest keeps raw bytes', async () => {
  const receiver = await startFakeReceiver({
    receiver: pki.receiver,
    tlsCertPem: tls.certPem,
    tlsKeyPem: tls.keyPem,
    mode: { kind: 'receipt-tampered' },
  });
  try {
    const result = await sendAs4(baseInput(pki, receiver.url, tls.caPem));
    assert.equal(result.outcome, 'receipt-unverified');
    if (result.outcome === 'receipt-unverified') {
      assert.equal(result.reason, 'receipt.digest-mismatch');
      assert.ok(result.raw.length > 0);
    }
    assert.equal(classify(result), 'unknown');
  } finally {
    await receiver.close();
  }
});

test('not-sent: receiver certificate does not chain to a trust anchor', async () => {
  const other = createTestPki();
  const input = baseInput(pki, 'https://localhost:1/as4', null, {
    validateCertificate: testValidator(other),
  });
  const result = await sendAs4(input);
  assert.equal(result.outcome, 'not-sent');
  if (result.outcome === 'not-sent') assert.equal(result.reason, 'certificate.refused');
  assert.equal(classify(result), 'fatal');
});

test('transport-failure: connection dropped after request bytes were written', async () => {
  const receiver = await startFakeReceiver({
    receiver: pki.receiver,
    tlsCertPem: tls.certPem,
    tlsKeyPem: tls.keyPem,
    mode: { kind: 'drop' },
  });
  try {
    const result = await sendAs4(baseInput(pki, receiver.url, tls.caPem));
    assert.equal(result.outcome, 'transport-failure');
    if (result.outcome === 'transport-failure') assert.equal(result.requestBytesWritten, true);
    assert.equal(classify(result), 'unknown');
  } finally {
    await receiver.close();
  }
});

test('not-sent: a signer whose certificate does not match its key never sends', async () => {
  // Key from the sender, certificate from the receiver: the signature verifies
  // with the receiver's public key, so the sender refuses to put it on the wire.
  const mismatched = signerFromKey(pki.sender.keyObject, pki.receiver.certPem);
  const result = await sendAs4(baseInput(pki, 'https://localhost:1/as4', null, { signer: mismatched }));
  assert.equal(result.outcome, 'not-sent');
  if (result.outcome === 'not-sent') assert.equal(result.reason, 'signature.mismatch');
});

test('not-sent: caller-supplied message id is not a valid RFC 2822 msg-id', async () => {
  const result = await sendAs4(baseInput(pki, 'https://localhost:1/as4', null, { as4MessageId: 'not a valid id' }));
  assert.equal(result.outcome, 'not-sent');
  if (result.outcome === 'not-sent') assert.equal(result.reason, 'message-id.invalid');
  assert.equal(result.sentAt, undefined);
});

test('not-sent: an unreadable receiver certificate is refused before any send', async () => {
  const result = await sendAs4(
    baseInput(pki, 'https://localhost:1/as4', null, { receiverCertificate: 'not a certificate' }),
  );
  assert.equal(result.outcome, 'not-sent');
  if (result.outcome === 'not-sent') assert.equal(result.reason, 'certificate.refused');
});

// The following two tests use a deliberately bad signer/validator to make sure
// no code path sends without a working validator.
test('missing validator: never sends', async () => {
  const input = baseInput(pki, 'https://localhost:1/as4', null);
  delete (input as { validateCertificate?: unknown }).validateCertificate;
  const result = await sendAs4(input);
  assert.equal(result.outcome, 'not-sent');
  if (result.outcome === 'not-sent') assert.equal(result.reason, 'certificate.unavailable');
});

test('throwing validator: never sends', async () => {
  const result = await sendAs4(
    baseInput(pki, 'https://localhost:1/as4', null, {
      validateCertificate: () => {
        throw new Error('validator exploded');
      },
    }),
  );
  assert.equal(result.outcome, 'not-sent');
  if (result.outcome === 'not-sent') assert.equal(result.reason, 'certificate.unavailable');
});

test('public key as signer key is rejected by signerFromKey', () => {
  assert.throws(() => signerFromKey(createPublicKey(pki.sender.keyObject), pki.sender.certPem));
});

test('classify is pure and total over the fact union', () => {
  const results: SendAs4Result[] = [
    {
      outcome: 'receipt-verified',
      as4MessageId: 'a@b',
      sentAt: '',
      receiverCertificateCommonName: '',
      transportProfile: '',
      receipt: {
        timestamp: '',
        raw: new Uint8Array(),
        signerCertificate: '',
        signerMatchesSmPCertificate: false,
        refToMessageId: '',
      },
    },
    {
      outcome: 'receipt-unverified',
      as4MessageId: 'a@b',
      sentAt: '',
      receiverCertificateCommonName: '',
      transportProfile: '',
      reason: 'receipt.malformed',
      raw: new Uint8Array(),
    },
    {
      outcome: 'no-signal',
      as4MessageId: 'a@b',
      sentAt: '',
      receiverCertificateCommonName: '',
      transportProfile: '',
      status: 200,
      bodyEmpty: true,
    },
    {
      outcome: 'transport-failure',
      as4MessageId: 'a@b',
      sentAt: '',
      receiverCertificateCommonName: '',
      transportProfile: '',
      requestBytesWritten: false,
      aborted: false,
    },
    {
      outcome: 'not-sent',
      as4MessageId: 'a@b',
      sentAt: '',
      receiverCertificateCommonName: '',
      transportProfile: '',
      reason: 'spool.failed',
    },
  ];
  assert.equal(classify(results[0]!), 'accepted');
  assert.equal(classify(results[1]!), 'unknown');
  assert.equal(classify(results[2]!), 'unknown');
  assert.equal(classify(results[3]!), 'retryable');
  assert.equal(classify(results[4]!), 'retryable');
});
