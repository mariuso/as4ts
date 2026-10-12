import test from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { sendAs4, signerFromKey } from '../src/index.js';
import { createTestPki, createTlsServerCert } from './helpers/pki.js';
import { startFakeReceiver } from './helpers/fake-receiver.js';
import { baseInput } from './helpers/input.js';

test('two sends to the same host both report request bytes written (no keep-alive reuse bug)', async () => {
  const pki = createTestPki();
  const tls = createTlsServerCert();
  const receiver = await startFakeReceiver({ receiver: pki.receiver, tlsCertPem: tls.certPem, tlsKeyPem: tls.keyPem });
  try {
    const first = await sendAs4(
      baseInput(pki, receiver.url, tls.caPem, { payload: Readable.from(Buffer.from('<d/>')) }),
    );
    const second = await sendAs4(
      baseInput(pki, receiver.url, tls.caPem, { payload: Readable.from(Buffer.from('<d/>')) }),
    );
    assert.equal(first.outcome, 'receipt-verified');
    assert.equal(second.outcome, 'receipt-verified');
  } finally {
    await receiver.close();
  }
});

test('round trip: sender and fake receiver agree', async () => {
  const pki = createTestPki();
  const tls = createTlsServerCert();
  const receiver = await startFakeReceiver({
    receiver: pki.receiver,
    tlsCertPem: tls.certPem,
    tlsKeyPem: tls.keyPem,
  });

  try {
    const payload = Buffer.from(
      '<?xml version="1.0" encoding="UTF-8"?><StandardBusinessDocument><Invoice>42</Invoice></StandardBusinessDocument>',
      'utf8',
    );
    const result = await sendAs4({
      payload: Readable.from(payload),
      endpointUrl: receiver.url,
      transportProfile: 'peppol-transport-as4-v2_0',
      receiverCertificate: pki.receiver.certPem,
      senderParticipant: { scheme: 'iso6523-actorid-upis', value: '0192:111111111' },
      receiverParticipant: { scheme: 'iso6523-actorid-upis', value: '0192:222222222' },
      documentType: {
        scheme: 'busdox-docid-qns',
        value:
          'urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice##urn:www.cenbii.eu:transaction:biitrns010:ver2.0:extended:urn:www.peppol.eu:bis:peppol5a:ver2.0::2.1',
      },
      process: { scheme: 'cenbii-procid-ubl', value: 'urn:www.cenbii.eu:profile:bii05:ver2.0' },
      as4MessageId: 'test-message-1@as4-sender.test',
      signer: signerFromKey(pki.sender.keyObject, pki.sender.certPem),
      validateCertificate: baseInput(pki, '', null).validateCertificate,
      http: { connectMs: 5_000, totalMs: 15_000, ca: [tls.caPem] },
      now: () => new Date(),
    });

    assert.equal(result.outcome, 'receipt-verified');
    assert.equal(receiver.received.length, 1);
    const received = receiver.received[0]!;
    assert.equal(received.signatureValid, true);
    assert.deepEqual(received.payload, payload);
  } finally {
    await receiver.close();
  }
});
