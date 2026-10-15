import test from 'node:test';
import assert from 'node:assert/strict';
import { sendAs4, type SendAs4Input } from '../src/index.js';
import { createTestPki, createTlsServerCert } from './helpers/pki.js';
import { startFakeReceiver } from './helpers/fake-receiver.js';
import { baseInput } from './helpers/input.js';

/**
 * Item 6: `classifyResponse` reports *why* a response was not a readable signal,
 * end to end through `sendAs4` (and therefore `transmitAs4`). A response that is
 * not a single unambiguous signal is a `no-signal` with a secret-free `detail`,
 * for a request that was definitely sent.
 */
const pki = createTestPki();
const tls = createTlsServerCert();
const ENVELOPE =
  '<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope"><env:Header/><env:Body/></env:Envelope>';

async function withBody(body: string, overrides: Partial<SendAs4Input> = {}) {
  const receiver = await startFakeReceiver({
    receiver: pki.receiver,
    tlsCertPem: tls.certPem,
    tlsKeyPem: tls.keyPem,
    mode: { kind: 'status', status: 200, body },
  });
  try {
    return await sendAs4(baseInput(pki, receiver.url, tls.caPem, overrides));
  } finally {
    await receiver.close();
  }
}

test('a DOCTYPE response is no-signal with detail xml.doctype and the status preserved', async () => {
  const result = await withBody(`<!DOCTYPE x []>${ENVELOPE}`);
  assert.equal(result.outcome, 'no-signal');
  if (result.outcome === 'no-signal') {
    assert.equal(result.detail, 'xml.doctype');
    assert.equal(result.status, 200);
    assert.equal(result.bodyEmpty, false);
  }
});

test('an over-maxXmlBytes response is no-signal with detail xml.too-large', async () => {
  const result = await withBody(ENVELOPE, { responseLimits: { maxXmlBytes: 16 } });
  assert.equal(result.outcome, 'no-signal');
  if (result.outcome === 'no-signal') assert.equal(result.detail, 'xml.too-large');
});

test('a well-formed response that is not a single signal is no-signal with detail signal.shape', async () => {
  const result = await withBody(ENVELOPE);
  assert.equal(result.outcome, 'no-signal');
  if (result.outcome === 'no-signal') assert.equal(result.detail, 'signal.shape');
});
