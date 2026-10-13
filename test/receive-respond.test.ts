import test from 'node:test';
import assert from 'node:assert/strict';
import { constants, privateDecrypt } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import {
  EBMS_ERROR_CODE_NOT_SERVICED,
  EBMS_ERROR_CODE_NOT_SERVICED_DETAIL,
  PEPPOL_PARTY_ID_TYPE,
} from '../src/constants.js';
import { signerFromKey } from '../src/index.js';
import { defaultEntropy, prepareAs4Internal } from '../src/internal.js';
import { buildMultipartBody } from '../src/multipart.js';
import { openAs4Message } from '../src/receive/open.js';
import { respondAs4Message } from '../src/receive/respond.js';
import { verifyReceipt } from '../src/receipt/verify.js';
import type {
  AcceptResponseInput,
  InboundKeyHolder,
  OpenAs4MessageInput,
  OpenSuccess,
  ReceiptContext,
  RespondAs4MessageInput,
} from '../src/receive/types.js';
import type { Signer } from '../src/types.js';
import { parseSignal } from '../src/xml/signal.js';
import { createTestPki } from './helpers/pki.js';
import { testValidator } from './helpers/input.js';

const pki = createTestPki();
const SENDER = { scheme: 'iso6523-actorid-upis', value: '0192:111111111' };
const RECEIVER = { scheme: 'iso6523-actorid-upis', value: '0192:222222222' };
const DOC_TYPE = {
  scheme: 'busdox-docid-qns',
  value: 'urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice##urn:cen.eu:en16931:2017::2.1',
};
const PROCESS = { scheme: 'cenbii-procid-ubl', value: 'urn:fdc:peppol.eu:2017:poacc:billing:01:1.0' };
const AS4_MESSAGE_ID = 'inbound@as4-sender.test';

const holder: InboundKeyHolder = {
  certificate: pki.receiver.certPem,
  async unwrap(wrapped) {
    return privateDecrypt(
      { key: pki.receiver.keyObject, oaepHash: 'sha256', padding: constants.RSA_PKCS1_OAEP_PADDING },
      Buffer.from(wrapped),
    );
  },
};

async function openInbound(): Promise<{ opened: OpenSuccess; cleanup: () => Promise<void> }> {
  const dir = await mkdtemp(join(tmpdir(), 'as4-respond-'));
  const payload = Buffer.from(
    `<StandardBusinessDocument xmlns="http://www.unece.org/cefact/namespaces/StandardBusinessDocumentHeader">` +
      '<StandardBusinessDocumentHeader><HeaderVersion>1.0</HeaderVersion></StandardBusinessDocumentHeader>' +
      '</StandardBusinessDocument>',
    'utf8',
  );
  const prepared = await prepareAs4Internal(
    {
      payload: Readable.from(payload),
      endpointUrl: 'https://ap.example/as4',
      transportProfile: 'peppol-transport-as4-v2_0',
      receiverCertificate: pki.receiver.certPem,
      senderParticipant: SENDER,
      receiverParticipant: RECEIVER,
      documentType: DOC_TYPE,
      process: PROCESS,
      as4MessageId: AS4_MESSAGE_ID,
      signer: signerFromKey(pki.sender.keyObject, pki.sender.certPem),
      validateCertificate: testValidator(pki),
      artifactDirectory: dir,
      now: () => new Date(),
    },
    defaultEntropy(),
  );
  assert.equal(prepared.outcome, 'prepared', JSON.stringify(prepared));
  if (prepared.outcome !== 'prepared') throw new Error('unreachable');
  const message = prepared.message;
  try {
    const multipart = buildMultipartBody({
      soapXml: message.soapXml,
      attachmentHref: message.attachmentHref,
      attachmentFilePath: join(message.directory, 'attachment.bin'),
      attachmentByteLength: message.attachmentByteLength,
      boundary: message.boundary,
      soapContentId: message.soapContentId,
    });
    const chunks: Buffer[] = [];
    for await (const chunk of multipart.stream) chunks.push(chunk as Buffer);
    const input: OpenAs4MessageInput = {
      contentType: multipart.contentType,
      body: (async function* () {
        yield Buffer.concat(chunks);
      })(),
      keyHolder: [holder],
      validateCertificate: testValidator(pki),
      receiverIdentity: { scheme: PEPPOL_PARTY_ID_TYPE, value: pki.receiver.commonName },
      now: () => new Date(),
    };
    const result = await openAs4Message(input);
    assert.equal(result.ok, true, JSON.stringify(result));
    if (!result.ok) throw new Error('unreachable');
    return {
      opened: result,
      cleanup: async () => {
        await result.dispose();
        await rm(dir, { recursive: true, force: true });
      },
    };
  } catch (err) {
    await message.dispose();
    await rm(dir, { recursive: true, force: true });
    throw err;
  }
}

test('builds a signed receipt that the sender verifies', async () => {
  const { opened, cleanup } = await openInbound();
  try {
    const result = await respondAs4Message({
      kind: 'accepted',
      receipt: opened.receipt,
      decision: 'committed',
      signer: signerFromKey(pki.receiver.keyObject, pki.receiver.certPem),
      now: () => new Date(),
    });
    assert.equal(result.ok, true, JSON.stringify(result));
    if (!result.ok) return;
    assert.equal(result.status, 200);
    assert.match(result.contentType, /application\/soap\+xml/);

    const signal = parseSignal(Buffer.from(result.body));
    assert.ok(signal, 'the response parses as a signal');
    assert.equal(signal.kind, 'receipt');
    assert.equal(signal.refToMessageId, AS4_MESSAGE_ID);

    const check = await verifyReceipt({
      signal: signal!,
      as4MessageId: AS4_MESSAGE_ID,
      receiverCertificatePem: pki.receiver.certPem,
      signedReferences: opened.receipt.signedReferences,
      validateCertificate: testValidator(pki),
      now: () => new Date(),
    });
    assert.equal(check.ok, true, JSON.stringify(check));
  } finally {
    await cleanup();
  }
});

test('builds a signed Not-serviced error with EBMS:0004 and PEPPOL:NOT_SERVICED', async () => {
  const result = await respondAs4Message({
    kind: 'rejected',
    correlation: { messageId: AS4_MESSAGE_ID, senderId: 'x', receiverId: 'y' },
    error: {
      code: EBMS_ERROR_CODE_NOT_SERVICED,
      severity: 'failure',
      detail: EBMS_ERROR_CODE_NOT_SERVICED_DETAIL,
    },
    signer: signerFromKey(pki.receiver.keyObject, pki.receiver.certPem),
    now: () => new Date(),
  });
  assert.equal(result.ok, true, JSON.stringify(result));
  if (!result.ok) return;
  const signal = parseSignal(Buffer.from(result.body));
  assert.ok(signal, 'the response parses as a signal');
  assert.equal(signal.kind, 'error');
  assert.equal(signal.refToMessageId, AS4_MESSAGE_ID);
  assert.equal(signal.errors[0]?.code, 'EBMS:0004');
  assert.equal(signal.errors[0]?.severity, 'failure');
  assert.equal(signal.errors[0]?.detail, 'PEPPOL:NOT_SERVICED');
  assert.match(Buffer.from(result.body).toString('utf8'), /PEPPOL:NOT_SERVICED/);
});

test('a rejected response needs no receipt facts', async () => {
  const result = await respondAs4Message({
    kind: 'rejected',
    correlation: { messageId: 'unknown@peer' },
    error: { code: 'EB:12', severity: 'failure' },
    signer: signerFromKey(pki.receiver.keyObject, pki.receiver.certPem),
    now: () => new Date(),
  });
  assert.equal(result.ok, true, JSON.stringify(result));
});

test('a serialised receipt context is enough to rebuild the response', async () => {
  const { opened, cleanup } = await openInbound();
  try {
    const serialised = JSON.parse(JSON.stringify(opened.receipt)) as ReceiptContext;
    const result = await respondAs4Message({
      kind: 'accepted',
      receipt: serialised,
      decision: 'already-committed',
      signer: signerFromKey(pki.receiver.keyObject, pki.receiver.certPem),
      now: () => new Date(),
    });
    assert.equal(result.ok, true, JSON.stringify(result));
    if (!result.ok) return;
    const signal = parseSignal(Buffer.from(result.body));
    assert.ok(signal);
    const check = await verifyReceipt({
      signal: signal!,
      as4MessageId: AS4_MESSAGE_ID,
      receiverCertificatePem: pki.receiver.certPem,
      signedReferences: opened.receipt.signedReferences,
      validateCertificate: testValidator(pki),
      now: () => new Date(),
    });
    assert.equal(check.ok, true, JSON.stringify(check));
  } finally {
    await cleanup();
  }
});

test('a cancelled response is a value, not a throw', async () => {
  const { opened, cleanup } = await openInbound();
  try {
    const controller = new AbortController();
    controller.abort();
    const result = await respondAs4Message({
      kind: 'accepted',
      receipt: opened.receipt,
      decision: 'committed',
      signer: signerFromKey(pki.receiver.keyObject, pki.receiver.certPem),
      now: () => new Date(),
      signal: controller.signal,
    });
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.reason, 'aborted');
  } finally {
    await cleanup();
  }
});

test('requires an explicit acceptance decision before signing', async () => {
  const { opened, cleanup } = await openInbound();
  const signer = signerFromKey(pki.receiver.keyObject, pki.receiver.certPem);
  try {
    for (const decision of [undefined, '', 'rejected']) {
      const result = await respondAs4Message({
        kind: 'accepted',
        receipt: opened.receipt,
        decision,
        signer,
        now: () => new Date(),
      } as unknown as AcceptResponseInput);
      assert.equal(result.ok, false, `decision ${String(decision)} must be rejected`);
      if (!result.ok) assert.equal(result.reason, 'respond.decision-required');
    }
  } finally {
    await cleanup();
  }
});

test('rejects an unsupported persisted receipt context with zero signing calls', async () => {
  const { opened, cleanup } = await openInbound();
  const inner = signerFromKey(pki.receiver.keyObject, pki.receiver.certPem);
  let signCalls = 0;
  const signer: Signer = {
    certificate: inner.certificate,
    async sign(data, signal) {
      signCalls += 1;
      return inner.sign(data, signal);
    },
  };
  const now = () => new Date();
  const attempt = (receipt: unknown) =>
    respondAs4Message({
      kind: 'accepted',
      receipt,
      decision: 'committed',
      signer,
      now,
    } as unknown as AcceptResponseInput);
  try {
    const [first, ...rest] = opened.receipt.signedReferences;
    const transform = first!.transforms[0]!;
    const cases: unknown[] = [
      { ...opened.receipt, signedReferences: [] },
      { ...opened.receipt, messageId: '' },
      { ...opened.receipt, signedReferences: [first, first, ...rest] },
      { ...opened.receipt, signedReferences: [{ ...first, digest: '' }] },
      { ...opened.receipt, signedReferences: [{ ...first, digest: 'not-a-digest' }] },
      { ...opened.receipt, signedReferences: [{ ...first, digestMethod: '' }] },
      { ...opened.receipt, signedReferences: [{ ...first, digestMethod: 'urn:unsupported' }] },
      { ...opened.receipt, signedReferences: [{ ...first, uri: 'https://example.test/external' }] },
      { ...opened.receipt, signedReferences: [{ ...first, uri: 'not-a-reference' }] },
      { ...opened.receipt, signedReferences: [{ ...first, uri: '#' }] },
      { ...opened.receipt, signedReferences: [{ ...first, uri: 'cid:' }] },
      { ...opened.receipt, signedReferences: [{ ...first, transforms: [] }] },
      { ...opened.receipt, signedReferences: [{ ...first, transforms: [{ algorithm: '', inclusivePrefixes: [] }] }] },
      {
        ...opened.receipt,
        signedReferences: [{ ...first, transforms: [{ algorithm: 'urn:unsupported', inclusivePrefixes: [] }] }],
      },
      {
        ...opened.receipt,
        signedReferences: [{ ...first, transforms: [{ algorithm: transform.algorithm, inclusivePrefixes: [7] }] }],
      },
    ];
    for (const receipt of cases) {
      const result = await attempt(receipt);
      assert.equal(result.ok, false, `must reject ${JSON.stringify(receipt)}`);
      if (!result.ok) assert.equal(result.reason, 'respond.invalid-receipt');
    }
    assert.equal(signCalls, 0, 'an invalid persisted context must never reach the signer');
  } finally {
    await cleanup();
  }
});

test('a signing failure is a value, not a throw', async () => {
  const { opened, cleanup } = await openInbound();
  try {
    const failing: Signer = {
      certificate: pki.receiver.certPem,
      sign(): Promise<Uint8Array> {
        return Promise.reject(new Error('HSM unavailable'));
      },
    };
    const result = await respondAs4Message({
      kind: 'accepted',
      receipt: opened.receipt,
      decision: 'committed',
      signer: failing,
      now: () => new Date(),
    });
    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(result.reason, 'respond.signing-failed');
      assert.match(result.detail ?? '', /HSM unavailable/);
    }
  } finally {
    await cleanup();
  }
});

test('an invalid clock is a value, not a throw', async () => {
  const { opened, cleanup } = await openInbound();
  try {
    const result = await respondAs4Message({
      kind: 'accepted',
      receipt: opened.receipt,
      decision: 'committed',
      signer: signerFromKey(pki.receiver.keyObject, pki.receiver.certPem),
      now: () => new Date(Number.NaN),
    });
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.reason, 'respond.invalid-input');
  } finally {
    await cleanup();
  }
});

test('a signer that aborts the signal cannot produce a receipt', async () => {
  const { opened, cleanup } = await openInbound();
  try {
    const controller = new AbortController();
    const inner = signerFromKey(pki.receiver.keyObject, pki.receiver.certPem);
    const aborter: Signer = {
      certificate: inner.certificate,
      async sign(data) {
        // Abort the operation, then still return a valid signature: the response
        // must not be issued after cancellation.
        controller.abort();
        return inner.sign(data);
      },
    };
    const result = await respondAs4Message({
      kind: 'accepted',
      receipt: opened.receipt,
      decision: 'committed',
      signer: aborter,
      now: () => new Date(),
      signal: controller.signal,
    });
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.reason, 'aborted');
  } finally {
    await cleanup();
  }
});

test('a stalled signer is interrupted by cancellation', async () => {
  const { opened, cleanup } = await openInbound();
  try {
    const controller = new AbortController();
    const stalled: Signer = {
      certificate: pki.receiver.certPem,
      sign(): Promise<Uint8Array> {
        return new Promise(() => {}); // never settles
      },
    };
    const pending = respondAs4Message({
      kind: 'accepted',
      receipt: opened.receipt,
      decision: 'committed',
      signer: stalled,
      now: () => new Date(),
      signal: controller.signal,
    });
    setTimeout(() => controller.abort(), 10);
    const result = await pending;
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.reason, 'aborted');
  } finally {
    await cleanup();
  }
});

test('a signer that aborts and rejects does not leak an unhandled rejection', async () => {
  const { opened, cleanup } = await openInbound();
  const leaked: unknown[] = [];
  const onUnhandled = (reason: unknown): void => {
    leaked.push(reason);
  };
  process.on('unhandledRejection', onUnhandled);
  try {
    const controller = new AbortController();
    const aborter: Signer = {
      certificate: pki.receiver.certPem,
      sign(): Promise<Uint8Array> {
        // Synchronously abort the operation, then reject: the started signing
        // promise must still be observed.
        controller.abort();
        return Promise.reject(new Error('signer aborted'));
      },
    };
    const result = await respondAs4Message({
      kind: 'accepted',
      receipt: opened.receipt,
      decision: 'committed',
      signer: aborter,
      now: () => new Date(),
      signal: controller.signal,
    });
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.reason, 'aborted');
    await new Promise((resolve) => setTimeout(resolve, 25));
    assert.deepEqual(leaked, []);
  } finally {
    process.off('unhandledRejection', onUnhandled);
    await cleanup();
  }
});

test('malformed runtime input is respond.invalid-input, not a throw', async () => {
  for (const input of [null, undefined, 42, 'accepted', {}, { kind: 'nope' }]) {
    const result = await respondAs4Message(input as unknown as RespondAs4MessageInput);
    assert.equal(result.ok, false, `must reject ${JSON.stringify(input)}`);
    if (!result.ok) assert.equal(result.reason, 'respond.invalid-input');
  }
});
