import test from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv, constants, privateDecrypt, publicEncrypt, randomBytes } from 'node:crypto';
import type { DecipherGCM } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { gzipSync } from 'node:zlib';
import { ALGO_SHA256, AS4_COMPRESSION_TYPE, SWA_TRANSFORM_SIGNATURE, XENC_NS } from '../src/constants.js';
import { buildEnvelope } from '../src/xml/envelope.js';
import { firstByLocalName, parseXml } from '../src/xml/nodes.js';
import { sha256Digest } from '../src/xml/c14n.js';
import { signerFromKey, peppolProfile } from '../src/index.js';
import { parseInboundEncryption } from '../src/receive/encryption.js';
import { recoverInboundPayload } from '../src/receive/payload.js';
import {
  defaultInboundLimits,
  type InboundEvent,
  type InboundKeyHolder,
  type RecoverInboundPayloadInput,
} from '../src/receive/types.js';
import { MessageBudget } from '../src/receive/budget.js';
import { attachmentDigestBase64 } from '../src/receive/attachment.js';
import { payloadHooks } from '../src/receive/payload-hooks.js';
import { createTestPki } from './helpers/pki.js';

const pki = createTestPki();
const DOCUMENT = Buffer.from(
  '<?xml version="1.0" encoding="UTF-8"?><StandardBusinessDocument><Invoice>42</Invoice></StandardBusinessDocument>',
  'utf8',
);

const holder: InboundKeyHolder = {
  certificate: pki.receiver.certPem,
  async unwrap(wrapped) {
    return privateDecrypt(
      { key: pki.receiver.keyObject, oaepHash: 'sha256', padding: constants.RSA_PKCS1_OAEP_PADDING },
      Buffer.from(wrapped),
    );
  },
};

/** Encrypt `representation` and build the inbound encryption graph with a controlled digest. */
async function makeInbound(representation: Buffer, options: { mediaType?: string; digest?: string } = {}) {
  const sessionKey = randomBytes(16);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-128-gcm', sessionKey, iv);
  const ciphertext = Buffer.concat([cipher.update(representation), cipher.final()]);
  const attachmentBytes = Buffer.concat([iv, ciphertext, cipher.getAuthTag()]);
  const wrappedKey = publicEncrypt(
    { key: pki.receiver.cert.publicKey, oaepHash: 'sha256', padding: constants.RSA_PKCS1_OAEP_PADDING },
    sessionKey,
  );
  const built = await buildEnvelope({
    userMessage: {
      messageId: 'inbound@test',
      timestamp: '2026-10-12T00:00:00.000Z',
      fromPartyId: pki.sender.commonName,
      toPartyId: pki.receiver.commonName,
      profile: peppolProfile,
      service: { scheme: 's', value: 'v' },
      action: 'a::b',
      originalSender: { scheme: 'iso6523-actorid-upis', value: '0192:1' },
      finalRecipient: { scheme: 'iso6523-actorid-upis', value: '0192:2' },
      payloadHref: 'cid:inbound@test',
      compressionType: AS4_COMPRESSION_TYPE,
    },
    signer: signerFromKey(pki.sender.keyObject, pki.sender.certPem),
    receiverCertificatePem: pki.receiver.certPem,
    wrappedKey,
    attachmentDigestBase64: sha256Digest(representation),
  });
  const doc = parseXml(built.xml);
  if (options.mediaType) firstByLocalName(doc, XENC_NS, 'EncryptedData')!.setAttribute('MimeType', options.mediaType);
  const encryption = parseInboundEncryption(doc);
  return {
    encryption,
    attachmentBytes,
    reference: {
      uri: encryption.attachmentHref,
      digest: options.digest ?? sha256Digest(representation),
      digestMethod: ALGO_SHA256,
      transforms: [{ algorithm: SWA_TRANSFORM_SIGNATURE, inclusivePrefixes: [] as string[] }],
    },
  };
}

function inputFor(
  built: Awaited<ReturnType<typeof makeInbound>>,
  overrides: Partial<RecoverInboundPayloadInput> = {},
): RecoverInboundPayloadInput {
  return {
    encryption: built.encryption,
    attachment: {
      contentId: built.encryption.attachmentHref.slice('cid:'.length),
      source: Readable.from([built.attachmentBytes]),
      byteLength: built.attachmentBytes.length,
    },
    reference: built.reference,
    compression: { kind: 'gzip', declaredBy: 'CompressionType' },
    keyHolder: [holder],
    limits: defaultInboundLimits,
    ...overrides,
  };
}

async function collect(stream: Readable): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks);
}

test('recovers a gzip payload and retains the exact compressed evidence', async () => {
  const representation = gzipSync(DOCUMENT);
  const built = await makeInbound(representation);
  const result = await recoverInboundPayload(inputFor(built));
  assert.equal(result.ok, true, JSON.stringify(result));
  if (!result.ok) return;
  try {
    assert.deepEqual(await collect(result.payload.read()), DOCUMENT);
    assert.equal(result.representation.rawDigestBase64, sha256Digest(representation));
    assert.equal(result.representation.transformDigestBase64, built.reference.digest);
    assert.equal(result.representation.byteLength, representation.length);
    assert.deepEqual(await collect(result.representation.read()), representation);
    assert.equal(result.credential.certificate, pki.receiver.certPem);
  } finally {
    await result.dispose();
  }
});

test('a wrong signed digest is rejected before decompression', async () => {
  // The representation is not valid gzip, so if decompression ran first it would
  // fail with decompress.failed. The digest check in pass 1 must win.
  const representation = Buffer.from('not gzip at all', 'utf8');
  const built = await makeInbound(representation, { digest: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' });
  const result = await recoverInboundPayload(inputFor(built));
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'signature.attachment-digest');
});

test('a tampered ciphertext fails GCM authentication', async () => {
  const built = await makeInbound(gzipSync(DOCUMENT));
  const index = built.attachmentBytes.length - 20;
  built.attachmentBytes[index] = built.attachmentBytes[index]! ^ 0xff;
  const result = await recoverInboundPayload(inputFor(built));
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'decrypt.gcm-auth');
});

test('rejects a truncated ciphertext layout without unwrapping', async () => {
  const built = await makeInbound(gzipSync(DOCUMENT));
  const short = Buffer.concat([built.attachmentBytes.subarray(0, 20)]);
  let unwraps = 0;
  const result = await recoverInboundPayload(
    inputFor(built, {
      attachment: { contentId: built.encryption.attachmentHref.slice(4), source: Readable.from([short]) },
      keyHolder: [
        {
          certificate: pki.receiver.certPem,
          async unwrap() {
            unwraps += 1;
            return randomBytes(16);
          },
        },
      ],
    }),
  );
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'encryption.invalid');
  assert.equal(unwraps, 0, 'the framing is checked before any credential is used');
});

test('recovers uncompressed XML and keeps the original bytes as the payload', async () => {
  const built = await makeInbound(DOCUMENT, {
    mediaType: 'application/xml',
    digest: attachmentDigestBase64('application/xml', DOCUMENT),
  });
  const recovered = await recoverInboundPayload(inputFor(built, { compression: { kind: 'none' } }));
  assert.equal(recovered.ok, true, JSON.stringify(recovered));
  if (!recovered.ok) return;
  try {
    assert.deepEqual(await collect(recovered.payload.read()), DOCUMENT);
    assert.equal(recovered.representation.rawDigestBase64, sha256Digest(DOCUMENT));
    assert.equal(recovered.representation.transformDigestBase64, attachmentDigestBase64('application/xml', DOCUMENT));
  } finally {
    await recovered.dispose();
  }
});

test('enforces the decompressed-size limit', async () => {
  const built = await makeInbound(gzipSync(Buffer.alloc(4096, 0x61)));
  const result = await recoverInboundPayload(
    inputFor(built, { limits: { ...defaultInboundLimits, maxDecompressedBytes: 100 } }),
  );
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'payload.too-large');
});

test('enforces the message aggregate output budget', async () => {
  const built = await makeInbound(gzipSync(DOCUMENT));
  const result = await recoverInboundPayload(inputFor(built, { budget: new MessageBudget(1) }));
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'payload.too-large');
});

test('handle disposal does not invalidate the other handle, and the bundle is idempotent', async () => {
  const representation = gzipSync(DOCUMENT);
  const built = await makeInbound(representation);
  const result = await recoverInboundPayload(inputFor(built));
  assert.equal(result.ok, true);
  if (!result.ok) return;

  await result.payload.dispose();
  assert.throws(() => result.payload.read(), /disposed/);
  assert.deepEqual(await collect(result.representation.read()), representation);

  await result.representation.dispose();
  await result.dispose(); // idempotent
  await result.dispose();
});

test('a failed recovery leaves no scratch files behind', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'as4-recover-'));
  try {
    const built = await makeInbound(gzipSync(DOCUMENT));
    const index = built.attachmentBytes.length - 20;
    built.attachmentBytes[index] = built.attachmentBytes[index]! ^ 0xff;
    const result = await recoverInboundPayload(inputFor(built, { spoolDirectory: dir }));
    assert.equal(result.ok, false);
    assert.deepEqual(await readdir(dir), []);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('an invalid gzip trailer is rejected after authentication', async () => {
  const representation = gzipSync(DOCUMENT);
  // Corrupt the CRC/length trailer while keeping the raw digest (pass 1) valid,
  // so the failure can only come from decompression.
  representation[representation.length - 8] = representation[representation.length - 8]! ^ 0xff;
  const built = await makeInbound(representation);
  const result = await recoverInboundPayload(inputFor(built));
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'decompress.failed');
});

test('the decompressed-size limit is inclusive at its boundary', async () => {
  const built = await makeInbound(gzipSync(DOCUMENT));
  const ok = await recoverInboundPayload(
    inputFor(built, { limits: { ...defaultInboundLimits, maxDecompressedBytes: DOCUMENT.length } }),
  );
  assert.equal(ok.ok, true, JSON.stringify(ok));
  if (ok.ok) await ok.dispose();

  const built2 = await makeInbound(gzipSync(DOCUMENT));
  const tooSmall = await recoverInboundPayload(
    inputFor(built2, { limits: { ...defaultInboundLimits, maxDecompressedBytes: DOCUMENT.length - 1 } }),
  );
  assert.equal(tooSmall.ok, false);
  if (!tooSmall.ok) assert.equal(tooSmall.reason, 'payload.too-large');
});

test('an observer that throws does not fail the recovery', async () => {
  const built = await makeInbound(gzipSync(DOCUMENT));
  const result = await recoverInboundPayload(
    inputFor(built, {
      onEvent: () => {
        throw new Error('observer exploded');
      },
    }),
  );
  assert.equal(result.ok, true, JSON.stringify(result));
  if (result.ok) await result.dispose();
});

test('rejects a mismatched attachment binding before spooling or unwrapping', async () => {
  let unwraps = 0;
  const spy: InboundKeyHolder = {
    certificate: pki.receiver.certPem,
    async unwrap(wrapped) {
      unwraps += 1;
      return privateDecrypt(
        { key: pki.receiver.keyObject, oaepHash: 'sha256', padding: constants.RSA_PKCS1_OAEP_PADDING },
        Buffer.from(wrapped),
      );
    },
  };

  const wrongReference = await makeInbound(gzipSync(DOCUMENT));
  const refResult = await recoverInboundPayload(
    inputFor(wrongReference, {
      reference: { ...wrongReference.reference, uri: 'cid:someone-else@x' },
      keyHolder: [spy],
    }),
  );
  assert.equal(refResult.ok, false);
  if (!refResult.ok) assert.equal(refResult.reason, 'signature.coverage');

  const wrongContentId = await makeInbound(gzipSync(DOCUMENT));
  const idResult = await recoverInboundPayload(
    inputFor(wrongContentId, {
      attachment: { contentId: 'someone-else@x', source: Readable.from([wrongContentId.attachmentBytes]) },
      keyHolder: [spy],
    }),
  );
  assert.equal(idResult.ok, false);
  if (!idResult.ok) assert.equal(idResult.reason, 'signature.coverage');

  assert.equal(unwraps, 0, 'no credential is used for an inconsistent binding');
});

test('applies the output limit to uncompressed and XML payloads', async () => {
  const binary = Buffer.from('plain binary payload', 'utf8');
  const binaryBuilt = await makeInbound(binary, { digest: sha256Digest(binary) });
  const binaryResult = await recoverInboundPayload(
    inputFor(binaryBuilt, {
      compression: { kind: 'none' },
      limits: { ...defaultInboundLimits, maxDecompressedBytes: 1 },
    }),
  );
  assert.equal(binaryResult.ok, false);
  if (!binaryResult.ok) assert.equal(binaryResult.reason, 'payload.too-large');

  const xmlBuilt = await makeInbound(DOCUMENT, {
    mediaType: 'application/xml',
    digest: attachmentDigestBase64('application/xml', DOCUMENT),
  });
  const xmlResult = await recoverInboundPayload(
    inputFor(xmlBuilt, { compression: { kind: 'none' }, limits: { ...defaultInboundLimits, maxDecompressedBytes: 1 } }),
  );
  assert.equal(xmlResult.ok, false);
  if (!xmlResult.ok) assert.equal(xmlResult.reason, 'payload.too-large');
});

test('the aggregate limit applies even without an explicit budget', async () => {
  const built = await makeInbound(gzipSync(DOCUMENT));
  const result = await recoverInboundPayload(
    inputFor(built, { limits: { ...defaultInboundLimits, maxAggregateOutputBytes: 1 } }),
  );
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'payload.too-large');
});

test('rejects an XML representation larger than maxXmlBytes before reading it', async () => {
  const built = await makeInbound(DOCUMENT, {
    mediaType: 'application/xml',
    digest: attachmentDigestBase64('application/xml', DOCUMENT),
  });
  const result = await recoverInboundPayload(
    inputFor(built, { compression: { kind: 'none' }, limits: { ...defaultInboundLimits, maxXmlBytes: 1 } }),
  );
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'xml.too-large');
});

test('cancellation after materialization is observed (uncompressed and XML)', async () => {
  const binary = Buffer.from('plain binary payload', 'utf8');
  for (const [representation, options] of [
    [binary, { digest: sha256Digest(binary) }],
    [DOCUMENT, { mediaType: 'application/xml', digest: attachmentDigestBase64('application/xml', DOCUMENT) }],
  ] as const) {
    const built = await makeInbound(representation, options);
    const controller = new AbortController();
    const result = await recoverInboundPayload(
      inputFor(built, {
        compression: { kind: 'none' },
        signal: controller.signal,
        onEvent: (event) => {
          if (event.phase === 'materialize') controller.abort();
        },
      }),
    );
    assert.equal(result.ok, false, JSON.stringify(result));
    if (!result.ok) assert.equal(result.reason, 'aborted');
  }
});

test('bundle disposal destroys an active reader', async () => {
  const built = await makeInbound(gzipSync(DOCUMENT));
  const result = await recoverInboundPayload(inputFor(built));
  assert.equal(result.ok, true);
  if (!result.ok) return;
  const stream = result.payload.read();
  stream.on('error', () => {});
  await result.dispose();
  assert.equal(stream.destroyed, true);
});

test('gzip policy: concatenated members decode together; NUL padding is tolerated; other trailing data fails', async () => {
  const member = gzipSync(DOCUMENT);
  const extra = gzipSync(Buffer.from('<extra/>'));

  const concatenated = await makeInbound(Buffer.concat([member, extra]));
  const concatenatedResult = await recoverInboundPayload(inputFor(concatenated));
  assert.equal(concatenatedResult.ok, true, JSON.stringify(concatenatedResult));
  if (concatenatedResult.ok) {
    assert.deepEqual(
      await collect(concatenatedResult.payload.read()),
      Buffer.concat([DOCUMENT, Buffer.from('<extra/>')]),
    );
    await concatenatedResult.dispose();
  }

  const padded = await makeInbound(Buffer.concat([member, Buffer.alloc(4)]));
  const paddedResult = await recoverInboundPayload(inputFor(padded));
  assert.equal(paddedResult.ok, true, JSON.stringify(paddedResult));
  if (paddedResult.ok) {
    assert.deepEqual(await collect(paddedResult.payload.read()), DOCUMENT);
    await paddedResult.dispose();
  }

  const garbage = await makeInbound(Buffer.concat([member, Buffer.from('garbage')]));
  const garbageResult = await recoverInboundPayload(inputFor(garbage));
  assert.equal(garbageResult.ok, false);
  if (!garbageResult.ok) assert.equal(garbageResult.reason, 'decompress.failed');

  // A NUL followed by non-padding data is not NUL-only padding.
  const nulThenGarbage = await makeInbound(Buffer.concat([member, Buffer.from([0]), Buffer.from('garbage')]));
  const nulThenGarbageResult = await recoverInboundPayload(inputFor(nulThenGarbage));
  assert.equal(nulThenGarbageResult.ok, false);
  if (!nulThenGarbageResult.ok) assert.equal(nulThenGarbageResult.reason, 'decompress.failed');

  // ...and a NUL followed by a second member is not a valid concatenation.
  const nulThenMember = await makeInbound(Buffer.concat([member, Buffer.from([0]), extra]));
  const nulThenMemberResult = await recoverInboundPayload(inputFor(nulThenMember));
  assert.equal(nulThenMemberResult.ok, false);
  if (!nulThenMemberResult.ok) assert.equal(nulThenMemberResult.reason, 'decompress.failed');
});

test('an invalid aggregate limit is returned as a failure fact', async () => {
  const built = await makeInbound(gzipSync(DOCUMENT));
  const result = await recoverInboundPayload(
    inputFor(built, { limits: { ...defaultInboundLimits, maxAggregateOutputBytes: Number.NaN } }),
  );
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'limits.invalid');
});

test('a limit failure returns promptly even when source cleanup stalls and no signal is given', async () => {
  let returned = false;
  const source: AsyncIterable<Uint8Array> = {
    [Symbol.asyncIterator]() {
      let sent = false;
      return {
        next(): Promise<IteratorResult<Uint8Array>> {
          if (sent) return Promise.resolve({ value: undefined, done: true });
          sent = true;
          return Promise.resolve({ value: gzipSync(DOCUMENT), done: false });
        },
        return(): Promise<IteratorResult<Uint8Array>> {
          returned = true;
          return new Promise(() => {}); // never resolves
        },
      };
    },
  };
  const built = await makeInbound(gzipSync(DOCUMENT));
  const result = await recoverInboundPayload(
    inputFor(built, {
      attachment: { contentId: built.encryption.attachmentHref.slice(4), source },
      limits: { ...defaultInboundLimits, maxPartBytes: 4 },
    }),
  );
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'payload.too-large');
  assert.ok(returned, 'the stalled source was signalled for cleanup');
});

test('no plaintext is written before pass-one authentication', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'as4-writes-'));
  const writes: string[] = [];
  payloadHooks.onWriteStream = (path) => writes.push(path);
  try {
    // A wrong digest fails in pass 1, so pass 2 must never open a writer.
    const built = await makeInbound(gzipSync(DOCUMENT), { digest: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' });
    const result = await recoverInboundPayload(inputFor(built, { spoolDirectory: dir }));
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.reason, 'signature.attachment-digest');
    assert.deepEqual(
      writes.map((path) => path.split('/').pop()),
      ['ciphertext.bin'],
    );
  } finally {
    payloadHooks.onWriteStream = undefined;
    await rm(dir, { recursive: true, force: true });
  }
});

test('a second-pass finalization failure yields gcm-auth and removes partial files', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'as4-pass2-'));
  let calls = 0;
  payloadHooks.createDecipher = (algorithm, key, iv) => {
    calls += 1;
    if (calls === 2) {
      return {
        setAuthTag: () => {},
        update: () => Buffer.alloc(0),
        final: () => {
          throw new Error('forced second-pass finalization failure');
        },
      } as unknown as DecipherGCM;
    }
    return createDecipheriv(algorithm, key, iv) as DecipherGCM;
  };
  try {
    const built = await makeInbound(gzipSync(DOCUMENT));
    const result = await recoverInboundPayload(inputFor(built, { spoolDirectory: dir }));
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.reason, 'decrypt.gcm-auth');
    assert.equal(calls, 2, 'each pass used a fresh decipher');
    assert.deepEqual(await readdir(dir), [], 'partial outputs are removed');
  } finally {
    payloadHooks.createDecipher = undefined;
    await rm(dir, { recursive: true, force: true });
  }
});

test('a failed disposal is reported, retryable and idempotent', async (t) => {
  if (process.platform === 'win32') {
    t.skip('permission-based cleanup failure requires POSIX permissions');
    return;
  }
  const spool = await mkdtemp(join(tmpdir(), 'as4-dispose-'));
  const events: InboundEvent[] = [];
  try {
    const built = await makeInbound(gzipSync(DOCUMENT));
    const result = await recoverInboundPayload(
      inputFor(built, { spoolDirectory: spool, onEvent: (e) => events.push(e) }),
    );
    assert.equal(result.ok, true);
    if (!result.ok) return;

    const [child] = await readdir(spool);
    const locked = join(spool, child!, 'locked');
    await mkdir(locked);
    await writeFile(join(locked, 'f'), 'x');
    await chmod(locked, 0o500);

    await result.dispose(); // fails, reported, not thrown
    assert.ok(
      events.some((e) => e.phase === 'cleanup'),
      'a cleanup diagnostic is emitted',
    );
    await result.dispose(); // retry while still locked

    await chmod(locked, 0o700);
    await result.dispose(); // retry now succeeds
    assert.deepEqual(await readdir(spool), []);
  } finally {
    await rm(spool, { recursive: true, force: true });
  }
});
