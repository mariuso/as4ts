import assert from 'node:assert/strict';
import { createHash, createPrivateKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createCertificateValidator, defaultRevocationPolicy } from '../../src/certificate-validator.js';
import { keyHolderFromKey } from '../../src/receive/key-holder.js';
import { openAs4Message } from '../../src/receive/open.js';
import { defaultInboundLimits } from '../../src/receive/types.js';
import type { InboundLimits, OpenSuccess } from '../../src/receive/types.js';
import type { ScopedId } from '../../src/types.js';

/**
 * Load and verify a recorded inbound capture through the real receiving path
 * (`openAs4Message`), not merely the envelope verifier. A capture is one
 * directory under `test/fixtures/inbound/<name>/` (see
 * docs/receiving-fixtures.md); its metadata records what the sender actually put
 * on the wire, and its files carry the test-only credentials needed to decrypt
 * and to validate the signer.
 *
 * This runs the whole path: bounded MIME parse, strict XML, signature and
 * coverage, certificate validation against the supplied trust chain, session-key
 * unwrap with the captured receiver credential, decryption, and payload
 * recovery. It then compares the recovered payload hash and the complete
 * reference set (URI, digest, digest method, ordered transforms with inclusive
 * prefixes), and disposes every returned handle.
 */

export type CaptureOrigin = 'independent' | 'local';

export interface CaptureTransform {
  readonly algorithm: string;
  readonly inclusivePrefixes: readonly string[];
}

export interface CaptureReference {
  readonly uri: string;
  readonly digest: string;
  readonly digestMethod: string;
  readonly transforms: readonly CaptureTransform[];
}

export interface CaptureMetadata {
  readonly schema: 1;
  readonly origin: CaptureOrigin;
  readonly capturedAt: string;
  readonly contentType: string;
  readonly sender: {
    readonly implementation: string;
    readonly version: string;
    readonly configuration?: string;
  };
  readonly transportProfile: string;
  /** The sender's AS4 access-point identity (From/PartyId — the certificate CN). */
  readonly senderParticipant: ScopedId;
  /** The receiver's AS4 access-point identity (To/PartyId — the certificate CN). */
  readonly receiverParticipant: ScopedId;
  /** The integrated-SBDH business participants (message properties), when recorded. */
  readonly originalSender?: ScopedId;
  readonly finalRecipient?: ScopedId;
  readonly documentType: ScopedId;
  readonly process: ScopedId;
  readonly expectedParts: number;
  readonly expectedCoverage: { readonly messaging: boolean; readonly body: boolean };
  readonly expectedPayloadSha256Base64: string;
  readonly expectedSignedReferences: readonly CaptureReference[];
  /** Whether the sender accepted the receipt this receiver generated for it. */
  readonly senderAcceptsReceipt: boolean;
}

export interface LoadedCapture {
  readonly dir: string;
  readonly name: string;
  readonly metadata: CaptureMetadata;
  readonly body: Buffer;
  readonly receiverCertPem: string;
  readonly receiverKeyPem: string;
  readonly roots: string[];
  readonly intermediates: string[];
}

export interface CaptureFacts {
  readonly name: string;
  readonly origin: CaptureOrigin;
  readonly messageId: string;
  readonly senderId: string;
  readonly receiverId: string;
  readonly payloadSha256Base64: string;
  readonly referenceCount: number;
}

function readRequired(dir: string, file: string): Buffer {
  try {
    return readFileSync(join(dir, file));
  } catch {
    throw new Error(`capture ${dir} is missing ${file}`);
  }
}

function readPem(dir: string, file: string): string {
  return readRequired(dir, file).toString('utf8').trim();
}

export function loadCapture(dir: string, name = dir): LoadedCapture {
  const metadata = JSON.parse(readRequired(dir, 'metadata.json').toString('utf8')) as CaptureMetadata;
  if (metadata.schema !== 1) throw new Error(`capture ${dir} has an unsupported metadata schema`);
  if (metadata.origin !== 'independent' && metadata.origin !== 'local') {
    throw new Error(`capture ${dir} must declare origin "independent" or "local"`);
  }
  return {
    dir,
    name,
    metadata,
    body: readRequired(dir, 'request.bin'),
    receiverCertPem: readPem(dir, 'receiver-cert.pem'),
    receiverKeyPem: readPem(dir, 'receiver-key.pem'),
    roots: [readPem(dir, 'trust-roots.pem')],
    intermediates: [readPem(dir, 'trust-intermediates.pem')],
  };
}

async function collect(stream: NodeJS.ReadableStream): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(Buffer.from(chunk as Uint8Array));
  return Buffer.concat(chunks);
}

function normalizedTransforms(reference: {
  readonly transforms: readonly { readonly algorithm: string; readonly inclusivePrefixes: readonly string[] }[];
}): CaptureTransform[] {
  return reference.transforms.map((transform) => ({
    algorithm: transform.algorithm,
    inclusivePrefixes: [...transform.inclusivePrefixes].sort(),
  }));
}

/**
 * Verify one capture end to end and return its facts. Throws (via `assert`) on
 * any mismatch, so both the test suite and the Phase 6 validation command can
 * rely on it.
 */
export async function verifyCapture(
  capture: LoadedCapture,
  limits: InboundLimits = defaultInboundLimits,
): Promise<CaptureFacts> {
  const { metadata } = capture;
  // A capture that declares it does not cover the Body/Messaging conflicts with
  // the selected coverage policy; surface it as a fixture/policy mismatch rather
  // than letting the open failure speak for it.
  assert.equal(metadata.expectedCoverage.messaging, true, `${capture.name}: capture must cover eb:Messaging`);
  assert.equal(metadata.expectedCoverage.body, true, `${capture.name}: capture must cover the SOAP Body`);

  const keyHolder = keyHolderFromKey(createPrivateKey(capture.receiverKeyPem), capture.receiverCertPem);
  const validator = createCertificateValidator({
    roots: capture.roots,
    intermediates: capture.intermediates,
    revocation: defaultRevocationPolicy({ ocsp: false, crl: false }),
  });

  const opened = await openAs4Message({
    contentType: metadata.contentType,
    body: (async function* () {
      yield capture.body;
    })(),
    keyHolder,
    validateCertificate: (input) => validator.validate(input),
    receiverIdentity: metadata.receiverParticipant,
    limits,
    now: () => new Date(metadata.capturedAt),
  });
  assert.equal(opened.ok, true, `${capture.name}: open failed: ${JSON.stringify(opened)}`);
  if (!opened.ok) throw new Error('unreachable');

  try {
    return await assertFacts(capture, opened);
  } finally {
    // Dispose every returned handle, on success or on an assertion failure.
    await opened.dispose();
  }
}

async function assertFacts(capture: LoadedCapture, opened: OpenSuccess): Promise<CaptureFacts> {
  const { metadata, name } = capture;

  // Identity binding: the signer is the sender AP, and the message was addressed
  // to the captured receiver.
  assert.equal(opened.senderId, metadata.senderParticipant.value, `${name}: sender AP identity`);
  assert.equal(opened.receiverId, metadata.receiverParticipant.value, `${name}: receiver AP identity`);
  if (metadata.originalSender) {
    assert.deepEqual(opened.originalSender, metadata.originalSender, `${name}: business originalSender`);
  }
  if (metadata.finalRecipient) {
    assert.deepEqual(opened.finalRecipient, metadata.finalRecipient, `${name}: business finalRecipient`);
  }

  // Complete reference set: URI, digest, digest method, ordered transforms and
  // inclusive-prefix parameters. No expected reference may be missing and no
  // unexpected reference may be present.
  const actual = opened.receipt.signedReferences;
  assert.equal(
    actual.length,
    metadata.expectedSignedReferences.length,
    `${name}: reference count (${actual.map((r) => r.uri).join(', ')})`,
  );
  const byUri = new Map(actual.map((reference) => [reference.uri, reference]));
  for (const expected of metadata.expectedSignedReferences) {
    const reference = byUri.get(expected.uri);
    assert.ok(reference, `${name}: expected reference ${expected.uri}`);
    assert.equal(reference.digest, expected.digest, `${name}: digest for ${expected.uri}`);
    assert.equal(reference.digestMethod, expected.digestMethod, `${name}: digest method for ${expected.uri}`);
    assert.deepEqual(
      normalizedTransforms(reference),
      normalizedTransforms(expected),
      `${name}: transforms for ${expected.uri}`,
    );
  }

  // The recovered payload must match the independently recorded hash.
  const payload = await collect(opened.payload.read());
  const payloadSha256Base64 = createHash('sha256').update(payload).digest('base64');
  assert.equal(payloadSha256Base64, metadata.expectedPayloadSha256Base64, `${name}: recovered payload hash`);
  assert.equal(opened.payload.digestBase64, metadata.expectedPayloadSha256Base64, `${name}: payload handle hash`);

  return {
    name,
    origin: metadata.origin,
    messageId: opened.messageId,
    senderId: opened.senderId,
    receiverId: opened.receiverId,
    payloadSha256Base64,
    referenceCount: actual.length,
  };
}
