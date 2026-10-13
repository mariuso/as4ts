import assert from 'node:assert/strict';
import { createHash, createPrivateKey, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createCertificateValidator, defaultRevocationPolicy } from '../../src/certificate-validator.js';
import { keyHolderFromKey } from '../../src/receive/key-holder.js';
import { parseMultipartRelated, type MimeLimits } from '../../src/receive/mime.js';
import { openAs4Message } from '../../src/receive/open.js';
import { defaultInboundLimits } from '../../src/receive/types.js';
import type { InboundLimits, OpenSuccess } from '../../src/receive/types.js';
import { verifyReceipt } from '../../src/receipt/verify.js';
import type { ScopedId, ValidateCertificate } from '../../src/types.js';
import { parseSignal } from '../../src/xml/signal.js';

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
 * recovery. It then compares the recovered payload hash, the declared process /
 * document type / part count, and the complete reference set (an exact URI set,
 * with digest, digest method and ordered transforms including inclusive
 * prefixes), checks the recorded sender acceptance, and disposes every handle.
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

/** The sender's recorded result for the receipt this receiver generated. */
export interface SenderAcceptanceEvidence {
  readonly implementation: string;
  readonly version?: string;
  readonly accepted: boolean;
  readonly refToMessageId: string;
  readonly recordedAt: string;
  /** The actual response bytes the sender accepted, as evidence. */
  readonly responseFile?: string;
  readonly responseSha256Base64?: string;
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
  /** Whether the sender accepted the receipt, and where the supporting evidence is. */
  readonly senderAcceptance: { readonly accepted: boolean; readonly evidenceFile: string };
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
  /** The parsed sender-acceptance evidence, validated for coherence. */
  readonly senderAcceptance: SenderAcceptanceEvidence;
  /** The exact response bytes the sender accepted, when an accepted exchange recorded them. */
  readonly acceptanceResponse: Buffer | null;
}

export interface CaptureFacts {
  readonly name: string;
  readonly origin: CaptureOrigin;
  readonly implementation: string;
  readonly senderAccepted: boolean;
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

/**
 * Split a PEM bundle into individual certificate blocks and reject any block
 * that does not parse. The validator expects one certificate per array entry, so
 * a bundle's additional certificates must not be dropped.
 */
export function splitPemCertificates(text: string): string[] {
  const blocks = text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
  return blocks.map((block) => {
    const pem = block.trim();
    try {
      void new X509Certificate(pem);
    } catch {
      throw new Error('a certificate block in the trust material does not parse');
    }
    return pem;
  });
}

/**
 * An explicitly zoned ISO 8601 timestamp. A naive or malformed string becomes an
 * invalid `Date`, which would silently weaken certificate validation at
 * verification time, so it is rejected up front.
 */
function requireZonedTimestamp(value: unknown, label: string): string {
  if (
    typeof value !== 'string' ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(value)
  ) {
    throw new Error(`${label} must be an ISO 8601 timestamp with an explicit zone`);
  }
  if (Number.isNaN(new Date(value).getTime())) throw new Error(`${label} is not a valid date`);
  return value;
}

/** Validate the required metadata centrally, so the suite and the gate agree. */
export function validateCaptureMetadata(metadata: CaptureMetadata, dir = '<capture>'): void {
  const fail = (message: string): never => {
    throw new Error(`${dir}: ${message}`);
  };
  if (metadata.schema !== 1) fail('unsupported metadata schema');
  if (metadata.origin !== 'independent' && metadata.origin !== 'local') {
    fail('origin must be "independent" or "local"');
  }
  if (!metadata.capturedAt) fail('capturedAt is required');
  requireZonedTimestamp(metadata.capturedAt, `${dir}: capturedAt`);
  if (!metadata.contentType) fail('contentType is required');
  if (!metadata.sender?.implementation) fail('sender.implementation is required');
  if (!metadata.sender?.version) fail('sender.version is required');
  for (const field of ['senderParticipant', 'receiverParticipant', 'documentType', 'process'] as const) {
    const value = metadata[field];
    if (!value?.scheme || !value?.value) fail(`${field} (scheme and value) is required`);
  }
  if (!Number.isInteger(metadata.expectedParts) || metadata.expectedParts < 2) {
    fail('expectedParts must be an integer >= 2');
  }
  if (metadata.expectedCoverage?.messaging !== true || metadata.expectedCoverage?.body !== true) {
    fail('expectedCoverage must require both messaging and body');
  }
  if (!metadata.expectedPayloadSha256Base64) fail('expectedPayloadSha256Base64 is required');
  const references = metadata.expectedSignedReferences;
  if (!Array.isArray(references) || references.length === 0) {
    fail('expectedSignedReferences must be a non-empty array');
  }
  const seen = new Set<string>();
  for (const reference of references) {
    if (!reference?.uri || !reference?.digest || !reference?.digestMethod) {
      fail('every expected reference needs uri, digest and digestMethod');
    }
    if (!Array.isArray(reference.transforms) || reference.transforms.length === 0) {
      fail(`reference ${reference.uri} needs at least one transform`);
    }
    if (seen.has(reference.uri)) fail(`duplicate expected reference ${reference.uri}`);
    seen.add(reference.uri);
  }
  if (
    !metadata.senderAcceptance ||
    typeof metadata.senderAcceptance.accepted !== 'boolean' ||
    !metadata.senderAcceptance.evidenceFile
  ) {
    fail('senderAcceptance { accepted, evidenceFile } is required');
  }
}

function readSenderAcceptance(
  dir: string,
  name: string,
  metadata: CaptureMetadata,
): { evidence: SenderAcceptanceEvidence; response: Buffer | null } {
  const raw = readRequired(dir, metadata.senderAcceptance.evidenceFile);
  let evidence: SenderAcceptanceEvidence;
  try {
    evidence = JSON.parse(raw.toString('utf8')) as SenderAcceptanceEvidence;
  } catch {
    throw new Error(`${name}: sender-acceptance evidence is not valid JSON`);
  }
  assert.equal(typeof evidence.accepted, 'boolean', `${name}: evidence.accepted must be a boolean`);
  assert.equal(
    evidence.accepted,
    metadata.senderAcceptance.accepted,
    `${name}: evidence.accepted must match metadata.senderAcceptance.accepted`,
  );
  assert.equal(evidence.implementation, metadata.sender.implementation, `${name}: evidence implementation`);
  if (evidence.version !== undefined) {
    assert.equal(evidence.version, metadata.sender.version, `${name}: evidence version`);
  }
  requireZonedTimestamp(evidence.recordedAt, `${name}: evidence.recordedAt`);

  if (evidence.accepted) {
    // An accepted exchange must preserve the exact response bytes and their hash;
    // a boolean is only an assertion. That the bytes are a receipt for this
    // request is checked against the opened message in `assertFacts`.
    assert.ok(evidence.responseFile, `${name}: an accepted exchange must record the accepted response file`);
    assert.ok(evidence.responseSha256Base64, `${name}: an accepted exchange must record the response hash`);
  }

  let response: Buffer | null = null;
  if (evidence.responseFile) {
    response = readRequired(dir, evidence.responseFile);
    assert.ok(response.length > 0, `${name}: the recorded response must not be empty`);
    if (evidence.responseSha256Base64) {
      assert.equal(
        createHash('sha256').update(response).digest('base64'),
        evidence.responseSha256Base64,
        `${name}: recorded response hash`,
      );
    }
  }
  return { evidence, response };
}

export function loadCapture(dir: string, name = dir): LoadedCapture {
  const metadata = JSON.parse(readRequired(dir, 'metadata.json').toString('utf8')) as CaptureMetadata;
  validateCaptureMetadata(metadata, dir);
  const roots = splitPemCertificates(readPem(dir, 'trust-roots.pem'));
  const intermediates = splitPemCertificates(readPem(dir, 'trust-intermediates.pem'));
  if (roots.length === 0) throw new Error(`capture ${dir}: trust-roots.pem contains no certificate`);
  if (intermediates.length === 0) throw new Error(`capture ${dir}: trust-intermediates.pem contains no certificate`);
  const acceptance = readSenderAcceptance(dir, name, metadata);
  return {
    dir,
    name,
    metadata,
    body: readRequired(dir, 'request.bin'),
    receiverCertPem: readPem(dir, 'receiver-cert.pem'),
    receiverKeyPem: readPem(dir, 'receiver-key.pem'),
    roots,
    intermediates,
    senderAcceptance: acceptance.evidence,
    acceptanceResponse: acceptance.response,
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

function mimeLimits(): MimeLimits {
  return {
    maxRequestBytes: defaultInboundLimits.maxRequestBytes,
    maxParts: defaultInboundLimits.maxParts,
    maxHeaderBytes: defaultInboundLimits.maxHeaderBytes,
    maxPartBytes: defaultInboundLimits.maxPartBytes,
    maxBoundaryLength: defaultInboundLimits.maxBoundaryLength,
  };
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
    return await assertFacts(capture, opened, (input) => validator.validate(input));
  } finally {
    // Dispose every returned handle, on success or on an assertion failure.
    await opened.dispose();
  }
}

async function assertFacts(
  capture: LoadedCapture,
  opened: OpenSuccess,
  validateCertificate: ValidateCertificate,
): Promise<CaptureFacts> {
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

  // Declared process and document type (the Action encodes the document type).
  assert.deepEqual(opened.service, metadata.process, `${name}: process (CollaborationInfo/Service)`);
  assert.equal(
    opened.action,
    `${metadata.documentType.scheme}::${metadata.documentType.value}`,
    `${name}: document type (Action)`,
  );

  // Declared MIME structure.
  const parsed = await parseMultipartRelated({
    contentType: metadata.contentType,
    body: (async function* () {
      yield capture.body;
    })(),
    limits: mimeLimits(),
  });
  assert.equal(parsed.parts.length, metadata.expectedParts, `${name}: MIME part count`);

  // Complete reference set: an exact URI set with no duplicates on either side,
  // and matching digest, digest method and ordered transforms (with inclusive
  // prefixes) for every URI.
  const actual = opened.receipt.signedReferences;
  const expected = metadata.expectedSignedReferences;
  const expectedUris = new Set(expected.map((reference) => reference.uri));
  assert.equal(expectedUris.size, expected.length, `${name}: duplicate expected reference URI`);
  const actualUris = new Set(actual.map((reference) => reference.uri));
  assert.deepEqual(
    [...actualUris].sort(),
    [...expectedUris].sort(),
    `${name}: the signed reference URI set must match exactly`,
  );
  const byUri = new Map(actual.map((reference) => [reference.uri, reference]));
  for (const reference of expected) {
    const found = byUri.get(reference.uri);
    assert.ok(found, `${name}: expected reference ${reference.uri}`);
    if (!found) continue;
    assert.equal(found.digest, reference.digest, `${name}: digest for ${reference.uri}`);
    assert.equal(found.digestMethod, reference.digestMethod, `${name}: digest method for ${reference.uri}`);
    assert.deepEqual(
      normalizedTransforms(found),
      normalizedTransforms(reference),
      `${name}: transforms for ${reference.uri}`,
    );
  }

  // The recovered payload must match the independently recorded hash.
  const payload = await collect(opened.payload.read());
  const payloadSha256Base64 = createHash('sha256').update(payload).digest('base64');
  assert.equal(payloadSha256Base64, metadata.expectedPayloadSha256Base64, `${name}: recovered payload hash`);
  assert.equal(opened.payload.digestBase64, metadata.expectedPayloadSha256Base64, `${name}: payload handle hash`);

  // Recorded sender acceptance must reference this exchange.
  assert.equal(
    capture.senderAcceptance.refToMessageId,
    opened.messageId,
    `${name}: recorded sender acceptance must reference this message`,
  );

  // For an accepted exchange, the recorded response must be a receipt that
  // verifies against this request — signature, signer identity, correlation and
  // NRI. The recorded peer result separately establishes that the sender
  // accepted those bytes; here we prove the bytes are the right receipt.
  if (metadata.senderAcceptance.accepted) {
    assert.ok(capture.acceptanceResponse, `${name}: an accepted exchange must record the accepted response bytes`);
    const response = capture.acceptanceResponse ?? Buffer.alloc(0);
    const signal = parseSignal(response);
    assert.ok(signal, `${name}: the recorded response must be an AS4 signal`);
    if (signal) {
      const check = await verifyReceipt({
        signal,
        as4MessageId: opened.messageId,
        receiverCertificatePem: capture.receiverCertPem,
        signedReferences: opened.receipt.signedReferences,
        validateCertificate,
        now: () => new Date(metadata.capturedAt),
      });
      assert.equal(check.ok, true, `${name}: the recorded receipt must verify: ${JSON.stringify(check)}`);
    }
  }

  return {
    name,
    origin: metadata.origin,
    implementation: metadata.sender.implementation,
    senderAccepted: capture.senderAcceptance.accepted,
    messageId: opened.messageId,
    senderId: opened.senderId,
    receiverId: opened.receiverId,
    payloadSha256Base64,
    referenceCount: actual.length,
  };
}
