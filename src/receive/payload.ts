import { createDecipheriv, createHash } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { open } from 'node:fs/promises';
import { Readable, Transform, Writable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { createGunzip } from 'node:zlib';
import { createTempWorkspace, type TempWorkspace } from '../temp-file.js';
import { safeMessage } from '../util.js';
import { attachmentDigestBase64 } from './attachment.js';
import { SessionKeyFault, unwrapSessionKey } from './session-key.js';
import { XmlFault, defaultXmlLimits } from './xml.js';
import type {
  InboundEvent,
  InboundFailure,
  InboundFailureReason,
  InboundStage,
  OnInboundEvent,
  PayloadHandle,
  RecoverInboundPayloadInput,
  RecoverResult,
  RepresentationHandle,
} from './types.js';

/**
 * Recover one inbound payload (Phase 2). The two-pass quarantine keeps plaintext
 * off disk until it is authenticated:
 *
 *   bounded, private ciphertext spool
 *   → pass 1: decrypt completely, authenticate, discard plaintext; check the
 *     signed digest here when the attachment transform streams (binary/gzip)
 *   → pass 2: materialize the authenticated representation privately
 *   → verify the transform digest / decompress under limits
 *   → finish every pipeline and close every writer
 *   → return owned handles
 *
 * A fresh decipher is used for each pass, the 16-byte GCM tag is required, and
 * both passes authenticate. Pass 1 writes nothing, so no plaintext is persisted
 * before authentication. Canonicalization is used only to verify the reference;
 * the payload is always the original decrypted bytes. The session key is cleared
 * once both passes are done.
 */
const IV_BYTES = 12;
const TAG_BYTES = 16;
const MIN_CIPHERTEXT_BYTES = IV_BYTES + TAG_BYTES;
const CIPHERTEXT_FILE = 'ciphertext.bin';
const REPRESENTATION_FILE = 'representation.bin';
const PAYLOAD_FILE = 'payload.bin';

class PayloadTooLarge extends Error {}
class GcmFailure extends Error {}

function emit(onEvent: OnInboundEvent | undefined, event: InboundEvent): void {
  if (!onEvent) return;
  try {
    onEvent(event);
  } catch {
    // observe only
  }
}

async function timed<T>(
  onEvent: OnInboundEvent | undefined,
  phase: InboundEvent['phase'],
  fn: () => Promise<T>,
): Promise<T> {
  const start = performance.now();
  try {
    return await fn();
  } finally {
    emit(onEvent, { phase, durationMs: performance.now() - start });
  }
}

function abortError(): Error {
  const error = new Error('aborted');
  error.name = 'AbortError';
  (error as NodeJS.ErrnoException).code = 'ABORT_ERR';
  return error;
}

function isAbortError(err: unknown): boolean {
  return err instanceof Error && (err.name === 'AbortError' || (err as NodeJS.ErrnoException).code === 'ABORT_ERR');
}

function isDecompressError(err: unknown): boolean {
  const code = (err as NodeJS.ErrnoException | undefined)?.code;
  return typeof code === 'string' && code.startsWith('Z_');
}

function isFileSystemError(err: unknown): boolean {
  const code = (err as NodeJS.ErrnoException | undefined)?.code;
  return typeof code === 'string' && /^E[A-Z]+$/.test(code);
}

function isXmlMediaType(mediaType: string): boolean {
  const type = mediaType.split(';')[0]?.trim().toLowerCase() ?? '';
  return type === 'application/xml' || type === 'text/xml' || type.endsWith('+xml');
}

/** Consume a source, honouring cancellation, and call `return()` on early exit. */
async function* abortableStream(
  source: AsyncIterable<Uint8Array>,
  signal: AbortSignal | undefined,
): AsyncGenerator<Uint8Array> {
  const iterator = source[Symbol.asyncIterator]();
  if (!signal) {
    try {
      for (;;) {
        const result = await iterator.next();
        if (result.done) break;
        yield result.value;
      }
    } finally {
      await iterator.return?.().catch(() => {});
    }
    return;
  }
  let onAbort: (() => void) | null = null;
  const aborted = new Promise<never>((_resolve, reject) => {
    const fail = (): void => reject(abortError());
    if (signal.aborted) {
      fail();
      return;
    }
    onAbort = fail;
    signal.addEventListener('abort', onAbort, { once: true });
  });
  try {
    for (;;) {
      const result = await Promise.race([iterator.next(), aborted]);
      if (result.done) break;
      yield result.value;
    }
  } finally {
    if (onAbort) signal.removeEventListener('abort', onAbort);
    await iterator.return?.().catch(() => {});
  }
}

function discardingSink(): Writable {
  return new Writable({
    write(_chunk, _encoding, callback) {
      callback();
    },
  });
}

async function readRange(path: string, start: number, length: number): Promise<Buffer> {
  const handle = await open(path, 'r');
  try {
    const buffer = Buffer.alloc(length);
    let offset = 0;
    while (offset < length) {
      const { bytesRead } = await handle.read(buffer, offset, length - offset, start + offset);
      if (bytesRead === 0) throw new Error('unexpected end of ciphertext');
      offset += bytesRead;
    }
    return buffer;
  } finally {
    await handle.close();
  }
}

/** Spool the ciphertext stream to a private file, bounded and cancellable. */
async function spoolCiphertext(
  source: AsyncIterable<Uint8Array>,
  filePath: string,
  maxBytes: number,
  signal: AbortSignal | undefined,
): Promise<number> {
  let bytes = 0;
  const count = new Transform({
    transform(chunk: Buffer, _encoding, callback) {
      bytes += chunk.length;
      if (bytes > maxBytes) callback(new PayloadTooLarge('ciphertext exceeds the limit'));
      else callback(null, chunk);
    },
  });
  await pipeline(abortableStream(source, signal), count, createWriteStream(filePath, { mode: 0o600 }));
  return bytes;
}

/**
 * One decrypt pass over the spooled ciphertext with a fresh decipher. The tag is
 * read from the file tail and set before decryption, so finalisation authenticates
 * the whole stream. Plaintext is pushed onward (to a file or a discarding sink).
 */
async function decryptPass(input: {
  readonly ciphertextPath: string;
  readonly size: number;
  readonly sessionKey: Buffer;
  readonly maxBytes: number;
  readonly signal: AbortSignal | undefined;
  readonly sinkPath?: string;
}): Promise<{ bytes: number; digestBase64: string }> {
  const { ciphertextPath, size, sessionKey, maxBytes, signal, sinkPath } = input;
  const iv = await readRange(ciphertextPath, 0, IV_BYTES);
  const tag = await readRange(ciphertextPath, size - TAG_BYTES, TAG_BYTES);
  const decipher = createDecipheriv('aes-128-gcm', sessionKey, iv);
  decipher.setAuthTag(tag);
  const hash = createHash('sha256');
  let bytes = 0;
  const consume = new Transform({
    transform(chunk: Buffer, _encoding, callback) {
      try {
        const plaintext = decipher.update(chunk);
        bytes += plaintext.length;
        if (bytes > maxBytes) throw new PayloadTooLarge('decrypted representation exceeds the limit');
        hash.update(plaintext);
        callback(null, plaintext);
      } catch (err) {
        callback(err as Error);
      }
    },
    flush(callback) {
      try {
        const final = decipher.final();
        bytes += final.length;
        if (bytes > maxBytes) throw new PayloadTooLarge('decrypted representation exceeds the limit');
        hash.update(final);
        callback(null, final.length ? final : undefined);
      } catch (err) {
        // Any failure here is an authentication failure (wrong key/tag/ciphertext).
        callback(err instanceof PayloadTooLarge ? err : new GcmFailure('GCM authentication failed'));
      }
    },
  });
  const cipherStart = IV_BYTES;
  const cipherEnd = size - TAG_BYTES - 1;
  const source: AsyncIterable<Uint8Array> =
    cipherEnd >= cipherStart
      ? createReadStream(ciphertextPath, { start: cipherStart, end: cipherEnd })
      : Readable.from([]);
  const sink = sinkPath ? createWriteStream(sinkPath, { mode: 0o600 }) : discardingSink();
  await pipeline(abortableStream(source, signal), consume, sink);
  return { bytes, digestBase64: hash.digest('base64') };
}

/** Decompress a gzip representation into the payload file, bounded and cancellable. */
async function gunzipToFile(
  sourcePath: string,
  destPath: string,
  maxBytes: number,
  signal: AbortSignal | undefined,
): Promise<{ bytes: number; digestBase64: string }> {
  let bytes = 0;
  const hash = createHash('sha256');
  const count = new Transform({
    transform(chunk: Buffer, _encoding, callback) {
      bytes += chunk.length;
      if (bytes > maxBytes) {
        callback(new PayloadTooLarge('decompressed output exceeds the limit'));
        return;
      }
      hash.update(chunk);
      callback(null, chunk);
    },
  });
  await pipeline(
    abortableStream(createReadStream(sourcePath), signal),
    createGunzip(),
    count,
    createWriteStream(destPath, { mode: 0o600 }),
  );
  return { bytes, digestBase64: hash.digest('base64') };
}

/** Owns the scratch workspace and every reader opened from it. */
class Owned {
  private disposed = false;
  private readonly streams = new Set<Readable>();

  constructor(
    private readonly workspace: TempWorkspace,
    private readonly onEvent: OnInboundEvent | undefined,
  ) {}

  read(path: string): Readable {
    if (this.disposed) throw new Error('the inbound result has been disposed');
    const stream = createReadStream(path);
    this.streams.add(stream);
    stream.on('close', () => this.streams.delete(stream));
    return stream;
  }

  async dispose(): Promise<void> {
    if (this.disposed) return;
    this.disposed = true;
    for (const stream of this.streams) stream.destroy();
    this.streams.clear();
    const start = performance.now();
    try {
      await this.workspace.cleanup();
    } catch (err) {
      emit(this.onEvent, { phase: 'cleanup', durationMs: performance.now() - start, error: safeMessage(err) });
    }
  }
}

function mapFailure(err: unknown): InboundFailure {
  const fail = (stage: InboundStage, reason: InboundFailureReason, detail?: string): InboundFailure => ({
    ok: false,
    stage,
    reason,
    answerable: false,
    ...(detail ? { detail } : {}),
  });
  if (err instanceof SessionKeyFault) return fail('decrypt', err.reason, err.message);
  if (err instanceof PayloadTooLarge) return fail('payload', 'payload.too-large', err.message);
  if (err instanceof GcmFailure) return fail('decrypt', 'decrypt.gcm-auth', err.message);
  if (err instanceof XmlFault) return fail('xml', err.reason, err.message);
  if (isAbortError(err)) return fail('transport', 'aborted');
  if (isDecompressError(err)) return fail('decompress', 'decompress.failed', safeMessage(err));
  if (isFileSystemError(err)) return fail('payload', 'payload.spool-failed', safeMessage(err));
  return fail('internal', 'internal.error', safeMessage(err));
}

export async function recoverInboundPayload(input: RecoverInboundPayloadInput): Promise<RecoverResult> {
  const { encryption, attachment, reference, compression, limits, signal, onEvent } = input;
  const fail = (stage: InboundStage, reason: InboundFailureReason, detail?: string): InboundFailure => ({
    ok: false,
    stage,
    reason,
    answerable: false,
    ...(detail ? { detail } : {}),
  });

  // The authenticated reference must be the one for this attachment.
  if (reference.uri !== encryption.attachmentHref && reference.uri !== `cid:${attachment.contentId}`) {
    return fail('signature', 'signature.coverage', 'the reference is not for this attachment');
  }

  let workspace: TempWorkspace | null = null;
  let sessionKey: Buffer | null = null;
  let keep = false;
  try {
    workspace = await createTempWorkspace({
      ...(input.spoolDirectory ? { directory: input.spoolDirectory } : {}),
    });
    const ciphertextPath = workspace.path(CIPHERTEXT_FILE);

    // Bounded, private ciphertext spool (no plaintext yet).
    const ciphertextBytes = await timed(onEvent, 'decrypt', () =>
      spoolCiphertext(attachment.source, ciphertextPath, limits.maxPartBytes, signal),
    );
    if (ciphertextBytes < MIN_CIPHERTEXT_BYTES) {
      return fail('decrypt', 'encryption.invalid', 'ciphertext is shorter than IV + tag');
    }

    // Bounded credential selection and unwrap.
    const unwrapped = await timed(onEvent, 'decrypt', () =>
      unwrapSessionKey({
        wrappedKey: encryption.wrappedKey,
        ...(encryption.recipientCertificate ? { recipientCertificate: encryption.recipientCertificate } : {}),
        holders: input.keyHolder,
        maxCandidates: limits.maxKeyCandidates,
        ...(signal ? { signal } : {}),
      }),
    );
    sessionKey = unwrapped.sessionKey;
    const credential = { certificate: unwrapped.credentialCertificate };

    const isXml = isXmlMediaType(encryption.mediaType);

    // Pass 1: decrypt completely, authenticate, discard plaintext. When the
    // transform streams (binary/gzip), check the signed digest here.
    const pass1 = await timed(onEvent, 'decrypt', () =>
      decryptPass({
        ciphertextPath,
        size: ciphertextBytes,
        sessionKey: sessionKey!,
        maxBytes: limits.maxRepresentationBytes,
        signal,
      }),
    );
    if (!isXml && pass1.digestBase64 !== reference.digest) {
      return fail('signature', 'signature.attachment-digest', 'attachment digest mismatch');
    }

    // Pass 2: materialize the authenticated representation privately.
    const representationPath = workspace.path(REPRESENTATION_FILE);
    const pass2 = await timed(onEvent, 'materialize', () =>
      decryptPass({
        ciphertextPath,
        size: ciphertextBytes,
        sessionKey: sessionKey!,
        maxBytes: limits.maxRepresentationBytes,
        signal,
        sinkPath: representationPath,
      }),
    );
    sessionKey.fill(0);
    sessionKey = null;

    let transformDigestBase64: string;
    let payloadPath: string;
    let payloadBytes: number;
    let payloadDigestBase64: string;

    if (isXml) {
      const bytes = await readRange(representationPath, 0, pass2.bytes);
      transformDigestBase64 = attachmentDigestBase64(encryption.mediaType, bytes, {
        ...defaultXmlLimits,
        maxBytes: limits.maxXmlBytes,
      });
      if (transformDigestBase64 !== reference.digest) {
        return fail('signature', 'signature.attachment-digest', 'canonical attachment digest mismatch');
      }
      // Canonicalization is only for verification: the payload is the original XML.
      payloadPath = representationPath;
      payloadBytes = pass2.bytes;
      payloadDigestBase64 = pass2.digestBase64;
    } else {
      transformDigestBase64 = pass2.digestBase64;
      const budgetRemaining = input.budget ? input.budget.remaining() : Number.MAX_SAFE_INTEGER;
      const maxOutput = Math.min(limits.maxDecompressedBytes, budgetRemaining);
      if (compression.kind === 'gzip') {
        const out = await timed(onEvent, 'decompress', () =>
          gunzipToFile(representationPath, workspace!.path(PAYLOAD_FILE), maxOutput, signal),
        );
        payloadPath = workspace.path(PAYLOAD_FILE);
        payloadBytes = out.bytes;
        payloadDigestBase64 = out.digestBase64;
      } else {
        payloadPath = representationPath;
        payloadBytes = pass2.bytes;
        payloadDigestBase64 = pass2.digestBase64;
      }
    }

    if (input.budget && !input.budget.reserve(payloadBytes)) {
      return fail('payload', 'payload.too-large', 'message aggregate output budget exceeded');
    }

    const owned = new Owned(workspace, onEvent);
    let remainingHandles = 2;
    const onHandleDisposed = async (): Promise<void> => {
      remainingHandles -= 1;
      if (remainingHandles === 0) await owned.dispose();
    };
    let payloadDisposed = false;
    let representationDisposed = false;

    const payload: PayloadHandle = {
      byteLength: payloadBytes,
      digestBase64: payloadDigestBase64,
      read: () => {
        if (payloadDisposed) throw new Error('the payload handle has been disposed');
        return owned.read(payloadPath);
      },
      dispose: async () => {
        if (payloadDisposed) return;
        payloadDisposed = true;
        await onHandleDisposed();
      },
    };
    const representation: RepresentationHandle = {
      byteLength: pass2.bytes,
      rawDigestBase64: pass2.digestBase64,
      mediaType: encryption.mediaType,
      transformDigestBase64,
      read: () => {
        if (representationDisposed) throw new Error('the representation handle has been disposed');
        return owned.read(representationPath);
      },
      dispose: async () => {
        if (representationDisposed) return;
        representationDisposed = true;
        await onHandleDisposed();
      },
    };

    keep = true;
    return { ok: true, payload, representation, credential, dispose: () => owned.dispose() };
  } catch (err) {
    return mapFailure(err);
  } finally {
    if (sessionKey) sessionKey.fill(0);
    if (!keep && workspace) {
      const start = performance.now();
      try {
        await workspace.cleanup();
      } catch (err) {
        emit(onEvent, { phase: 'cleanup', durationMs: performance.now() - start, error: safeMessage(err) });
      }
    }
  }
}
