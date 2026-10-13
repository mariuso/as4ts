import { createReadStream, createWriteStream } from 'node:fs';
import { mkdtemp, rename, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import type { Writable } from 'node:stream';
import {
  MimeFault,
  extractBoundary,
  extractStart,
  normalizeContentId,
  parseHeaderBlock,
  type MimeLimits,
} from './mime.js';
import { abortableAwait, abortableStream, isAbortError } from './streams.js';
import type { InboundFailureReason } from './types.js';

/**
 * Incremental `multipart/related` parsing with owned spools (Phase 6).
 *
 * Headers and delimiters are parsed as bytes arrive: the SOAP part is buffered
 * under both `maxPartBytes` and a dedicated `maxEnvelopeBytes`, while every other
 * part is streamed straight to a private spool file with backpressure. Receiving
 * a larger attachment therefore grows disk usage and processing time, not the
 * in-memory buffer.
 *
 * Writer failure is a parser-wide event: it interrupts source reads and writer
 * operations, so a storage failure is reported as such rather than as a stall or
 * a cancellation. Cleanup waits for writers to actually close before unlinking,
 * so a delayed file open cannot recreate a spool after cleanup.
 */
const CR = 0x0d;
const LF = 0x0a;
const SPACE = 0x20;
const TAB = 0x09;
const DASH = 0x2d;
/** The largest partial `\r\n\r\n` terminator that may be buffered with a header. */
const MAX_PARTIAL_TERMINATOR = 3;

const SOAP_MEDIA = /^(?:application\/soap\+xml|application\/xml)$/i;

/** Test seams: inject a spool writer, and observe retained bytes. */
export const multipartHooks: {
  createSpoolWriter?: (path: string) => Writable;
  onRetained?: (pendingBytes: number) => void;
} = {};

export interface MultipartPart {
  readonly headers: Readonly<Record<string, string>>;
  readonly contentId: string | null;
  readonly contentType: string | null;
  readonly byteLength: number;
  /** The owned spool path for a file-backed attachment; null for the SOAP part. */
  readonly spoolPath: string | null;
  /**
   * Read the part: the bounded in-memory buffer, or the spool file. A spool that
   * has been transferred out (see `transferSpool`) is no longer readable here.
   */
  read(): Readable;
}

export interface ParsedMultipartMessage {
  readonly parts: readonly MultipartPart[];
  readonly startContentId: string | null;
  /**
   * Move an attachment's ciphertext spool into `destination` with a single
   * rename, transferring ownership. The part's Content-ID must match
   * `expectedContentId`. Both directories must be on the same filesystem: on any
   * mismatch or rename failure the parser keeps ownership (and deletes the spool
   * on dispose), and the caller can still read the spool via `part.read()`.
   */
  transferSpool(part: MultipartPart, expectedContentId: string, destination: string): Promise<string | null>;
  /** Delete owned spools and the private directory. Retries are safe; failures are retained. */
  dispose(): Promise<void>;
}

interface PartBuilder {
  headers: Record<string, string>;
  contentId: string | null;
  contentType: string | null;
  soap: boolean;
  buffer: Buffer[];
  size: number;
  spoolPath: string | null;
  spool: SpoolWriter | null;
}

interface SpoolWriter {
  readonly path: string;
  failure(): Error | null;
  write(chunk: Buffer): Promise<void>;
  close(): Promise<void>;
  /** Destroy the writer and resolve once it has actually closed. */
  destroy(): Promise<void>;
}

function isSoapMediaType(contentType: string | null): boolean {
  return SOAP_MEDIA.test((contentType ?? '').split(';')[0]?.trim() ?? '');
}

function findLineStart(buffer: Buffer, marker: Buffer): number {
  let from = 0;
  for (;;) {
    const index = buffer.indexOf(marker, from);
    if (index < 0) return -1;
    if (index === 0 || (buffer[index - 2] === CR && buffer[index - 1] === LF)) return index;
    from = index + marker.length;
  }
}

/** A writer that records failure, emits no unhandled error, and closes on demand. */
function openSpool(path: string, onFailure: (err: Error) => void): SpoolWriter {
  const stream = multipartHooks.createSpoolWriter?.(path) ?? createWriteStream(path, { mode: 0o600 });
  let failure: Error | null = null;
  let closed = false;
  let pendingReject: ((err: Error) => void) | null = null;
  stream.on('close', () => {
    closed = true;
  });
  stream.on('error', (err: unknown) => {
    failure ??= err instanceof Error ? err : new Error(String(err));
    onFailure(failure);
    const reject = pendingReject;
    pendingReject = null;
    reject?.(failure);
  });
  return {
    path,
    failure: () => failure,
    write(chunk: Buffer): Promise<void> {
      if (failure) return Promise.reject(failure);
      if (chunk.length === 0) return Promise.resolve();
      return new Promise<void>((resolve, reject) => {
        let settled = false;
        const fail = (err: Error): void => {
          if (settled) return;
          settled = true;
          pendingReject = null;
          reject(err);
        };
        pendingReject = fail;
        stream.write(chunk, (err) => {
          pendingReject = null;
          if (err) fail(err);
          else if (!settled) {
            settled = true;
            resolve();
          }
        });
      });
    },
    close(): Promise<void> {
      if (failure) return Promise.reject(failure);
      return new Promise<void>((resolve, reject) => {
        stream.end((err?: Error | null) => (err ? reject(err) : resolve()));
      });
    },
    destroy(): Promise<void> {
      if (closed) return Promise.resolve();
      return new Promise<void>((resolve) => {
        stream.once('close', () => {
          closed = true;
          resolve();
        });
        try {
          stream.destroy();
        } catch {
          closed = true;
          resolve();
        }
      });
    },
  };
}

export async function parseMultipartMessage(input: {
  readonly contentType: string | undefined;
  readonly body: AsyncIterable<Uint8Array>;
  readonly limits: MimeLimits;
  /** Additional bound for the buffered SOAP envelope; defaults to `maxPartBytes`. */
  readonly maxEnvelopeBytes?: number;
  readonly signal?: AbortSignal;
  /** Directory for owned spools; a fresh private directory is created when absent. */
  readonly spoolDirectory?: string;
}): Promise<ParsedMultipartMessage> {
  const { limits } = input;
  const envelopeBudget = input.maxEnvelopeBytes ?? limits.maxPartBytes;
  const boundary = extractBoundary(input.contentType, limits);
  const startContentId = extractStart(input.contentType);
  const marker = Buffer.from(`--${boundary}`, 'latin1');
  const bodyNeedle = Buffer.from(`\r\n--${boundary}`, 'latin1');

  // A writer failure aborts this controller, which interrupts the source read and
  // any in-flight writer operation; the failure itself is reported, not "aborted".
  const failureController = new AbortController();
  let writerFailure: Error | null = null;
  const noteWriterFailure = (err: Error): void => {
    writerFailure ??= err;
    failureController.abort();
  };
  const signal = input.signal ? AbortSignal.any([input.signal, failureController.signal]) : failureController.signal;

  const ownsDirectory = input.spoolDirectory === undefined;
  const directory = input.spoolDirectory ?? (await mkdtemp(join(tmpdir(), 'as4-mime-')));
  const ownedSpools = new Set<string>();
  const parts: MultipartPart[] = [];
  const contentIds = new Set<string>();

  let pending: Buffer = Buffer.alloc(0);
  let state: 'preamble' | 'headers' | 'body' | 'after' | 'done' = 'preamble';
  let current: PartBuilder | null = null;
  let total = 0;
  let partIndex = 0;

  const fault = (reason: InboundFailureReason, message: string): never => {
    throw new MimeFault(reason, message);
  };
  const isDone = (): boolean => state === 'done';

  const startPart = (headers: Record<string, string>): PartBuilder => {
    partIndex += 1;
    if (partIndex > limits.maxParts) fault('mime.parts-too-many', `more than ${limits.maxParts} parts`);
    const contentId = normalizeContentId(headers['content-id']);
    if (contentId) {
      if (contentIds.has(contentId)) fault('mime.duplicate-content-id', `duplicate Content-ID ${contentId}`);
      contentIds.add(contentId);
    }
    const contentType = headers['content-type'] ?? null;
    const soap = isSoapMediaType(contentType);
    const builder: PartBuilder = {
      headers,
      contentId,
      contentType,
      soap,
      buffer: [],
      size: 0,
      spoolPath: null,
      spool: null,
    };
    if (!soap) {
      builder.spoolPath = join(directory, `part-${partIndex}.bin`);
      // Register ownership when creation starts, so a failure mid-part still cleans up.
      ownedSpools.add(builder.spoolPath);
      builder.spool = openSpool(builder.spoolPath, noteWriterFailure);
    }
    return builder;
  };

  const appendBody = async (builder: PartBuilder, chunk: Buffer): Promise<void> => {
    if (chunk.length === 0) return;
    builder.size += chunk.length;
    // The per-part bound applies to every part, including the SOAP part.
    if (builder.size > limits.maxPartBytes) fault('mime.part-too-large', 'part body exceeds the limit');
    if (builder.soap) {
      if (builder.size > envelopeBudget) fault('xml.too-large', 'the SOAP envelope exceeds the limit');
      builder.buffer.push(Buffer.from(chunk));
      return;
    }
    await abortableAwait(builder.spool!.write(chunk), signal);
  };

  const finishPart = (builder: PartBuilder): void => {
    if (builder.soap) {
      const body = Buffer.concat(builder.buffer, builder.size);
      parts.push({
        headers: builder.headers,
        contentId: builder.contentId,
        contentType: builder.contentType,
        byteLength: body.length,
        spoolPath: null,
        read: () => Readable.from([body]),
      });
      return;
    }
    parts.push({
      headers: builder.headers,
      contentId: builder.contentId,
      contentType: builder.contentType,
      byteLength: builder.size,
      spoolPath: builder.spoolPath,
      read: () => createReadStream(builder.spoolPath!),
    });
  };

  const dispose = async (): Promise<void> => {
    // Wait for writers to actually close before unlinking, so a delayed file open
    // cannot recreate a spool after cleanup. destroy() abandons pending writes
    // without a graceful flush.
    const closings: Promise<void>[] = [];
    if (current?.spool) {
      closings.push(current.spool.destroy());
      current = null;
    }
    await Promise.all(closings);
    for (const path of [...ownedSpools]) {
      try {
        await rm(path, { force: true });
        ownedSpools.delete(path);
      } catch {
        // retain for a retry
      }
    }
    if (ownsDirectory && ownedSpools.size === 0) {
      await rm(directory, { recursive: true, force: true }).catch(() => {});
    }
  };

  const pump = async (): Promise<void> => {
    for (;;) {
      if (isDone()) return;
      if (state === 'preamble') {
        const index = findLineStart(pending, marker);
        if (index < 0) {
          const keep = Math.max(0, pending.length - (marker.length + 2));
          pending = pending.subarray(keep);
          return;
        }
        pending = pending.subarray(index + marker.length);
        state = 'after';
        continue;
      }
      if (state === 'after') {
        // Consume delimiter padding incrementally so it cannot accumulate.
        let consumed = 0;
        while (consumed < pending.length && (pending[consumed] === SPACE || pending[consumed] === TAB)) consumed += 1;
        if (consumed > 0) pending = pending.subarray(consumed);
        if (pending.length < 2) return; // need two bytes to decide
        if (pending[0] === DASH && pending[1] === DASH) {
          pending = pending.subarray(2);
          state = 'done';
          return;
        }
        if (pending[0] === CR && pending[1] === LF) {
          pending = pending.subarray(2);
          state = 'headers';
          continue;
        }
        fault('mime.malformed', 'delimiter line is not terminated by CRLF');
      }
      if (state === 'headers') {
        const separator = pending.indexOf('\r\n\r\n');
        if (separator < 0) {
          if (pending.length > limits.maxHeaderBytes + MAX_PARTIAL_TERMINATOR) {
            fault('mime.header-too-large', 'part header exceeds the limit');
          }
          return;
        }
        if (separator > limits.maxHeaderBytes) fault('mime.header-too-large', 'part header exceeds the limit');
        const headers = parseHeaderBlock(pending.subarray(0, separator));
        current = startPart(headers);
        pending = pending.subarray(separator + 4);
        state = 'body';
        continue;
      }
      if (state === 'body') {
        const builder = current!;
        const index = pending.indexOf(bodyNeedle);
        if (index < 0) {
          const keep = Math.max(0, pending.length - (bodyNeedle.length - 1));
          await appendBody(builder, pending.subarray(0, keep));
          pending = pending.subarray(keep);
          return;
        }
        await appendBody(builder, pending.subarray(0, index));
        if (builder.spool) {
          await abortableAwait(builder.spool.close(), signal);
          const failure = builder.spool.failure();
          if (failure) throw failure;
        }
        finishPart(builder);
        current = null;
        pending = pending.subarray(index + bodyNeedle.length);
        state = 'after';
        continue;
      }
    }
  };

  try {
    for await (const raw of abortableStream(input.body, signal)) {
      const chunk = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
      total += chunk.length;
      if (total > limits.maxRequestBytes) fault('body.too-large', 'request body exceeds the limit');
      // The epilogue after the closing boundary is discarded as it arrives; it is
      // still accounted for against the request budget.
      if (!isDone()) {
        pending = pending.length === 0 ? chunk : Buffer.concat([pending, chunk]);
        await pump();
      }
      multipartHooks.onRetained?.(pending.length);
    }
  } catch (err) {
    await dispose();
    if (writerFailure) throw writerFailure;
    if (isAbortError(err)) throw new MimeFault('aborted', 'request body read aborted');
    throw err;
  }

  if (!isDone()) {
    await dispose();
    fault('mime.malformed', 'no closing boundary');
  }

  return {
    parts,
    startContentId,
    async transferSpool(part: MultipartPart, expectedContentId: string, destination: string): Promise<string | null> {
      const source = part.spoolPath;
      if (!source || part.contentId !== expectedContentId) return null;
      if (!ownedSpools.has(source)) return null;
      try {
        // A single rename; both directories must share a filesystem. No copy.
        await rename(source, destination);
      } catch {
        return null; // keep ownership; the spool stays readable via part.read()
      }
      ownedSpools.delete(source);
      return destination;
    },
    dispose,
  };
}

/** Select the SOAP envelope part; ambiguity is rejected rather than guessed. */
export function selectSoapPart(message: ParsedMultipartMessage): MultipartPart {
  if (message.startContentId) {
    const part = message.parts.find((candidate) => candidate.contentId === message.startContentId);
    if (!part) throw new MimeFault('mime.no-soap-part', 'the start Content-ID does not match any part');
    if (!isSoapMediaType(part.contentType)) {
      throw new MimeFault('mime.no-soap-part', 'the start part is not a SOAP part');
    }
    return part;
  }
  const candidates = message.parts.filter((part) => isSoapMediaType(part.contentType));
  if (candidates.length === 0) throw new MimeFault('mime.no-soap-part', 'no SOAP part found');
  if (candidates.length > 1) throw new MimeFault('mime.ambiguous-root', 'more than one SOAP part');
  return candidates[0]!;
}
