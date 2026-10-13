import { createReadStream, createWriteStream } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
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
import { abortableStream, isAbortError } from './streams.js';
import type { InboundFailureReason } from './types.js';

/**
 * Incremental `multipart/related` parsing with owned spools (Phase 6).
 *
 * Unlike the buffered `parseMultipartRelated`, this parses headers and delimiters
 * as bytes arrive: the bounded SOAP part is retained in memory, while every other
 * part is streamed straight to a private spool file with backpressure. Receiving a
 * larger attachment therefore grows disk usage and processing time, not the
 * in-memory buffer.
 *
 * The SOAP root may appear in any position (attachments are spooled regardless of
 * order); the whole structure is traversed before success, so a trailing part
 * cannot escape validation. Cancellation and early failure never wait indefinitely
 * for the source's `return()`.
 */
const CR = 0x0d;
const LF = 0x0a;
const SPACE = 0x20;
const TAB = 0x09;
const DASH = 0x2d;

const SOAP_MEDIA = /^(?:application\/soap\+xml|application\/xml)$/i;

/** Test seam: inject a spool writer (for example a slow one) without changing the API. */
export const multipartHooks: { createSpoolWriter?: (path: string) => Writable } = {};

export interface MultipartPart {
  readonly headers: Readonly<Record<string, string>>;
  /** Content-ID without angle brackets, or null when absent. */
  readonly contentId: string | null;
  /** Content-Type with parameters, or null when absent. */
  readonly contentType: string | null;
  readonly byteLength: number;
  /** The owned spool path for a file-backed attachment; null for the SOAP part. */
  readonly spoolPath: string | null;
  /** Read the part: the bounded in-memory buffer, or the spool file. Repeatable. */
  read(): Readable;
}

export interface ParsedMultipartMessage {
  readonly parts: readonly MultipartPart[];
  /** The `start` parameter's Content-ID, if the request carried one. */
  readonly startContentId: string | null;
  /**
   * Transfer ownership of an attachment's ciphertext spool to the caller. The
   * part's Content-ID must match `expectedContentId`; on any mismatch the parser
   * keeps ownership (and deletes it on dispose). Returns the path, or null.
   */
  takeSpool(part: MultipartPart, expectedContentId: string): string | null;
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
  spool: Writable | null;
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

function writeChunk(stream: Writable, chunk: Buffer): Promise<void> {
  if (chunk.length === 0) return Promise.resolve();
  return new Promise<void>((resolve, reject) => {
    stream.write(chunk, (err) => (err ? reject(err) : resolve()));
  });
}

function closeWriter(stream: Writable): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    stream.end((err?: Error | null) => (err ? reject(err) : resolve()));
  });
}

export async function parseMultipartMessage(input: {
  readonly contentType: string | undefined;
  readonly body: AsyncIterable<Uint8Array>;
  readonly limits: MimeLimits;
  readonly signal?: AbortSignal;
  /** Directory for owned spools; a fresh private directory is created when absent. */
  readonly spoolDirectory?: string;
}): Promise<ParsedMultipartMessage> {
  const { limits } = input;
  const boundary = extractBoundary(input.contentType, limits);
  const startContentId = extractStart(input.contentType);
  const marker = Buffer.from(`--${boundary}`, 'latin1');
  const bodyNeedle = Buffer.from(`\r\n--${boundary}`, 'latin1');

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
      builder.spool =
        multipartHooks.createSpoolWriter?.(builder.spoolPath) ?? createWriteStream(builder.spoolPath, { mode: 0o600 });
    }
    return builder;
  };

  const appendBody = async (builder: PartBuilder, chunk: Buffer): Promise<void> => {
    if (chunk.length === 0) return;
    builder.size += chunk.length;
    if (builder.size > limits.maxPartBytes) fault('mime.part-too-large', 'part body exceeds the limit');
    if (builder.soap) builder.buffer.push(Buffer.from(chunk));
    else await writeChunk(builder.spool!, chunk);
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
    ownedSpools.add(builder.spoolPath!);
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
    if (current?.spool) {
      try {
        await closeWriter(current.spool);
      } catch {
        // best effort
      }
      current = null;
    }
    for (const path of ownedSpools) await rm(path, { force: true }).catch(() => {});
    ownedSpools.clear();
    if (ownsDirectory) await rm(directory, { recursive: true, force: true }).catch(() => {});
  };

  const pump = async (): Promise<void> => {
    for (;;) {
      if (state === 'done') return;
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
        let i = 0;
        while (i < pending.length && (pending[i] === SPACE || pending[i] === TAB)) i += 1;
        if (i + 1 >= pending.length) return; // need at least two bytes to decide
        if (pending[i] === DASH && pending[i + 1] === DASH) {
          pending = pending.subarray(i + 2);
          state = 'done';
          return;
        }
        if (pending[i] === CR && pending[i + 1] === LF) {
          pending = pending.subarray(i + 2);
          state = 'headers';
          continue;
        }
        fault('mime.malformed', 'delimiter line is not terminated by CRLF');
      }
      if (state === 'headers') {
        const separator = pending.indexOf('\r\n\r\n');
        if (separator < 0) {
          if (pending.length > limits.maxHeaderBytes) fault('mime.header-too-large', 'part header exceeds the limit');
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
        if (builder.spool) await closeWriter(builder.spool);
        finishPart(builder);
        current = null;
        pending = pending.subarray(index + bodyNeedle.length);
        state = 'after';
        continue;
      }
    }
  };

  const isDone = (): boolean => state === 'done';

  try {
    for await (const raw of abortableStream(input.body, input.signal)) {
      const chunk = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
      total += chunk.length;
      if (total > limits.maxRequestBytes) fault('body.too-large', 'request body exceeds the limit');
      pending = pending.length === 0 ? chunk : Buffer.concat([pending, chunk]);
      await pump();
    }
  } catch (err) {
    await dispose();
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
    takeSpool(part: MultipartPart, expectedContentId: string): string | null {
      if (!part.spoolPath || part.contentId !== expectedContentId) return null;
      if (!ownedSpools.has(part.spoolPath)) return null;
      ownedSpools.delete(part.spoolPath);
      return part.spoolPath;
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
