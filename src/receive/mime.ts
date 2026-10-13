import type { InboundFailureReason } from './types.js';
import { abortableStream, isAbortError } from './streams.js';

/**
 * A bounded `multipart/related` parser for inbound AS4 requests (Phase 1 spike).
 *
 * Scope and limits are explicit: the accepted subset is `multipart/related` with
 * a single boundary, each part carrying a header block and a body. The total
 * request, part count, per-part header size, per-part body size and boundary
 * length are all capped.
 *
 * Strictness: a `--boundary` sequence only delimits a part when it starts a
 * line, so boundary-like bytes inside a part never split it; parsing stops at the
 * first valid closing delimiter and any epilogue is ignored; duplicate headers,
 * ambiguous root parts and non-SOAP `start` targets are rejected. Reading is
 * cancellable even when the source stalls, and the source's `return()` is called
 * on early exit so a caller-owned stream is cleaned up.
 *
 * The transport-decoded body is reassembled up to `maxRequestBytes` before it is
 * split; streaming each part body straight to a spool is a later phase.
 */
export class MimeFault extends Error {
  constructor(
    readonly reason: InboundFailureReason,
    message: string,
  ) {
    super(message);
    this.name = 'MimeFault';
  }
}

export interface MimeLimits {
  readonly maxRequestBytes: number;
  readonly maxParts: number;
  readonly maxHeaderBytes: number;
  readonly maxPartBytes: number;
  readonly maxBoundaryLength: number;
}

export interface MimePart {
  readonly headers: Readonly<Record<string, string>>;
  /** Content-ID without angle brackets, or null when absent. */
  readonly contentId: string | null;
  /** Content-Type with parameters, or null when absent. */
  readonly contentType: string | null;
  readonly body: Buffer;
}

export interface ParsedMultipart {
  readonly parts: readonly MimePart[];
  /** The `start` parameter's Content-ID, if the header carried one. */
  readonly startContentId: string | null;
}

const CR = 0x0d;
const LF = 0x0a;
const SPACE = 0x20;
const TAB = 0x09;

/** Extract and validate the boundary from a `multipart/related` Content-Type. */
export function extractBoundary(contentType: string | undefined, limits: MimeLimits): string {
  const mediaType = (contentType ?? '').split(';')[0]?.trim().toLowerCase() ?? '';
  if (mediaType !== 'multipart/related' && mediaType !== 'multipart/mixed') {
    throw new MimeFault('mime.content-type-invalid', `expected multipart/related, got ${mediaType || '(none)'}`);
  }
  // The parameter name must be a full token, so `notboundary=` is not a boundary.
  const match = /(?:^|;)\s*boundary\s*=\s*(?:"([^"]*)"|([^";]+))/i.exec(contentType ?? '');
  const boundary = (match?.[1] ?? match?.[2] ?? '').trim();
  if (!boundary) throw new MimeFault('mime.boundary-invalid', 'no boundary parameter');
  if (boundary.length > limits.maxBoundaryLength) {
    throw new MimeFault('mime.boundary-invalid', 'boundary too long');
  }
  return boundary;
}

/** The `start` parameter of a `multipart/related` Content-Type, as a bare Content-ID. */
export function extractStart(contentType: string | undefined): string | null {
  const match = /(?:^|;)\s*start\s*=\s*"?<?([^">\s;]+)>?"?/i.exec(contentType ?? '');
  return match?.[1]?.trim() ?? null;
}

/** Reassemble the body up to `maxRequestBytes`, honouring cancellation. */
async function readAllBounded(
  body: AsyncIterable<Uint8Array>,
  maxRequestBytes: number,
  signal: AbortSignal | undefined,
): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  try {
    for await (const chunk of abortableStream(body, signal)) {
      total += chunk.byteLength;
      if (total > maxRequestBytes) throw new MimeFault('body.too-large', 'request body exceeds the limit');
      chunks.push(Buffer.from(chunk));
    }
  } catch (err) {
    if (isAbortError(err)) throw new MimeFault('aborted', 'request body read aborted');
    throw err;
  }
  return Buffer.concat(chunks);
}

/** Offsets where `--boundary` starts a line (index 0 or after CRLF). */
function delimiterPositions(buffer: Buffer, boundary: string): number[] {
  const marker = Buffer.from(`--${boundary}`, 'latin1');
  const positions: number[] = [];
  let from = 0;
  for (;;) {
    const idx = buffer.indexOf(marker, from);
    if (idx < 0) break;
    const atLineStart = idx === 0 || (buffer[idx - 2] === CR && buffer[idx - 1] === LF);
    if (atLineStart) positions.push(idx);
    from = idx + marker.length;
  }
  return positions;
}

export async function parseMultipartRelated(input: {
  readonly contentType: string | undefined;
  readonly body: AsyncIterable<Uint8Array>;
  readonly limits: MimeLimits;
  readonly signal?: AbortSignal;
}): Promise<ParsedMultipart> {
  const { limits } = input;
  const boundary = extractBoundary(input.contentType, limits);
  const startContentId = extractStart(input.contentType);
  const buffer = await readAllBounded(input.body, limits.maxRequestBytes, input.signal);

  const marker = Buffer.from(`--${boundary}`, 'latin1');
  const positions = delimiterPositions(buffer, boundary);

  const isClosingAt = (index: number): boolean => {
    const after = buffer.subarray(positions[index]! + marker.length, positions[index]! + marker.length + 2);
    return after[0] === 0x2d && after[1] === 0x2d;
  };
  const closingIndex = positions.findIndex((_position, index) => isClosingAt(index));
  if (closingIndex < 0) throw new MimeFault('mime.malformed', 'no closing boundary');
  const partCount = closingIndex; // delimiters before the first closing one
  if (partCount > limits.maxParts) {
    throw new MimeFault('mime.parts-too-many', `${partCount} parts exceeds ${limits.maxParts}`);
  }

  const parts: MimePart[] = [];
  const contentIds = new Set<string>();
  for (let i = 0; i < partCount; i += 1) {
    const contentStart = delimiterLineEnd(buffer, positions[i]! + marker.length);
    const contentEnd = positions[i + 1]! - 2; // the CRLF before the next delimiter
    if (contentEnd < contentStart) throw new MimeFault('mime.malformed', 'empty part framing');
    const rawPart = buffer.subarray(contentStart, contentEnd);

    const headerEnd = rawPart.indexOf('\r\n\r\n');
    if (headerEnd < 0) throw new MimeFault('mime.malformed', 'part has no header/body separator');
    if (headerEnd > limits.maxHeaderBytes)
      throw new MimeFault('mime.header-too-large', 'part header exceeds the limit');
    const headers = parseHeaderBlock(rawPart.subarray(0, headerEnd));
    const partBody = rawPart.subarray(headerEnd + 4);
    if (partBody.byteLength > limits.maxPartBytes)
      throw new MimeFault('mime.part-too-large', 'part body exceeds the limit');

    const contentId = normalizeContentId(headers['content-id']);
    if (contentId) {
      if (contentIds.has(contentId)) {
        throw new MimeFault('mime.duplicate-content-id', `duplicate Content-ID ${contentId}`);
      }
      contentIds.add(contentId);
    }
    parts.push({
      headers,
      contentId,
      contentType: headers['content-type'] ?? null,
      body: Buffer.from(partBody),
    });
  }

  return { parts, startContentId };
}

/** Index just past the CRLF that ends a delimiter line, allowing transport padding. */
function delimiterLineEnd(buffer: Buffer, afterMarker: number): number {
  let cursor = afterMarker;
  while (buffer[cursor] === SPACE || buffer[cursor] === TAB) cursor += 1;
  if (buffer[cursor] !== CR || buffer[cursor + 1] !== LF) {
    throw new MimeFault('mime.malformed', 'delimiter line is not terminated by CRLF');
  }
  return cursor + 2;
}

/**
 * Select the SOAP envelope part. Prefer the part named by the `start` parameter
 * (which must itself be a SOAP part); otherwise the single `application/soap+xml`
 * part. Ambiguity is rejected rather than guessed.
 */
export function selectSoapPart(parsed: ParsedMultipart): MimePart {
  const isSoap = (part: MimePart): boolean =>
    /application\/soap\+xml|application\/xml/i.test((part.contentType ?? '').split(';')[0]?.trim() ?? '');

  if (parsed.startContentId) {
    const part = parsed.parts.find((candidate) => candidate.contentId === parsed.startContentId);
    if (!part) throw new MimeFault('mime.no-soap-part', 'the start Content-ID does not match any part');
    if (!isSoap(part)) throw new MimeFault('mime.no-soap-part', 'the start part is not a SOAP part');
    return part;
  }
  const candidates = parsed.parts.filter(isSoap);
  if (candidates.length === 0) throw new MimeFault('mime.no-soap-part', 'no SOAP part found');
  if (candidates.length > 1) throw new MimeFault('mime.ambiguous-root', 'more than one SOAP part');
  return candidates[0]!;
}

export function parseHeaderBlock(block: Buffer): Record<string, string> {
  const headers: Record<string, string> = Object.create(null) as Record<string, string>;
  let current: string | null = null;
  for (const line of block.toString('latin1').split('\r\n')) {
    if (line === '') continue;
    if (/^[ \t]/.test(line)) {
      if (!current) throw new MimeFault('mime.malformed', 'header continuation without a header');
      headers[current] = `${headers[current]} ${line.trim()}`;
      continue;
    }
    const colon = line.indexOf(':');
    if (colon <= 0) throw new MimeFault('mime.malformed', 'malformed part header line');
    const name = line.slice(0, colon).trim().toLowerCase();
    if (headers[name] !== undefined) throw new MimeFault('mime.duplicate-header', `duplicate header ${name}`);
    headers[name] = line.slice(colon + 1).trim();
    current = name;
  }
  return headers;
}

export function normalizeContentId(value: string | undefined): string | null {
  if (!value) return null;
  const trimmed = value.trim();
  return trimmed.startsWith('<') && trimmed.endsWith('>') ? trimmed.slice(1, -1) : trimmed;
}
