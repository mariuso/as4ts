import type { InboundFailureReason } from './types.js';

/**
 * A bounded `multipart/related` parser for inbound AS4 requests (Phase 1 spike).
 *
 * Scope and limits are explicit: the accepted subset is `multipart/related` with
 * a single boundary, each part carrying a header block and a body. The total
 * request, part count, per-part header size, per-part body size and boundary
 * length are all capped. Both delimiter recognition and binary safety are exact:
 * a `--boundary` sequence only delimits a part when it starts a line, so
 * boundary-like bytes inside a part never split it.
 *
 * The transport-decoded body is reassembled up to `maxRequestBytes` before it is
 * split; chunk boundaries are invisible to the result. Streaming each part body
 * straight to a spool is a later phase; the parser keeps a bounded buffer.
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
  /** Content-Type with parameters, lower-cased type, or null when absent. */
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

/** Extract and validate the boundary from a `multipart/related` Content-Type. */
export function extractBoundary(contentType: string | undefined, limits: MimeLimits): string {
  const mediaType = (contentType ?? '').split(';')[0]?.trim().toLowerCase() ?? '';
  if (mediaType !== 'multipart/related' && mediaType !== 'multipart/mixed') {
    throw new MimeFault('mime.content-type-invalid', `expected multipart/related, got ${mediaType || '(none)'}`);
  }
  const match = /boundary\s*=\s*"?([^";]+)"?/i.exec(contentType ?? '');
  const boundary = match?.[1]?.trim();
  if (!boundary) throw new MimeFault('mime.boundary-invalid', 'no boundary parameter');
  if (boundary.length > limits.maxBoundaryLength) {
    throw new MimeFault('mime.boundary-invalid', 'boundary too long');
  }
  return boundary;
}

/** The `start` parameter of a `multipart/related` Content-Type, as a bare Content-ID. */
export function extractStart(contentType: string | undefined): string | null {
  const match = /;\s*start\s*=\s*"?<([^">]+)>"?/i.exec(contentType ?? '');
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
  for await (const chunk of body) {
    if (signal?.aborted) throw new MimeFault('aborted', 'aborted while reading the request body');
    total += chunk.byteLength;
    if (total > maxRequestBytes) throw new MimeFault('body.too-large', 'request body exceeds the limit');
    chunks.push(Buffer.from(chunk));
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
  if (positions.length < 2) {
    throw new MimeFault('mime.malformed', 'no complete multipart framing found');
  }
  // The final delimiter must be the closing form `--boundary--`.
  const last = positions[positions.length - 1]!;
  const afterLast = buffer.subarray(last + marker.length, last + marker.length + 2);
  if (afterLast[0] !== 0x2d || afterLast[1] !== 0x2d) {
    throw new MimeFault('mime.malformed', 'missing closing boundary');
  }

  const partCount = positions.length - 1;
  if (partCount > limits.maxParts) {
    throw new MimeFault('mime.parts-too-many', `${partCount} parts exceeds ${limits.maxParts}`);
  }

  const parts: MimePart[] = [];
  const contentIds = new Set<string>();
  for (let i = 0; i < partCount; i += 1) {
    const start = positions[i]! + marker.length;
    const end = positions[i + 1]! - 2; // the CRLF before the next delimiter
    // Skip the CRLF ending the delimiter line.
    const lineEnd = buffer.indexOf('\r\n', start);
    if (lineEnd < 0 || lineEnd > end) throw new MimeFault('mime.malformed', 'part header is not terminated');
    const rawPart = buffer.subarray(lineEnd + 2, end);

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

/**
 * Select the SOAP envelope part. Prefer the part named by the `start` parameter;
 * otherwise the single `application/soap+xml` part. Ambiguity is rejected rather
 * than guessed.
 */
export function selectSoapPart(parsed: ParsedMultipart): MimePart {
  if (parsed.startContentId) {
    const part = parsed.parts.find((candidate) => candidate.contentId === parsed.startContentId);
    if (!part) throw new MimeFault('mime.no-soap-part', 'the start Content-ID does not match any part');
    return part;
  }
  const soapParts = parsed.parts.filter((part) =>
    /application\/soap\+xml|application\/xml/i.test((part.contentType ?? '').split(';')[0]?.trim() ?? ''),
  );
  const part = soapParts[0];
  if (!part) throw new MimeFault('mime.no-soap-part', 'no SOAP part found');
  return part;
}

function parseHeaderBlock(block: Buffer): Record<string, string> {
  const headers: Record<string, string> = {};
  let current: string | null = null;
  for (const line of block.toString('latin1').split('\r\n')) {
    if (line === '') continue;
    if (/^[ \t]/.test(line)) {
      if (current) headers[current] = `${headers[current]} ${line.trim()}`;
      continue;
    }
    const colon = line.indexOf(':');
    if (colon <= 0) throw new MimeFault('mime.malformed', 'malformed part header line');
    const name = line.slice(0, colon).trim().toLowerCase();
    headers[name] = line.slice(colon + 1).trim();
    current = name;
  }
  return headers;
}

function normalizeContentId(value: string | undefined): string | null {
  if (!value) return null;
  const trimmed = value.trim();
  return trimmed.startsWith('<') && trimmed.endsWith('>') ? trimmed.slice(1, -1) : trimmed;
}
