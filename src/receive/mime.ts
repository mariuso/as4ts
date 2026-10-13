import type { InboundFailureReason } from './types.js';

/**
 * MIME primitives for inbound AS4 requests.
 *
 * The multipart framing itself is parsed incrementally by
 * `src/receive/multipart.ts` (bounded SOAP buffer plus file-backed attachment
 * spools). This module keeps the pieces that parser and its callers share: the
 * fault type, the header/parameter helpers, and `MimeLimits`.
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

/** Parse a MIME header block, folding continuation lines and rejecting duplicates. */
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

/** A Content-ID without its angle brackets. */
export function normalizeContentId(value: string | undefined): string | null {
  if (!value) return null;
  const trimmed = value.trim();
  return trimmed.startsWith('<') && trimmed.endsWith('>') ? trimmed.slice(1, -1) : trimmed;
}
