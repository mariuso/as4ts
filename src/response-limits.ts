/**
 * Limits for a SOAP response the sender receives: a receipt or error signal
 * returned by a remote access point.
 *
 * The defaults are generous relative to real responses — every captured receipt
 * is under 10 KiB, 63 nodes and depth 10 — while bounding a hostile one.
 * `maxCanonicalBytes` is a **total** across the SignedInfo and every reference,
 * because a receipt may declare up to 64 references and a per-call bound would
 * allow 64× the intended work.
 *
 * These bounds are separate from the fixed HTTP response cap (16 MiB in
 * `src/http/send.ts`), which is not overridable here.
 */
export interface ResponseLimits {
  /** SOAP envelope bytes, after MIME extraction. */
  readonly maxXmlBytes: number;
  readonly maxDepth: number;
  readonly maxNodes: number;
  readonly maxAttributes: number;
  /** One text, attribute, comment, CDATA or markup token, in UTF-8 bytes. */
  readonly maxTokenBytes: number;
  /** Total canonicalisation budget for one verification (all references). */
  readonly maxCanonicalBytes: number;
}

export const defaultResponseLimits: ResponseLimits = {
  maxXmlBytes: 1024 * 1024,
  maxDepth: 64,
  maxNodes: 10_000,
  maxAttributes: 64,
  maxTokenBytes: 64 * 1024,
  maxCanonicalBytes: 16 * 1024 * 1024,
};

/** Merge a caller override over the defaults; every property defaults independently. */
export function resolveResponseLimits(partial?: Partial<ResponseLimits>): ResponseLimits {
  const resolved: { -readonly [K in keyof ResponseLimits]: ResponseLimits[K] } = { ...defaultResponseLimits };
  if (!partial) return resolved;
  for (const key of Object.keys(defaultResponseLimits) as Array<keyof ResponseLimits>) {
    const value = partial[key];
    if (value !== undefined) resolved[key] = value;
  }
  return resolved;
}

/** Validate every limit as a finite, non-negative safe integer; null when usable. */
export function validateResponseLimits(limits: ResponseLimits): string | null {
  for (const key of Object.keys(defaultResponseLimits) as Array<keyof ResponseLimits>) {
    const value = limits[key];
    if (!Number.isSafeInteger(value) || value < 0) {
      return `limit ${key} must be a non-negative safe integer`;
    }
  }
  return null;
}
