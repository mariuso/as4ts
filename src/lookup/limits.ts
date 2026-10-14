/**
 * Limits for a Peppol SMP lookup response.
 *
 * Two shapes are fetched, and they are bounded separately: a `ServiceGroup` is
 * read only (a large participant publishes many document types, hence the high
 * node budget), while a `SignedServiceMetadata` is cloned and canonicalised
 * twice (document digest + SignedInfo). The shared depth/attribute/token limits
 * and the total canonicalisation budget apply to both. All defaults are far
 * above the recorded SMP fixtures (the largest is ~14 KB, 44 nodes, depth 3).
 *
 * These bounds are separate from the fixed HTTP response cap (8 MiB in
 * `src/lookup/http.ts`), which is not overridable here.
 */
export interface LookupLimits {
  readonly maxServiceGroupBytes: number;
  readonly maxServiceGroupNodes: number;
  readonly maxMetadataBytes: number;
  readonly maxMetadataNodes: number;
  readonly maxDepth: number;
  readonly maxAttributes: number;
  /** One text, attribute, comment, CDATA or markup token, in UTF-8 bytes. */
  readonly maxTokenBytes: number;
  /** Total canonicalisation budget for one signed-metadata verification. */
  readonly maxCanonicalBytes: number;
}

export const defaultLookupLimits: LookupLimits = {
  maxServiceGroupBytes: 8 * 1024 * 1024,
  maxServiceGroupNodes: 200_000,
  maxMetadataBytes: 1024 * 1024,
  maxMetadataNodes: 10_000,
  maxDepth: 64,
  maxAttributes: 64,
  maxTokenBytes: 64 * 1024,
  maxCanonicalBytes: 8 * 1024 * 1024,
};

/** Merge a caller override over the defaults; every property defaults independently. */
export function resolveLookupLimits(partial?: Partial<LookupLimits>): LookupLimits {
  const resolved: { -readonly [K in keyof LookupLimits]: LookupLimits[K] } = { ...defaultLookupLimits };
  if (!partial) return resolved;
  for (const key of Object.keys(defaultLookupLimits) as Array<keyof LookupLimits>) {
    const value = partial[key];
    if (value !== undefined) resolved[key] = value;
  }
  return resolved;
}

/** Validate every limit as a finite, non-negative safe integer; null when usable. */
export function validateLookupLimits(limits: LookupLimits): string | null {
  for (const key of Object.keys(defaultLookupLimits) as Array<keyof LookupLimits>) {
    const value = limits[key];
    if (!Number.isSafeInteger(value) || value < 0) {
      return `limit ${key} must be a non-negative safe integer`;
    }
  }
  return null;
}
