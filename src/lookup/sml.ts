import { createHash } from 'node:crypto';
import { resolveNaptr as nodeResolveNaptr } from 'node:dns/promises';
import type { ParticipantId } from '../types.js';
import { SML_NAPTR_SERVICE } from './constants.js';
import type { NaptrRecord, NaptrResolver } from './types.js';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Base32 (RFC 4648, no padding) of the SHA-256 of the lowercased participant
 * identifier value. [PFUOI4] POLICY 7, [SML] §3.1.1.
 */
export function participantHash(value: string): string {
  const digest = createHash('sha256').update(value.toLowerCase(), 'utf8').digest();
  let bits = '';
  for (const byte of digest) bits += byte.toString(2).padStart(8, '0');
  while (bits.length % 5 !== 0) bits += '0';
  let out = '';
  for (let i = 0; i + 5 <= bits.length; i += 5) out += BASE32_ALPHABET[parseInt(bits.slice(i, i + 5), 2)];
  return out;
}

/** The DNS name to query: `<hash>.<scheme>.<sml zone>`. [PFUOI4] POLICY 7. */
export function participantDnsName(participant: ParticipantId, smlZone: string): string {
  const zone = smlZone.trim().replace(/\.+$/, '');
  return `${participantHash(participant.value)}.${participant.scheme}.${zone}`;
}

export interface SmpBase {
  readonly ok: true;
  readonly url: string;
}

export interface SmpBaseFailure {
  readonly ok: false;
  readonly reason: string;
  /** Whether a retry could help. */
  readonly retryable: boolean;
}

export type SmpBaseResolution = SmpBase | SmpBaseFailure;

/**
 * Resolve the SMP base URL from NAPTR records. Only the `Meta:SMP` service with
 * the `u` (URI) flag is used, in order/preference order, and the result must be
 * an `https:` URL with no userinfo, query or fragment ([SML] v1.3.0 §2.1.1).
 */
export function smpBaseFromRecords(records: readonly NaptrRecord[], domain: string): SmpBaseResolution {
  const usable = [...records]
    .filter((r) => (r.flags ?? '').toLowerCase() === 'u')
    .filter((r) => (r.service ?? '').toLowerCase() === SML_NAPTR_SERVICE)
    .sort((a, b) => a.order - b.order || a.preference - b.preference);
  if (usable.length === 0) {
    return { ok: false, reason: `no ${SML_NAPTR_SERVICE} NAPTR record for ${domain}`, retryable: false };
  }

  for (const record of usable) {
    const uri = applyNaptrRegexp(record.regexp, domain);
    if (!uri) continue;
    let url: URL;
    try {
      url = new URL(uri);
    } catch {
      continue;
    }
    if (url.protocol !== 'https:') {
      return { ok: false, reason: `SMP URL ${uri} is not https ([SML] v1.3.0 §2.1.1)`, retryable: false };
    }
    if (url.username || url.password || url.search || url.hash) {
      return {
        ok: false,
        reason: `SMP URL ${uri} has userinfo, query or fragment ([SML] v1.3.0 §2.1.1)`,
        retryable: false,
      };
    }
    return { ok: true, url: `${url.origin}${trimTrailingSlash(url.pathname)}` };
  }
  return { ok: false, reason: `no usable ${SML_NAPTR_SERVICE} NAPTR record for ${domain}`, retryable: false };
}

function trimTrailingSlash(path: string): string {
  return path.length > 1 ? path.replace(/\/+$/, '') : '';
}

/**
 * Apply a NAPTR regular-expression field to a domain name. The field is
 * `/delimiter pattern delimiter replacement delimiter flags`.
 */
function applyNaptrRegexp(regexp: string, domain: string): string | null {
  if (typeof regexp !== 'string' || regexp.length < 2) return null;
  const delimiter = regexp[0]!;
  const end = regexp.lastIndexOf(delimiter);
  if (end <= 0) return null;
  const body = regexp.slice(1, end);
  const flags = regexp.slice(end + 1);
  const separator = body.indexOf(delimiter);
  if (separator < 0) return null;
  const pattern = body.slice(0, separator);
  const replacement = body.slice(separator + 1);
  let matcher: RegExp;
  try {
    matcher = new RegExp(pattern, flags.includes('i') ? 'i' : '');
  } catch {
    return null;
  }
  if (!matcher.test(domain)) return null;
  return domain.replace(matcher, replacement.replace(/\\\\(\d)/g, '$$$1'));
}

/** The default NAPTR resolver: Node's `dns.promises.resolveNaptr`. */
export const defaultResolveNaptr: NaptrResolver = (domain) => nodeResolveNaptr(domain);

const NOT_FOUND_CODES = new Set(['ENOTFOUND', 'ENODATA', 'NXDOMAIN']);

/** Classify a DNS failure: missing names are facts, transport failures are retryable. */
export function classifyDnsError(err: unknown): {
  readonly notRegistered: boolean;
  readonly retryable: boolean;
  readonly reason: string;
} {
  const code = (err as NodeJS.ErrnoException | undefined)?.code ?? '';
  const reason = err instanceof Error ? err.message : String(err);
  if (NOT_FOUND_CODES.has(code)) return { notRegistered: true, retryable: false, reason };
  return { notRegistered: false, retryable: true, reason };
}
