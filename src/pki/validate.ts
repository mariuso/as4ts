import type { CertificatePurpose, CertificateValidation } from '../types.js';
import { commonNameOf, parseCertificate } from '../util.js';
import { buildCertificatePath } from './chain.js';
import {
  checkRevocation,
  extractRevocationEndpoints,
  RevocationCache,
  type RevocationAnswer,
  type RevocationPolicy,
} from './revocation.js';

export interface ValidateCertificatePemOptions {
  readonly roots: readonly string[];
  readonly intermediates: readonly string[];
  readonly revocation: RevocationPolicy;
  readonly now: Date;
  /** Selects the leaf Key Usage requirement; defaults to any signing or encryption use. */
  readonly purpose?: CertificatePurpose;
  readonly cache?: RevocationCache;
  readonly fetchImpl?: typeof fetch;
  readonly signal?: AbortSignal;
  /** Serials known revoked out of band, keyed by issuer common name. */
  readonly extraRevokedSerials?: Readonly<Record<string, readonly string[]>>;
}

/**
 * Validate a Peppol access point certificate: build a real path to a configured
 * root, check validity and CA constraints, then check revocation for every
 * non-anchor certificate.
 *
 * Revocation policy: [PEPPOLAS4] §4.7 requires certificates to be verified when
 * fetched from SMP and requires them to be issued by OpenPeppol. When an OCSP
 * or CRL answer cannot be obtained, `revocation.unreachable` decides: `strict`
 * (default) refuses and reports `unavailable`; `soft` proceeds.
 */
export async function validateCertificatePem(
  pem: string,
  options: ValidateCertificatePemOptions,
): Promise<CertificateValidation> {
  const leaf = parseCertificate(pem);
  const now = options.now;
  const path = buildCertificatePath(
    leaf,
    options.intermediates,
    options.roots,
    now,
    options.purpose !== undefined ? { purpose: options.purpose } : {},
  );
  if (!path.ok) {
    return { ok: false, status: 'invalid', reason: path.reason };
  }

  const cache = options.cache ?? new RevocationCache();
  let worst: RevocationAnswer | null = null;

  for (let i = 0; i < path.chain.length - 1; i += 1) {
    const cert = path.chain[i]!;
    const issuer = path.chain[i + 1]!;
    const endpoints = extractRevocationEndpoints(cert);
    const answer = await checkRevocation(cert, issuer, endpoints, {
      policy: options.revocation,
      now: () => now,
      cache,
      ...(options.fetchImpl ? { fetchImpl: options.fetchImpl } : {}),
      ...(options.signal ? { signal: options.signal } : {}),
      ...(options.extraRevokedSerials ? { extraRevokedSerials: options.extraRevokedSerials } : {}),
    });
    if (answer.status === 'revoked') {
      return {
        ok: false,
        status: 'revoked',
        reason: `${commonNameOf(cert)}: ${answer.reason}`,
      };
    }
    if (!worst || answer.status === 'unknown') worst = answer;
  }

  const revocation: RevocationAnswer = worst ?? {
    status: 'unknown',
    source: 'none',
    reason: 'no revocation endpoints',
  };

  if (revocation.status === 'unknown' && options.revocation.unreachable === 'strict') {
    return { ok: false, status: 'unavailable', reason: revocation.reason };
  }

  return { ok: true };
}
