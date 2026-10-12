/**
 * Certificate-validator entry point.
 *
 * The validator object owns a long-lived revocation cache, so a process that
 * validates many certificates reuses OCSP/CRL answers. It implements the
 * `validateCertificate` function the sender requires. The sender never imports
 * this module.
 */
import { RevocationCache, type RevocationPolicy } from './pki/revocation.js';
import { validateCertificatePem } from './pki/validate.js';
import type { CertificatePurpose, CertificateValidation, CertificateValidationInput } from './types.js';

export interface CertificateValidatorOptions {
  /** Peppol root trust anchor(s) (PEM). */
  readonly roots: readonly string[];
  /** Allowed intermediate CA certificate(s) (PEM) used for every purpose. */
  readonly intermediates: readonly string[];
  /**
   * Optional per-purpose intermediate CA sets. When a purpose appears here its
   * set replaces `intermediates` for that purpose, so an access point CA can be
   * kept from validating an SMP signer and vice versa. `message-signer` falls
   * back to `receipt-signer`, then to `intermediates`.
   */
  readonly intermediatesByPurpose?: Partial<Record<CertificatePurpose, readonly string[]>>;
  readonly revocation: RevocationPolicy;
  /** Reuse an existing cache instead of creating one. */
  readonly cache?: RevocationCache;
  /** Injectable fetch, for tests and for a proxied environment. */
  readonly fetch?: typeof fetch;
  /** Serials known revoked out of band, keyed by issuer common name. */
  readonly extraRevokedSerials?: Readonly<Record<string, readonly string[]>>;
}

export interface CertificateValidator {
  validate(input: CertificateValidationInput): Promise<CertificateValidation>;
}

/**
 * Choose the intermediate CAs for a purpose. A purpose-specific set wins; the
 * inbound user-message signer shares the receipt signer's set; otherwise the
 * flat `intermediates` list applies to every purpose.
 */
function intermediatesFor(options: CertificateValidatorOptions, purpose: CertificatePurpose): readonly string[] {
  const byPurpose = options.intermediatesByPurpose;
  const specific = byPurpose?.[purpose];
  if (specific) return specific;
  if (purpose === 'message-signer' && byPurpose?.['receipt-signer']) return byPurpose['receipt-signer'];
  return options.intermediates;
}

/** Build a validator bound to one trust configuration and one revocation cache. */
export function createCertificateValidator(options: CertificateValidatorOptions): CertificateValidator {
  const cache = options.cache ?? new RevocationCache();
  return {
    validate(input) {
      return validateCertificatePem(input.certificatePem, {
        roots: options.roots,
        intermediates: intermediatesFor(options, input.purpose),
        revocation: options.revocation,
        now: input.now,
        purpose: input.purpose,
        cache,
        ...(options.fetch ? { fetchImpl: options.fetch } : {}),
        ...(input.signal ? { signal: input.signal } : {}),
        ...(options.extraRevokedSerials ? { extraRevokedSerials: options.extraRevokedSerials } : {}),
      });
    },
  };
}

/** Stricter defaults: an unreachable revocation service blocks the send. */
export function defaultRevocationPolicy(overrides: Partial<RevocationPolicy> = {}): RevocationPolicy {
  return {
    unreachable: 'strict' as const,
    ocsp: true,
    crl: true,
    timeoutMs: 5_000,
    maxResponseBytes: 1024 * 1024,
    maxCacheMs: 60 * 60 * 1000,
    ...overrides,
  };
}

export { RevocationCache } from './pki/revocation.js';
export type { CertificateValidation, CertificateValidationInput, CertificatePurpose } from './types.js';
export type { RevocationAnswer, RevocationMode, RevocationPolicy, RevocationStatus } from './pki/revocation.js';
