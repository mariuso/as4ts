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
import type { CertificateValidation, CertificateValidationInput } from './types.js';

export interface CertificateValidatorOptions {
  /** Peppol root trust anchor(s) (PEM). */
  readonly roots: readonly string[];
  /** Allowed intermediate CA certificate(s) (PEM). */
  readonly intermediates: readonly string[];
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

/** Build a validator bound to one trust configuration and one revocation cache. */
export function createCertificateValidator(options: CertificateValidatorOptions): CertificateValidator {
  const cache = options.cache ?? new RevocationCache();
  return {
    validate(input) {
      return validateCertificatePem(input.certificatePem, {
        roots: options.roots,
        intermediates: options.intermediates,
        revocation: options.revocation,
        now: input.now,
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
    maxCacheMs: 60 * 60 * 1000,
    ...overrides,
  };
}

export { RevocationCache } from './pki/revocation.js';
export type { CertificateValidation, CertificateValidationInput, CertificatePurpose } from './types.js';
export type { RevocationAnswer, RevocationMode, RevocationPolicy, RevocationStatus } from './pki/revocation.js';
