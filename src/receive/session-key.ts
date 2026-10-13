import { certFingerprint256, parseCertificate } from '../util.js';
import type { InboundFailureReason, InboundKeyHolder } from './types.js';

/**
 * Credential selection and session-key unwrap (Phase 2). The private-key
 * operation lives here, isolated from the structural parsing in `encryption.ts`.
 *
 * Selection prefers the credential the sender encrypted to (by certificate
 * fingerprint) and falls back to the supplied, bounded candidate list for
 * rollover. The unwrap contract is the empty-label RSA-OAEP(SHA-256,
 * MGF1-SHA-256) that `parseInboundEncryption` already validated — an inbound
 * identifier never selects an arbitrary remote key resource, and only a
 * configured holder is ever invoked.
 */
export class SessionKeyFault extends Error {
  constructor(
    readonly reason: InboundFailureReason,
    message: string,
  ) {
    super(message);
    this.name = 'SessionKeyFault';
  }
}

/** AES-128 session keys are exactly 16 bytes. */
const SESSION_KEY_BYTES = 16;

export interface UnwrappedSessionKey {
  /** Owned AES-128 session key; the caller clears it when done. */
  readonly sessionKey: Buffer;
  /** AP certificate of the credential that unwrapped it. */
  readonly credentialCertificate: string;
}

export interface UnwrapSessionKeyInput {
  readonly wrappedKey: Uint8Array;
  /** The certificate the sender encrypted to, when the EncryptedKey named one. */
  readonly recipientCertificate?: string;
  readonly holders: readonly InboundKeyHolder[];
  readonly maxCandidates: number;
  readonly signal?: AbortSignal;
}

function isAbortError(err: unknown): boolean {
  return err instanceof Error && (err.name === 'AbortError' || (err as NodeJS.ErrnoException).code === 'ABORT_ERR');
}

function fingerprint(pem: string): string | null {
  try {
    return certFingerprint256(parseCertificate(pem));
  } catch {
    return null;
  }
}

export async function unwrapSessionKey(input: UnwrapSessionKeyInput): Promise<UnwrappedSessionKey> {
  const candidates = input.holders.slice(0, Math.max(1, input.maxCandidates));
  if (candidates.length === 0) {
    throw new SessionKeyFault('decrypt.key-unwrap', 'no decryption credential configured');
  }

  // Prefer the credential named by the EncryptedKey; otherwise try the bounded
  // candidate list in order.
  let ordered = candidates;
  if (input.recipientCertificate) {
    const wanted = fingerprint(input.recipientCertificate);
    if (wanted) {
      const preferred = candidates.filter((holder) => fingerprint(holder.certificate) === wanted);
      if (preferred.length > 0) ordered = preferred;
    }
  }

  for (const holder of ordered) {
    if (input.signal?.aborted) throw new SessionKeyFault('aborted', 'aborted before unwrapping the session key');
    let key: Uint8Array;
    try {
      key = await holder.unwrap(input.wrappedKey, input.signal);
    } catch (err) {
      if (isAbortError(err)) throw new SessionKeyFault('aborted', 'aborted while unwrapping the session key');
      continue; // wrong credential, or a provider that could not serve this request
    }
    if (key.byteLength !== SESSION_KEY_BYTES) {
      // A provider returned something that is not an AES-128 key: hard failure.
      throw new SessionKeyFault(
        'decrypt.bad-key-length',
        `unwrapped key is ${key.byteLength} bytes, expected ${SESSION_KEY_BYTES}`,
      );
    }
    return { sessionKey: Buffer.from(key), credentialCertificate: holder.certificate };
  }
  throw new SessionKeyFault('decrypt.key-unwrap', 'no credential could unwrap the session key');
}
