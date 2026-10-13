import { certFingerprint256, parseCertificate } from '../util.js';
import type { InboundFailureReason, InboundKeyHolder } from './types.js';

/**
 * Credential selection and session-key unwrap (Phase 2). The private-key
 * operation lives here, isolated from the structural parsing in `encryption.ts`.
 *
 * Selection orders the configured credentials (the one the EncryptedKey named
 * first) and *then* caps the number of private-key attempts, so a bound never
 * hides the preferred credential. The unwrap contract is the empty-label
 * RSA-OAEP(SHA-256, MGF1-SHA-256) that `parseInboundEncryption` validated — only
 * a configured holder is ever invoked. Waiting is cancellable even when a
 * provider stalls, and a result that arrives after cancellation is discarded.
 *
 * A holder that cannot serve the request rejects with an error carrying
 * `code === 'KEY_UNAVAILABLE'`; that is reported distinctly from exhausting
 * credentials that were simply wrong.
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
  /** Upper bound on private-key attempts; a non-positive/invalid value means none. */
  readonly maxCandidates: number;
  readonly signal?: AbortSignal;
}

function abortError(): Error {
  const error = new Error('aborted');
  error.name = 'AbortError';
  (error as NodeJS.ErrnoException).code = 'ABORT_ERR';
  return error;
}

function isAbortError(err: unknown): boolean {
  return err instanceof Error && (err.name === 'AbortError' || (err as NodeJS.ErrnoException).code === 'ABORT_ERR');
}

function isUnavailable(err: unknown): boolean {
  return typeof err === 'object' && err !== null && (err as { code?: unknown }).code === 'KEY_UNAVAILABLE';
}

function fingerprint(pem: string): string | null {
  try {
    return certFingerprint256(parseCertificate(pem));
  } catch {
    return null;
  }
}

/**
 * Resolve or reject as soon as `signal` aborts. Fulfilment/rejection handlers are
 * always attached, so a provider rejection is never left unhandled even when the
 * signal is already aborted, and a result that arrives after cancellation is
 * passed to `onAbandon` for disposal instead of being dropped.
 */
function raceWithSignal<T>(
  promise: Promise<T>,
  signal: AbortSignal | undefined,
  onAbandon: (value: T) => void,
): Promise<T> {
  if (!signal) return promise;
  let settled = false;
  return new Promise<T>((resolve, reject) => {
    const onAbort = (): void => {
      if (settled) return;
      settled = true;
      reject(abortError());
    };
    if (signal.aborted) onAbort();
    else signal.addEventListener('abort', onAbort, { once: true });

    promise.then(
      (value) => {
        signal.removeEventListener('abort', onAbort);
        if (settled) {
          // Cancellation already won: dispose the abandoned result.
          onAbandon(value);
          return;
        }
        settled = true;
        resolve(value);
      },
      (err) => {
        signal.removeEventListener('abort', onAbort);
        if (settled) return; // already rejected through cancellation
        settled = true;
        reject(err);
      },
    );
  });
}

export async function unwrapSessionKey(input: UnwrapSessionKeyInput): Promise<UnwrappedSessionKey> {
  const bound = Number.isInteger(input.maxCandidates) && input.maxCandidates > 0 ? input.maxCandidates : 0;
  if (bound === 0 || input.holders.length === 0) {
    throw new SessionKeyFault('decrypt.key-unwrap', 'no decryption credential configured');
  }

  // Order the configured credentials first (the referenced one at the front),
  // then cap the attempts.
  const wanted = input.recipientCertificate ? fingerprint(input.recipientCertificate) : null;
  const ordered = wanted
    ? [
        ...input.holders.filter((holder) => fingerprint(holder.certificate) === wanted),
        ...input.holders.filter((holder) => fingerprint(holder.certificate) !== wanted),
      ]
    : [...input.holders];
  const candidates = ordered.slice(0, bound);

  let providerUnavailable = false;
  for (const holder of candidates) {
    if (input.signal?.aborted) throw new SessionKeyFault('aborted', 'aborted before unwrapping the session key');
    let key: Uint8Array;
    try {
      key = await raceWithSignal(holder.unwrap(input.wrappedKey, input.signal), input.signal, (late) => late.fill(0));
    } catch (err) {
      if (isAbortError(err)) throw new SessionKeyFault('aborted', 'aborted while unwrapping the session key');
      if (isUnavailable(err)) providerUnavailable = true;
      continue; // wrong credential, or a provider that could not serve this request
    }
    if (input.signal?.aborted) {
      // Discard a result that arrived after cancellation.
      key.fill(0);
      throw new SessionKeyFault('aborted', 'aborted while unwrapping the session key');
    }
    if (key.byteLength !== SESSION_KEY_BYTES) {
      throw new SessionKeyFault(
        'decrypt.bad-key-length',
        `unwrapped key is ${key.byteLength} bytes, expected ${SESSION_KEY_BYTES}`,
      );
    }
    return { sessionKey: Buffer.from(key), credentialCertificate: holder.certificate };
  }

  if (providerUnavailable) {
    throw new SessionKeyFault('decrypt.key-unavailable', 'the key provider was unavailable');
  }
  throw new SessionKeyFault('decrypt.key-unwrap', 'no credential could unwrap the session key');
}
