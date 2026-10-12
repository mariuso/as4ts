import { randomBytes, randomUUID } from 'node:crypto';

/**
 * Every source of unpredictability the sender needs, behind one seam.
 *
 * Production uses the cryptographic RNG. Tests inject a deterministic
 * implementation so that a fixed input produces a byte-identical envelope and
 * multipart body (see test/golden.test.ts). Entropy never carries payload bytes,
 * keys or certificates.
 */
export interface Entropy {
  /** `length` random bytes. Used for the session key and the GCM IV. */
  bytes(length: number): Uint8Array;
  /** A random UUID string. Used for the attachment Content-ID. */
  uuid(): string;
}

/** The default, cryptographically secure entropy source. */
export function defaultEntropy(): Entropy {
  return {
    bytes: (length) => randomBytes(length),
    uuid: () => randomUUID(),
  };
}

/** A hex token of `byteLength` random bytes, as used for XML ids and boundaries. */
export function hexToken(entropy: Entropy, byteLength: number): string {
  return Buffer.from(entropy.bytes(byteLength)).toString('hex');
}
