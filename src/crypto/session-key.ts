import { constants, publicEncrypt } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import { defaultEntropy, type Entropy } from '../entropy.js';

export interface WrappedSessionKey {
  /** 16-byte AES-128-GCM session key. Never logged. */
  readonly sessionKey: Buffer;
  /** RSA-OAEP(SHA-256, MGF1-SHA-256) wrapped session key. */
  readonly wrappedKey: Buffer;
}

/**
 * Wrap a fresh AES-128 session key for the receiver.
 *
 * [CEFEAS4] §3.2.6 mandates xenc:EncryptionMethod Algorithm
 * http://www.w3.org/2009/xmlenc11#rsa-oaep, DigestMethod
 * http://www.w3.org/2001/04/xmlenc#sha256 and MGF
 * http://www.w3.org/2009/xmlenc11#mgf1sha256. Node's RSA-OAEP uses the same
 * digest for MGF1 unless told otherwise, which is exactly this combination.
 *
 * The session key is drawn from `entropy` so tests can pin it; the OAEP random
 * padding still comes from OpenSSL, exactly as on the wire today.
 */
export function wrapSessionKey(receiverPublicKey: KeyObject, entropy: Entropy = defaultEntropy()): WrappedSessionKey {
  const sessionKey = Buffer.from(entropy.bytes(16));
  const wrappedKey = publicEncrypt(
    {
      key: receiverPublicKey,
      oaepHash: 'sha256',
      padding: constants.RSA_PKCS1_OAEP_PADDING,
    },
    sessionKey,
  );
  return { sessionKey, wrappedKey };
}
