import { constants, privateDecrypt } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import type { InboundKeyHolder } from './types.js';

/**
 * Wrap a local RSA private key as an {@link InboundKeyHolder}. The key unwraps
 * the inbound RSA-OAEP (SHA-256, MGF1-SHA-256) session key and never leaves this
 * closure; the returned key buffer is freshly allocated each call and ownership
 * transfers to the caller, which clears it.
 *
 * A receiver whose unwrap happens in a managed key service should implement
 * {@link InboundKeyHolder} directly rather than load the private key locally.
 */
export function keyHolderFromKey(keyObject: KeyObject, certificate: string): InboundKeyHolder {
  if (keyObject.type !== 'private') throw new Error('keyHolderFromKey: key must be a private key');
  if (keyObject.asymmetricKeyType !== 'rsa') throw new Error('keyHolderFromKey: key must be an RSA key');
  return {
    certificate,
    async unwrap(wrappedKey: Uint8Array, signal?: AbortSignal): Promise<Uint8Array> {
      signal?.throwIfAborted();
      return privateDecrypt(
        { key: keyObject, oaepHash: 'sha256', padding: constants.RSA_PKCS1_OAEP_PADDING },
        Buffer.from(wrappedKey),
      );
    },
  };
}
