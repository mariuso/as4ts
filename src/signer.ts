import { constants, sign as cryptoSign } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import type { Signer } from './types.js';

/**
 * Wrap a local RSA private key as a {@link Signer}. The key is used only to
 * produce RSA PKCS#1 v1.5 / SHA-256 signatures and never leaves this closure.
 *
 * The sender verifies every produced signature against the certificate before
 * anything is sent, so a wrong or mismatched key cannot go on the wire.
 */
export function signerFromKey(keyObject: KeyObject, certificatePem: string): Signer {
  if (keyObject.type !== 'private') throw new Error('signerFromKey: key must be a private key');
  if (keyObject.asymmetricKeyType !== 'rsa') throw new Error('signerFromKey: key must be an RSA key');
  return {
    certificate: certificatePem,
    async sign(data: Uint8Array): Promise<Uint8Array> {
      return cryptoSign('sha256', Buffer.from(data), {
        key: keyObject,
        padding: constants.RSA_PKCS1_PADDING,
      });
    },
  };
}
