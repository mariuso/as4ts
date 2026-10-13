import type { DecipherGCM } from 'node:crypto';

/**
 * Narrow internal dependency seams. Not part of any package entry point; they
 * exist only so tests can inject a failing second-pass decipher or observe write
 * streams, which the public inputs cannot express.
 */
export interface PayloadHooks {
  readonly createDecipher?: ((algorithm: string, key: Buffer, iv: Buffer) => DecipherGCM) | undefined;
  readonly onWriteStream?: ((path: string) => void) | undefined;
}

export const payloadHooks: {
  createDecipher?: ((algorithm: string, key: Buffer, iv: Buffer) => DecipherGCM) | undefined;
  onWriteStream?: ((path: string) => void) | undefined;
} = {};
