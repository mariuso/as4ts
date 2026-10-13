import type { DecipherGCM } from 'node:crypto';

/**
 * Narrow internal dependency seams. Not part of any package entry point; they
 * exist only so tests can inject a failing second-pass decipher or observe write
 * streams, which the public inputs cannot express.
 */
export interface PayloadHooks {
  readonly createDecipher?: ((algorithm: string, key: Buffer, iv: Buffer) => DecipherGCM) | undefined;
  readonly onWriteStream?: ((path: string) => void) | undefined;
  /** Called just before an inbound payload is read back for the SBDH check. */
  readonly onReadPayload?: (() => void) | undefined;
  /** Called with the recovery workspace directory once it is created. */
  readonly onWorkspace?: ((directory: string) => void) | undefined;
  /** Called just before a transferred ciphertext spool is renamed in. */
  readonly onSpoolTransfer?: ((from: string, to: string) => void) | undefined;
}

export const payloadHooks: {
  createDecipher?: ((algorithm: string, key: Buffer, iv: Buffer) => DecipherGCM) | undefined;
  onWriteStream?: ((path: string) => void) | undefined;
  onReadPayload?: (() => void) | undefined;
  onWorkspace?: ((directory: string) => void) | undefined;
  onSpoolTransfer?: ((from: string, to: string) => void) | undefined;
} = {};
