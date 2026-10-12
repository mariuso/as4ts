import { createCipheriv, createHash } from 'node:crypto';
import { createGzip } from 'node:zlib';
import { createWriteStream } from 'node:fs';
import { pipeline } from 'node:stream/promises';
import { Transform } from 'node:stream';
import type { Readable } from 'node:stream';
import { defaultEntropy, type Entropy } from '../entropy.js';

export interface PreparedPayload {
  /** Path of the temp file holding IV || ciphertext || tag. */
  readonly filePath: string;
  /** Size of that file in bytes. */
  readonly byteLength: number;
  /** Base64 SHA-256 of the gzipped plaintext (the SwA signed digest). */
  readonly compressedDigestBase64: string;
  /** Wrapped session key bytes. */
  readonly wrappedKey: Buffer;
}

export interface PreparePayloadOptions {
  readonly source: Readable;
  readonly sessionKey: Buffer;
  readonly wrappedKey: Buffer;
  readonly filePath: string;
  /** Gzip level. The AS4 compression feature uses RFC 1952 gzip. */
  readonly gzipLevel?: number;
  /** Test-only, pins the 12-byte GCM IV. */
  readonly entropy?: Entropy;
  /** Aborting stops the spooling pass and leaves no partial temp file. */
  readonly signal?: AbortSignal;
}

/**
 * Single streaming pass over the payload:
 *
 *   payload -> gzip -> [ SHA-256 | AES-128-GCM ] -> temp file
 *
 * Two different artefacts come out of the same pass:
 *  - the SHA-256 of the *gzipped* bytes, which is what the SwA
 *    Attachment-Content-Signature-Transform digests ([WSSSWA] §5,
 *    [CEFEAS4] §3.2.3: compression is applied before signing); and
 *  - the AES-128-GCM ciphertext laid out as 12-byte IV, ciphertext, 16-byte tag,
 *    the CipherValue format of XML Encryption 1.1 for GCM.
 *
 * The payload is never buffered in full and never parsed.
 */
export async function preparePayload(options: PreparePayloadOptions): Promise<PreparedPayload> {
  const { source, sessionKey, wrappedKey, filePath } = options;
  const entropy = options.entropy ?? defaultEntropy();
  const iv = Buffer.from(entropy.bytes(12));
  const cipher = createCipheriv('aes-128-gcm', sessionKey, iv);
  const hash = createHash('sha256');
  const out = createWriteStream(filePath, { mode: 0o600 });
  out.write(iv);
  let byteLength = iv.byteLength;

  const encryptor = new Transform({
    transform(chunk: Buffer, _enc, callback) {
      try {
        hash.update(chunk);
        const encrypted = cipher.update(chunk);
        byteLength += encrypted.byteLength;
        callback(null, encrypted);
      } catch (err) {
        callback(err as Error);
      }
    },
    flush(callback) {
      try {
        const final = cipher.final();
        const tag = cipher.getAuthTag();
        byteLength += final.byteLength + tag.byteLength;
        this.push(final);
        this.push(tag);
        callback();
      } catch (err) {
        callback(err as Error);
      }
    },
  });

  const pipelineOptions = options.signal ? { signal: options.signal } : {};
  await pipeline(source, createGzip({ level: options.gzipLevel ?? 6 }), encryptor, out, pipelineOptions);

  return {
    filePath,
    byteLength,
    compressedDigestBase64: hash.digest('base64'),
    wrappedKey,
  };
}
