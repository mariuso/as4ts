import { canonicalize, sha256Digest } from '../xml/c14n.js';
import { parseStrictXml } from './xml.js';

/**
 * The SwA content-signature transform digest for an attachment, chosen by media
 * type: an XML attachment is strictly parsed and canonicalised (exclusive C14N)
 * before digesting, while a binary or compressed attachment is digested as raw
 * bytes. The gzip attachment a Peppol sender emits is the binary case, so its
 * digest is the SHA-256 of the compressed bytes — which a receiver can only
 * compute after decryption and before decompression.
 *
 * The XML path rejects malformed content, DOCTYPEs, oversized documents and
 * unsupported encodings, and honours the declared encoding, so equivalent
 * documents in different encodings digest identically.
 */
export function attachmentDigestBase64(mediaType: string, bytes: Buffer): string {
  const type = mediaType.split(';')[0]?.trim().toLowerCase() ?? '';
  const isXml = type === 'application/xml' || type === 'text/xml' || type.endsWith('+xml');
  if (isXml) {
    return sha256Digest(Buffer.from(canonicalize(parseStrictXml(bytes)), 'utf8'));
  }
  return sha256Digest(bytes);
}
