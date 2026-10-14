import { createHash } from 'node:crypto';
import { CanonicalizationLimitExceeded, canonicalizeWithin, sha256Digest } from '../xml/c14n.js';
import { XmlFault, parseStrictXml, type XmlLimits } from './xml.js';

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
 * documents in different encodings digest identically. Canonicalisation runs only
 * when its conservative expansion bound fits `maxCanonicalBytes`; the resulting
 * string is hashed directly, without an intermediate UTF-8 buffer.
 */
export function attachmentDigestBase64(
  mediaType: string,
  bytes: Buffer,
  xmlLimits?: XmlLimits,
  maxCanonicalBytes = Number.MAX_SAFE_INTEGER,
): string {
  const type = mediaType.split(';')[0]?.trim().toLowerCase() ?? '';
  const isXml = type === 'application/xml' || type === 'text/xml' || type.endsWith('+xml');
  if (isXml) {
    const document = parseStrictXml(bytes, xmlLimits);
    try {
      const canonical = canonicalizeWithin(document, maxCanonicalBytes);
      return createHash('sha256').update(canonical, 'utf8').digest('base64');
    } catch (error) {
      // A canonicalisation budget failure is an XML size limit, not an internal
      // error: reclassify it so recovery maps it to `stage: 'xml'`.
      if (error instanceof CanonicalizationLimitExceeded) throw new XmlFault('xml.too-large', error.message);
      throw error;
    }
  }
  return sha256Digest(bytes);
}
