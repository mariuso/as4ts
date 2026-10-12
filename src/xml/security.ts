import { constants, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import {
  ALGO_AES128_GCM,
  ALGO_EXC_C14N,
  ALGO_MGF1_SHA256,
  ALGO_RSA_OAEP,
  ALGO_RSA_SHA256,
  ALGO_SHA256,
  SWA_ATTACHMENT_CONTENT_ONLY,
  SWA_TRANSFORM_CIPHERTEXT,
  WSS_BASE64_ENCODING,
  WSS_ENCRYPTED_KEY_TOKEN_TYPE,
  WSS_X509_V3,
  SOAP_ENV_NS,
} from '../constants.js';
import { SenderFault } from '../errors.js';
import type { Signer } from '../types.js';
import { parseCertificate } from '../util.js';
import { canonicalize, canonicalizeDigest } from './c14n.js';
import { append, element, setAttr } from './nodes.js';

export interface SignedPart {
  /** Reference URI: `#<xmlId>` for SOAP parts, `cid:...` for an attachment. */
  readonly uri: string;
  /** One of the two known transforms. */
  readonly transform: string;
  /** Base64 digest value. */
  readonly digest: string;
}

export interface EncryptionParams {
  readonly receiverCertificatePem: string;
  readonly wrappedKey: Buffer;
  readonly encryptedKeyId: string;
  readonly encryptedDataId: string;
  readonly encryptionTokenId: string;
  /** `cid:<id>` of the encrypted attachment. [WSSSWA] §5. */
  readonly attachmentHref: string;
}

export interface SignatureParams {
  readonly signingTokenId: string;
  readonly signatureId: string;
  /** References in the order they must appear: Body, Messaging, attachment. */
  readonly references: readonly SignedPart[];
}

export function createSecurityHeader(doc: Document): Element {
  return element(doc, 'wsse', 'Security', { 'env:mustUnderstand': 'true' });
}

function binarySecurityToken(doc: Document, id: string, certPem: string): Element {
  const der = Buffer.from(parseCertificate(certPem).raw);
  return element(
    doc,
    'wsse',
    'BinarySecurityToken',
    {
      'wsu:Id': id,
      EncodingType: WSS_BASE64_ENCODING,
      ValueType: WSS_X509_V3,
    },
    der.toString('base64'),
  );
}

function securityTokenReference(
  doc: Document,
  targetId: string,
  opts: { readonly valueType?: string; readonly tokenType?: string } = {},
): Element {
  const str = element(doc, 'wsse', 'SecurityTokenReference');
  if (opts.tokenType) setAttr(str, 'wsse11:TokenType', opts.tokenType);
  const refAttrs: Record<string, string> = { URI: `#${targetId}` };
  if (opts.valueType) refAttrs['ValueType'] = opts.valueType;
  append(str, element(doc, 'wsse', 'Reference', refAttrs));
  return str;
}

/** Append the X.509 encryption token, xenc:EncryptedKey and xenc:EncryptedData. */
export function addEncryption(doc: Document, security: Element, p: EncryptionParams): void {
  append(security, binarySecurityToken(doc, p.encryptionTokenId, p.receiverCertificatePem));

  const encryptedKey = element(doc, 'xenc', 'EncryptedKey', { Id: p.encryptedKeyId });
  const encKeyMethod = element(doc, 'xenc', 'EncryptionMethod', { Algorithm: ALGO_RSA_OAEP });
  append(encKeyMethod, element(doc, 'ds', 'DigestMethod', { Algorithm: ALGO_SHA256 }));
  append(encKeyMethod, element(doc, 'xenc11', 'MGF', { Algorithm: ALGO_MGF1_SHA256 }));
  append(encryptedKey, encKeyMethod);

  const encKeyKeyInfo = element(doc, 'ds', 'KeyInfo');
  append(encKeyKeyInfo, securityTokenReference(doc, p.encryptionTokenId, { valueType: WSS_X509_V3 }));
  append(encryptedKey, encKeyKeyInfo);

  const encKeyCipherData = element(doc, 'xenc', 'CipherData');
  append(encKeyCipherData, element(doc, 'xenc', 'CipherValue', {}, p.wrappedKey.toString('base64')));
  append(encryptedKey, encKeyCipherData);

  const referenceList = element(doc, 'xenc', 'ReferenceList');
  append(referenceList, element(doc, 'xenc', 'DataReference', { URI: `#${p.encryptedDataId}` }));
  append(encryptedKey, referenceList);
  append(security, encryptedKey);

  const encryptedData = element(doc, 'xenc', 'EncryptedData', {
    Id: p.encryptedDataId,
    MimeType: 'application/gzip',
    Type: SWA_ATTACHMENT_CONTENT_ONLY,
  });
  append(encryptedData, element(doc, 'xenc', 'EncryptionMethod', { Algorithm: ALGO_AES128_GCM }));

  const dataKeyInfo = element(doc, 'ds', 'KeyInfo');
  append(dataKeyInfo, securityTokenReference(doc, p.encryptedKeyId, { tokenType: WSS_ENCRYPTED_KEY_TOKEN_TYPE }));
  append(encryptedData, dataKeyInfo);

  const dataCipherData = element(doc, 'xenc', 'CipherData');
  const cipherReference = element(doc, 'xenc', 'CipherReference', { URI: p.attachmentHref });
  const transforms = element(doc, 'xenc', 'Transforms');
  append(transforms, element(doc, 'ds', 'Transform', { Algorithm: SWA_TRANSFORM_CIPHERTEXT }));
  append(cipherReference, transforms);
  append(dataCipherData, cipherReference);
  append(encryptedData, dataCipherData);
  append(security, encryptedData);
}

/**
 * Append the signing X.509 token and the ds:Signature.
 *
 * The signature covers the empty SOAP Body, the eb:Messaging header and the
 * attachment, in that order, per [AS4PROFILE] §5.1.4/§5.1.5 and the CEF
 * example. It is computed (and must be verified) with exclusive C14N and
 * RSA-SHA256, and the attachment digest is the SwA content signature transform
 * over the pre-encryption (gzipped) bytes.
 *
 * The produced signature is verified against `signer.certificate` before it is
 * placed on the wire; a mismatch throws {@link SenderFault} and nothing is sent.
 */
export async function addSignature(
  doc: Document,
  security: Element,
  p: SignatureParams,
  signer: Signer,
  signal?: AbortSignal,
): Promise<void> {
  append(security, binarySecurityToken(doc, p.signingTokenId, signer.certificate));

  const signature = element(doc, 'ds', 'Signature', { Id: p.signatureId });
  const signedInfo = element(doc, 'ds', 'SignedInfo');
  // WS-Security convention: the SignedInfo is canonicalized with exclusive C14N
  // and the inclusive prefix list "env". The env declaration must be present on
  // SignedInfo for exclusive C14N to emit it (xml-crypto renders the literal
  // declaration; Apache Santuario synthesizes it, and the receiver expects it).
  setAttr(signedInfo, 'xmlns:env', SOAP_ENV_NS);

  const c14nMethod = element(doc, 'ds', 'CanonicalizationMethod', { Algorithm: ALGO_EXC_C14N });
  append(c14nMethod, element(doc, 'ec', 'InclusiveNamespaces', { PrefixList: 'env' }));
  append(signedInfo, c14nMethod);
  append(signedInfo, element(doc, 'ds', 'SignatureMethod', { Algorithm: ALGO_RSA_SHA256 }));

  for (const ref of p.references) {
    const reference = element(doc, 'ds', 'Reference', { URI: ref.uri });
    const transforms = element(doc, 'ds', 'Transforms');
    append(transforms, element(doc, 'ds', 'Transform', { Algorithm: ref.transform }));
    append(reference, transforms);
    append(reference, element(doc, 'ds', 'DigestMethod', { Algorithm: ALGO_SHA256 }));
    append(reference, element(doc, 'ds', 'DigestValue', {}, ref.digest));
    append(signedInfo, reference);
  }

  const signatureValue = await signSignedInfo(signedInfo, signer, signal);
  append(signature, signedInfo);
  append(signature, element(doc, 'ds', 'SignatureValue', {}, signatureValue));

  const keyInfo = element(doc, 'ds', 'KeyInfo');
  append(keyInfo, securityTokenReference(doc, p.signingTokenId, { valueType: WSS_X509_V3 }));
  append(signature, keyInfo);
  append(security, signature);
}

/**
 * Canonicalize ds:SignedInfo with the inclusive `env` prefix (WS-Security
 * convention), sign it with the injected signer, and verify the result against
 * the signer's certificate. Throws `SenderFault` when the signature does not
 * verify.
 */
export async function signSignedInfo(signedInfo: Element, signer: Signer, signal?: AbortSignal): Promise<string> {
  const canonical = canonicalize(signedInfo);
  const signature = await signer.sign(Buffer.from(canonical, 'utf8'), signal);
  if (!verifySignedInfoSignature(signedInfo, signature, signer.certificate)) {
    throw new SenderFault('signature.mismatch', 'the produced signature does not verify with the signer certificate');
  }
  return Buffer.from(signature).toString('base64');
}

function verifySignedInfoSignature(signedInfo: Element, signature: Uint8Array, certificatePem: string): boolean {
  try {
    const canonical = canonicalize(signedInfo);
    return cryptoVerify(
      'sha256',
      Buffer.from(canonical, 'utf8'),
      { key: createPublicKey(certificatePem), padding: constants.RSA_PKCS1_PADDING },
      Buffer.from(signature),
    );
  } catch {
    return false;
  }
}

export { canonicalizeDigest };
