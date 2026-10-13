import {
  ALGO_AES128_GCM,
  ALGO_MGF1_SHA256,
  ALGO_RSA_OAEP,
  ALGO_SHA256,
  DS_NS,
  SWA_ATTACHMENT_CONTENT_ONLY,
  SWA_TRANSFORM_CIPHERTEXT,
  WSSE_NS,
  XENC_NS,
  XENC11_NS,
} from '../constants.js';
import { normalizePem } from '../util.js';
import { attrOf, elementsByLocalName, firstByLocalName, textOf } from '../xml/nodes.js';
import { resolveIdUnique } from '../xml/ws-security.js';
import type { InboundEncryption, InboundFailureReason } from './types.js';

/**
 * Structural validation of the inbound encryption graph (Phase 2). This module
 * performs no private-key operation: it resolves and checks the shape of
 * `xenc:EncryptedData`, `xenc:EncryptedKey` and their references so that a
 * credential is only ever invoked against an unambiguous, supported descriptor.
 *
 * It rejects ambiguous ids, external references (this never fetches a URI), an
 * unsupported data/key encapsulation algorithm, a ciphertext transform other
 * than attachment-ciphertext, and non-empty OAEP parameters. It does not treat an
 * omitted RSA-OAEP digest/MGF as SHA-256: XML Encryption's defaults differ, so the
 * parameters must be declared. [XMLENC11] §5.5.2, [WSSSWA] §5.5.3
 */
export class EncryptionFault extends Error {
  constructor(
    readonly reason: InboundFailureReason,
    message: string,
  ) {
    super(message);
    this.name = 'EncryptionFault';
  }
}

function invalid(message: string): never {
  throw new EncryptionFault('encryption.invalid', message);
}
function unsupported(message: string): never {
  throw new EncryptionFault('decrypt.unsupported-algorithm', message);
}

function single(elements: readonly Element[], what: string): Element {
  if (elements.length === 0) invalid(`no ${what} found`);
  if (elements.length > 1) invalid(`more than one ${what} found`);
  return elements[0]!;
}

/** Resolve an internal `#id` reference to exactly one element; no external fetches. */
function resolveInternal(doc: Document, uri: string | null, what: string): Element {
  if (!uri || !uri.startsWith('#')) invalid(`${what} reference is missing or external`);
  const id = uri.slice(1);
  const resolved = resolveIdUnique(doc, id);
  if (resolved.matches > 1) invalid(`duplicate id for ${what}`);
  if (!resolved.element) invalid(`unresolved ${what} reference`);
  return resolved.element;
}

function base64Bytes(value: string | null, what: string): Uint8Array {
  if (!value) invalid(`missing ${what}`);
  const cleaned = value.replace(/\s+/g, '');
  if (cleaned === '') invalid(`empty ${what}`);
  const bytes = Buffer.from(cleaned, 'base64');
  if (bytes.byteLength === 0) invalid(`undecodable ${what}`);
  return bytes;
}

function binarySecurityTokenPem(token: Element): string {
  const b64 = textOf(token)?.replace(/\s+/g, '');
  if (!b64) invalid('encryption token is empty');
  return normalizePem(`-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----`);
}

export function parseInboundEncryption(doc: Document): InboundEncryption {
  const security = single(elementsByLocalName(doc, WSSE_NS, 'Security'), 'wsse:Security header');

  const encryptedData = single(elementsByLocalName(security, XENC_NS, 'EncryptedData'), 'xenc:EncryptedData');
  const encryptedKey = single(elementsByLocalName(security, XENC_NS, 'EncryptedKey'), 'xenc:EncryptedKey');

  // The EncryptedData must name the EncryptedKey that decrypts it, once.
  const dataKeyRef = firstByLocalName(encryptedData, WSSE_NS, 'SecurityTokenReference');
  const dataKeyUri = attrOf(firstByLocalName(dataKeyRef, WSSE_NS, 'Reference'), 'URI');
  const keyElement = resolveInternal(doc, dataKeyUri, 'EncryptedData KeyInfo');
  if (keyElement !== encryptedKey) invalid('EncryptedData does not reference the EncryptedKey');

  // The EncryptedKey must reference the EncryptedData once (ReferenceList).
  const dataReferences = elementsByLocalName(encryptedKey, XENC_NS, 'DataReference');
  if (dataReferences.length !== 1) invalid('EncryptedKey must carry exactly one DataReference');
  const referencedData = resolveInternal(doc, attrOf(dataReferences[0]!, 'URI'), 'EncryptedKey DataReference');
  if (referencedData !== encryptedData) invalid('EncryptedKey does not reference the EncryptedData');

  // Data algorithm and SwA shape.
  const dataMethod = attrOf(firstByLocalName(encryptedData, XENC_NS, 'EncryptionMethod'), 'Algorithm');
  if (dataMethod !== ALGO_AES128_GCM) unsupported(`unsupported data encryption algorithm ${dataMethod ?? '(none)'}`);
  const dataType = attrOf(encryptedData, 'Type');
  if (dataType !== SWA_ATTACHMENT_CONTENT_ONLY) unsupported(`unsupported EncryptedData Type ${dataType ?? '(none)'}`);
  const mediaType = attrOf(encryptedData, 'MimeType');
  if (!mediaType) invalid('EncryptedData has no MimeType');
  if (!attrOf(encryptedData, 'Id')) invalid('EncryptedData has no Id');

  // CipherReference must be an internal `cid:` attachment with the ciphertext transform.
  const cipherReference = firstByLocalName(
    firstByLocalName(encryptedData, XENC_NS, 'CipherData'),
    XENC_NS,
    'CipherReference',
  );
  if (!cipherReference) invalid('EncryptedData has no CipherReference');
  const attachmentHref = attrOf(cipherReference, 'URI');
  if (!attachmentHref || !attachmentHref.startsWith('cid:'))
    invalid('CipherReference is not an internal cid: reference');
  const transforms = elementsByLocalName(cipherReference, DS_NS, 'Transform');
  if (transforms.length !== 1 || attrOf(transforms[0]!, 'Algorithm') !== SWA_TRANSFORM_CIPHERTEXT) {
    unsupported('CipherReference must use exactly the attachment-ciphertext transform');
  }

  // Key encapsulation: RSA-OAEP with declared SHA-256, MGF1-SHA-256 and an empty label.
  const keyMethod = firstByLocalName(encryptedKey, XENC_NS, 'EncryptionMethod');
  if (attrOf(keyMethod, 'Algorithm') !== ALGO_RSA_OAEP) {
    unsupported(`unsupported key encapsulation algorithm ${attrOf(keyMethod, 'Algorithm') ?? '(none)'}`);
  }
  const digest = attrOf(firstByLocalName(keyMethod, DS_NS, 'DigestMethod'), 'Algorithm');
  if (digest !== ALGO_SHA256) unsupported('RSA-OAEP must declare DigestMethod SHA-256');
  const mgf = attrOf(firstByLocalName(keyMethod, XENC11_NS, 'MGF'), 'Algorithm');
  if (mgf !== ALGO_MGF1_SHA256) unsupported('RSA-OAEP must declare MGF1-SHA-256');
  const oaepParams = firstByLocalName(keyMethod, XENC_NS, 'OAEPparams');
  const label = oaepParams ? new Uint8Array(base64Bytes(textOf(oaepParams), 'OAEPparams')) : new Uint8Array(0);
  if (label.byteLength !== 0) unsupported('non-empty OAEP parameters are not supported');

  const wrappedKey = base64Bytes(
    textOf(firstByLocalName(firstByLocalName(encryptedKey, XENC_NS, 'CipherData'), XENC_NS, 'CipherValue')),
    'EncryptedKey CipherValue',
  );

  // The recipient certificate, when the EncryptedKey names one (internal only).
  let recipientCertificate: string | undefined;
  const keyInfo = firstByLocalName(encryptedKey, DS_NS, 'KeyInfo');
  const keyTokenRef = firstByLocalName(keyInfo, WSSE_NS, 'SecurityTokenReference');
  if (keyTokenRef) {
    const token = resolveInternal(
      doc,
      attrOf(firstByLocalName(keyTokenRef, WSSE_NS, 'Reference'), 'URI'),
      'EncryptionKeyInfo',
    );
    recipientCertificate = binarySecurityTokenPem(token);
  }

  return {
    dataAlgorithm: dataMethod,
    mediaType,
    dataType,
    ciphertextTransform: SWA_TRANSFORM_CIPHERTEXT,
    attachmentHref,
    wrappedKey,
    oaep: { digest, mgf, label },
    ...(recipientCertificate ? { recipientCertificate } : {}),
  };
}
