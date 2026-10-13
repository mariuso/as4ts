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
import { attrOf, elementsByLocalName, textOf } from '../xml/nodes.js';
import { resolveIdUnique } from '../xml/ws-security.js';
import type { InboundEncryption, InboundFailureReason } from './types.js';

/**
 * Structural validation of the inbound encryption graph (Phase 2). This module
 * performs no private-key operation: it resolves and checks the shape of
 * `xenc:EncryptedData`, `xenc:EncryptedKey` and their references so that a
 * credential is only ever invoked against an unambiguous, supported descriptor.
 *
 * It establishes cardinality from direct children (never "the first match"),
 * resolves attachment keys through the EncryptedKey's `ReferenceList`
 * (SwA §5.5), and only cross-checks the `ds:KeyInfo` reverse link when a peer
 * supplies one. It rejects ambiguous ids, external references (this never fetches
 * a URI), an unsupported data/key encapsulation algorithm, a ciphertext transform
 * other than attachment-ciphertext, and a non-empty OAEP label, and it decodes
 * base64 strictly. An omitted RSA-OAEP digest/MGF is rejected rather than assumed
 * to be SHA-256. [XMLENC11] §5.5.2, [WSSSWA] §5.5
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

function directChildrenOf(node: Element | null, ns: string, localName: string): Element[] {
  const out: Element[] = [];
  const children = node?.childNodes;
  if (!children) return out;
  for (let i = 0; i < children.length; i += 1) {
    const child = children.item(i);
    if (!child || child.nodeType !== 1) continue;
    const element = child as Element;
    if (element.namespaceURI === ns && element.localName === localName) out.push(element);
  }
  return out;
}

/** Exactly one named direct child. */
function onlyChild(node: Element | null, ns: string, localName: string, what: string): Element {
  const matches = directChildrenOf(node, ns, localName);
  if (matches.length === 0) invalid(`missing ${what}`);
  if (matches.length > 1) invalid(`more than one ${what}`);
  return matches[0]!;
}

/** At most one named direct child. */
function optionalChild(node: Element | null, ns: string, localName: string, what: string): Element | null {
  const matches = directChildrenOf(node, ns, localName);
  if (matches.length > 1) invalid(`more than one ${what}`);
  return matches[0] ?? null;
}

/** The single top-level element of a namespace/local name, or a fault. */
function singleElement(doc: Document, ns: string, localName: string, what: string): Element {
  const matches = elementsByLocalName(doc, ns, localName);
  if (matches.length === 0) invalid(`no ${what} found`);
  if (matches.length > 1) invalid(`more than one ${what} found`);
  return matches[0]!;
}

/** Resolve an internal `#id` reference to exactly one element; no external fetches. */
function resolveInternal(doc: Document, uri: string | null, what: string): Element {
  if (!uri || !uri.startsWith('#')) invalid(`${what} reference is missing or external`);
  const resolved = resolveIdUnique(doc, uri.slice(1));
  if (resolved.matches > 1) invalid(`duplicate id for ${what}`);
  if (!resolved.element) invalid(`unresolved ${what} reference`);
  return resolved.element;
}

/** Strict base64: charset and padding must be canonical, not merely tolerated. */
function base64Bytes(value: string | null, what: string): Uint8Array {
  if (value === null) invalid(`missing ${what}`);
  const cleaned = value.replace(/\s+/g, '');
  if (cleaned === '') invalid(`empty ${what}`);
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(cleaned) || cleaned.length % 4 !== 0) invalid(`malformed base64 in ${what}`);
  const bytes = Buffer.from(cleaned, 'base64');
  if (bytes.byteLength === 0) invalid(`undecodable ${what}`);
  if (bytes.toString('base64').replace(/=+$/, '') !== cleaned.replace(/=+$/, '')) {
    invalid(`non-canonical base64 in ${what}`);
  }
  return bytes;
}

function binarySecurityTokenPem(token: Element): string {
  const b64 = textOf(token)?.replace(/\s+/g, '');
  if (!b64) invalid('encryption token is empty');
  return normalizePem(`-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----`);
}

export function parseInboundEncryption(doc: Document): InboundEncryption {
  const security = singleElement(doc, WSSE_NS, 'Security', 'wsse:Security header');
  const encryptedData = onlyChild(security, XENC_NS, 'EncryptedData', 'xenc:EncryptedData');
  const encryptedKey = onlyChild(security, XENC_NS, 'EncryptedKey', 'xenc:EncryptedKey');

  // SwA §5.5: the attachment key is resolved through the EncryptedKey's
  // ReferenceList. The EncryptedData's own ds:KeyInfo is prohibited when an
  // EncryptedKey is used, so it is neither required nor expected.
  const referenceList = onlyChild(encryptedKey, XENC_NS, 'ReferenceList', 'EncryptedKey ReferenceList');
  const dataReferences = directChildrenOf(referenceList, XENC_NS, 'DataReference');
  if (dataReferences.length !== 1) invalid('EncryptedKey must carry exactly one DataReference');
  if (resolveInternal(doc, attrOf(dataReferences[0]!, 'URI'), 'EncryptedKey DataReference') !== encryptedData) {
    invalid('EncryptedKey DataReference does not reference the EncryptedData');
  }
  // Compatibility variant: if a peer also emits the reverse link, it must agree.
  const dataKeyInfo = optionalChild(encryptedData, DS_NS, 'KeyInfo', 'EncryptedData KeyInfo');
  const dataKeyToken = optionalChild(dataKeyInfo, WSSE_NS, 'SecurityTokenReference', 'EncryptedData KeyInfo token');
  const dataKeyReference = optionalChild(dataKeyToken, WSSE_NS, 'Reference', 'EncryptedData KeyInfo reference');
  if (dataKeyReference) {
    if (resolveInternal(doc, attrOf(dataKeyReference, 'URI'), 'EncryptedData KeyInfo') !== encryptedKey) {
      invalid('EncryptedData KeyInfo does not reference the EncryptedKey');
    }
  }

  // Data algorithm and SwA shape.
  const dataMethod = onlyChild(encryptedData, XENC_NS, 'EncryptionMethod', 'data EncryptionMethod');
  const dataAlgorithm = attrOf(dataMethod, 'Algorithm');
  if (dataAlgorithm !== ALGO_AES128_GCM)
    unsupported(`unsupported data encryption algorithm ${dataAlgorithm ?? '(none)'}`);
  const dataType = attrOf(encryptedData, 'Type');
  if (dataType !== SWA_ATTACHMENT_CONTENT_ONLY) unsupported(`unsupported EncryptedData Type ${dataType ?? '(none)'}`);
  const mediaType = attrOf(encryptedData, 'MimeType');
  if (!mediaType) invalid('EncryptedData has no MimeType');
  if (!attrOf(encryptedData, 'Id')) invalid('EncryptedData has no Id');

  // CipherReference must be an internal `cid:` attachment with the ciphertext transform.
  const dataCipherData = onlyChild(encryptedData, XENC_NS, 'CipherData', 'EncryptedData CipherData');
  const cipherReference = onlyChild(dataCipherData, XENC_NS, 'CipherReference', 'EncryptedData CipherReference');
  const attachmentHref = attrOf(cipherReference, 'URI');
  if (!attachmentHref || !attachmentHref.startsWith('cid:'))
    invalid('CipherReference is not an internal cid: reference');
  // Peppol senders wrap the transform in `xenc:Transforms`; accept the
  // `ds:Transforms` spelling too, but only one container and one transform.
  const containers = [
    ...directChildrenOf(cipherReference, XENC_NS, 'Transforms'),
    ...directChildrenOf(cipherReference, DS_NS, 'Transforms'),
  ];
  if (containers.length !== 1) invalid('CipherReference must carry exactly one Transforms');
  const transforms = directChildrenOf(containers[0]!, DS_NS, 'Transform');
  if (transforms.length !== 1 || attrOf(transforms[0]!, 'Algorithm') !== SWA_TRANSFORM_CIPHERTEXT) {
    unsupported('CipherReference must use exactly the attachment-ciphertext transform');
  }

  // Key encapsulation: RSA-OAEP with declared SHA-256, MGF1-SHA-256, empty label.
  const keyMethod = onlyChild(encryptedKey, XENC_NS, 'EncryptionMethod', 'key EncryptionMethod');
  if (attrOf(keyMethod, 'Algorithm') !== ALGO_RSA_OAEP) {
    unsupported(`unsupported key encapsulation algorithm ${attrOf(keyMethod, 'Algorithm') ?? '(none)'}`);
  }
  const digest = attrOf(optionalChild(keyMethod, DS_NS, 'DigestMethod', 'key DigestMethod'), 'Algorithm');
  if (digest !== ALGO_SHA256) unsupported('RSA-OAEP must declare DigestMethod SHA-256');
  const mgf = attrOf(optionalChild(keyMethod, XENC11_NS, 'MGF', 'key MGF'), 'Algorithm');
  if (mgf !== ALGO_MGF1_SHA256) unsupported('RSA-OAEP must declare MGF1-SHA-256');
  // Absent and explicitly empty OAEPparams both mean the empty label.
  const oaepParams = optionalChild(keyMethod, XENC_NS, 'OAEPparams', 'OAEPparams');
  const label =
    oaepParams && (textOf(oaepParams) ?? '').trim() !== ''
      ? new Uint8Array(base64Bytes(textOf(oaepParams), 'OAEPparams'))
      : new Uint8Array(0);
  if (label.byteLength !== 0) unsupported('non-empty OAEP parameters are not supported');

  const keyCipherData = onlyChild(encryptedKey, XENC_NS, 'CipherData', 'EncryptedKey CipherData');
  const wrappedKey = base64Bytes(
    textOf(onlyChild(keyCipherData, XENC_NS, 'CipherValue', 'EncryptedKey CipherValue')),
    'EncryptedKey CipherValue',
  );

  // The recipient certificate, when the EncryptedKey names one (internal only).
  let recipientCertificate: string | undefined;
  const keyInfo = optionalChild(encryptedKey, DS_NS, 'KeyInfo', 'EncryptedKey KeyInfo');
  const keyToken = optionalChild(keyInfo, WSSE_NS, 'SecurityTokenReference', 'EncryptedKey KeyInfo token');
  const keyReference = optionalChild(keyToken, WSSE_NS, 'Reference', 'EncryptedKey KeyInfo reference');
  if (keyReference) {
    recipientCertificate = binarySecurityTokenPem(
      resolveInternal(doc, attrOf(keyReference, 'URI'), 'EncryptionKeyInfo'),
    );
  }

  return {
    dataAlgorithm,
    mediaType,
    dataType,
    ciphertextTransform: SWA_TRANSFORM_CIPHERTEXT,
    attachmentHref,
    wrappedKey,
    oaep: { digest, mgf, label },
    ...(recipientCertificate ? { recipientCertificate } : {}),
  };
}
