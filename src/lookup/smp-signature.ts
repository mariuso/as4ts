import { constants, createHash, verify as cryptoVerify } from 'node:crypto';
import { C14nCanonicalization } from 'xml-crypto';
import type { NamespacePrefix } from 'xml-crypto';
import { DS_NS } from '../constants.js';
import { normalizePem, parseCertificate } from '../util.js';
import { attrOf, firstByLocalName, textOf } from '../xml/nodes.js';
import { ALGO_ENVELOPED_SIGNATURE, ALGO_INCLUSIVE_C14N, ALGO_RSA_SHA256, ALGO_SHA256, SMP_NS } from './constants.js';

/**
 * Inclusive C14N 1.0, which the SMP specification mandates (SMP v1.4.0 §5.5.1,
 * `http://www.w3.org/TR/2001/REC-xml-c14n-20010315`). This differs from the
 * AS4 messages, whose signatures use exclusive C14N; the AS4 canonicaliser is
 * deliberately not bent to fit.
 *
 * As in `xml/c14n.ts`, replace xml-crypto's locale-aware namespace comparator
 * with the codepoint one Canonical XML requires.
 */
const canonicalizer = new C14nCanonicalization();
(canonicalizer as unknown as { nsCompare: (a: { prefix?: string }, b: { prefix?: string }) => number }).nsCompare = (
  a,
  b,
) => {
  const pa = a.prefix ?? '';
  const pb = b.prefix ?? '';
  return pa === pb ? 0 : pa < pb ? -1 : 1;
};

/**
 * Inclusive C14N of a node, carrying the namespace declarations it inherits from
 * its ancestors onto the apex. Inclusive C14N requires them (Canonical XML §1);
 * without them a `ds:SignedInfo` nested under a response root that declares
 * namespaces canonicalises differently, and real SMP responses fail to verify.
 * Exported for the fixture signer, which must canonicalise the same way.
 */
export function inclusiveCanonicalize(node: Node): string {
  const ancestorNamespaces = node.nodeType === 1 ? findAncestorNsForElement(node as Element) : [];
  return canonicalizer.process(node, { ancestorNamespaces });
}

/**
 * Mirrors xml-crypto's `findAncestorNsForElement`: the namespaces in scope above
 * `node`, nearest declaration winning, excluding undeclarations and anything the
 * node declares (or binds) itself.
 */
function findAncestorNsForElement(node: Element): NamespacePrefix[] {
  const collected: NamespacePrefix[] = [];
  let ancestor: Node | null = node.parentNode;
  while (ancestor && ancestor.nodeType === 1) {
    const element = ancestor as Element;
    for (let i = 0; i < element.attributes.length; i += 1) {
      const attr = element.attributes.item(i);
      if (attr && (attr.nodeName === 'xmlns' || attr.nodeName.startsWith('xmlns:'))) {
        collected.push({ prefix: attr.nodeName.replace(/^xmlns:?/, ''), namespaceURI: attr.nodeValue ?? '' });
      }
    }
    ancestor = element.parentNode;
  }
  const nearest: NamespacePrefix[] = [];
  for (const namespace of collected) {
    if (!nearest.some((seen) => seen.prefix === namespace.prefix)) nearest.push(namespace);
  }
  const own = new Set<string>();
  for (let i = 0; i < node.attributes.length; i += 1) {
    const name = node.attributes.item(i)?.nodeName ?? '';
    if (name === 'xmlns' || name.startsWith('xmlns:')) own.add(name.replace(/^xmlns:?/, ''));
  }
  own.add(node.prefix ?? '');
  return nearest.filter((namespace) => namespace.namespaceURI !== '' && !own.has(namespace.prefix));
}

export type SmpSignatureVerification =
  | {
      readonly ok: true;
      readonly signerCertificatePem: string;
      /** The document with the signature removed: exactly the nodes the digest covered. */
      readonly verifiedDocument: Document;
    }
  | { readonly ok: false; readonly reason: string };

/**
 * Verify the enveloped XML signature on a Peppol SMP `SignedServiceMetadata`
 * response, per SMP v1.4.0 §5.5.1:
 *
 *  - exactly one `ds:Signature`, a **direct child of the root**;
 *  - exactly one `ds:Reference` with an **empty URI** (the signature covers the
 *    whole document) and exactly the `enveloped-signature` transform;
 *  - inclusive C14N, RSA-SHA256 and SHA-256 only; anything else is rejected;
 *  - the signer certificate in `ds:KeyInfo/ds:X509Data/ds:X509Certificate`.
 *
 * It returns the document **with the signature removed**: precisely the nodes
 * the digest covered. Callers must read facts (the endpoint, the redirect) only
 * from that document, never from the original, or a forged `ServiceInformation`
 * hidden inside the signature element — which the digest does not cover — would
 * be trusted.
 *
 * The certificate is only extracted here; the caller validates it. Nothing is
 * thrown.
 */
export function verifySmpSignature(document: Document): SmpSignatureVerification {
  const root = document.documentElement;
  if (!root) return fail('the response has no document element');
  if (root.namespaceURI !== SMP_NS || root.localName !== 'SignedServiceMetadata') {
    return fail('the response root is not smp:SignedServiceMetadata');
  }

  const signatures = directChildren(root, DS_NS, 'Signature');
  if (signatures.length !== 1) {
    return fail('the response must have exactly one ds:Signature, a direct child of the root');
  }
  const signature = signatures[0]!;

  const signerPem = extractSignerCertificate(signature);
  if (!signerPem) return fail('no ds:X509Certificate in ds:KeyInfo');

  const signedInfo = firstByLocalName(signature, DS_NS, 'SignedInfo');
  if (!signedInfo) return fail('no ds:SignedInfo');

  const c14nMethod = firstByLocalName(signedInfo, DS_NS, 'CanonicalizationMethod');
  if (attrOf(c14nMethod, 'Algorithm') !== ALGO_INCLUSIVE_C14N) {
    return fail('SMP signatures must use inclusive C14N (SMP v1.4.0 §5.5.1)');
  }
  const signatureMethod = firstByLocalName(signedInfo, DS_NS, 'SignatureMethod');
  if (attrOf(signatureMethod, 'Algorithm') !== ALGO_RSA_SHA256) {
    return fail('SMP signatures must use rsa-sha256 (SMP v1.4.0 §5.5.1)');
  }

  const references = Array.from(signedInfo.getElementsByTagNameNS(DS_NS, 'Reference'));
  if (references.length !== 1) return fail('the SMP signature must have exactly one ds:Reference');
  const reference = references[0]!;
  if ((attrOf(reference, 'URI') ?? '') !== '') {
    return fail('the SMP signature reference must have an empty URI (it covers the whole document)');
  }
  const transforms = Array.from(reference.getElementsByTagNameNS(DS_NS, 'Transform'));
  if (transforms.length !== 1 || attrOf(transforms[0] ?? null, 'Algorithm') !== ALGO_ENVELOPED_SIGNATURE) {
    return fail('the SMP reference must use exactly the enveloped-signature transform');
  }
  const digestMethod = firstByLocalName(reference, DS_NS, 'DigestMethod');
  if (attrOf(digestMethod, 'Algorithm') !== ALGO_SHA256) {
    return fail('SMP references must use SHA-256 (SMP v1.4.0 §5.5.1)');
  }
  const expected = textOf(firstByLocalName(reference, DS_NS, 'DigestValue'))?.trim();
  if (!expected) return fail('missing ds:DigestValue');

  // The node-set the reference covers: the whole document with the signature
  // removed. Everything downstream reads from this document only.
  const verifiedDocument = document.cloneNode(true) as Document;
  const verifiedRoot = verifiedDocument.documentElement;
  if (!verifiedRoot) return fail('the response has no document element');
  for (const cloned of directChildren(verifiedRoot, DS_NS, 'Signature')) {
    cloned.parentNode?.removeChild(cloned);
  }
  const actual = createHash('sha256').update(inclusiveCanonicalize(verifiedRoot), 'utf8').digest('base64');
  if (actual !== expected) return fail('digest mismatch for the SMP document');

  const signatureValue = textOf(firstByLocalName(signature, DS_NS, 'SignatureValue'))?.trim();
  if (!signatureValue) return fail('no ds:SignatureValue');

  let signer;
  try {
    signer = parseCertificate(signerPem);
  } catch {
    return fail('the ds:X509Certificate is not readable');
  }
  let verified = false;
  try {
    verified = cryptoVerify(
      'sha256',
      Buffer.from(inclusiveCanonicalize(signedInfo), 'utf8'),
      { key: signer.publicKey, padding: constants.RSA_PKCS1_PADDING },
      Buffer.from(signatureValue, 'base64'),
    );
  } catch {
    verified = false;
  }
  if (!verified) return fail('ds:SignatureValue does not verify over ds:SignedInfo');

  return { ok: true, signerCertificatePem: signerPem, verifiedDocument };
}

function fail(reason: string): SmpSignatureVerification {
  return { ok: false, reason };
}

function directChildren(element: Element, namespace: string, localName: string): Element[] {
  const children: Element[] = [];
  for (let i = 0; i < element.childNodes.length; i += 1) {
    const child = element.childNodes.item(i);
    if (child && child.nodeType === 1) {
      const childElement = child as Element;
      if (childElement.namespaceURI === namespace && childElement.localName === localName) {
        children.push(childElement);
      }
    }
  }
  return children;
}

function extractSignerCertificate(signature: Element): string | null {
  const keyInfo = firstByLocalName(signature, DS_NS, 'KeyInfo');
  if (!keyInfo) return null;
  const x509Data = firstByLocalName(keyInfo, DS_NS, 'X509Data');
  const certificate = firstByLocalName(x509Data, DS_NS, 'X509Certificate');
  const base64 = certificate ? textOf(certificate)?.replace(/\s+/g, '') : null;
  return base64 ? normalizePem(`-----BEGIN CERTIFICATE-----\n${base64}\n-----END CERTIFICATE-----`) : null;
}
