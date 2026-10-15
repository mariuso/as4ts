import { constants, createHash, verify as cryptoVerify } from 'node:crypto';
import { C14nCanonicalization } from 'xml-crypto';
import type { NamespacePrefix } from 'xml-crypto';
import { DS_NS } from '../constants.js';
import { normalizePem, parseCertificate } from '../util.js';
import { CanonicalizationLimitExceeded } from '../xml/c14n.js';
import { xmlHooks } from '../xml/hooks.js';
import { attrOf, firstByLocalName, textOf } from '../xml/nodes.js';
import { ALGO_ENVELOPED_SIGNATURE, ALGO_INCLUSIVE_C14N, ALGO_RSA_SHA256, ALGO_SHA256, SMP_NS } from './constants.js';
import { defaultLookupLimits, type LookupLimits } from './limits.js';

/** The XML namespace, whose attributes xml-crypto copies from ancestors to the apex. */
const XML_NAMESPACE = 'http://www.w3.org/XML/1998/namespace';

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
  xmlHooks.onCanonicalize?.();
  return canonicalizer.process(node, { ancestorNamespaces });
}

/**
 * Mirrors xml-crypto's `findAncestorNsForElement`: the namespaces in scope above
 * `node`, nearest declaration winning, excluding undeclarations and anything the
 * node declares (or binds) itself.
 */
export function findAncestorNsForElement(node: Element): NamespacePrefix[] {
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

/** UTF-8 byte length, without allocating. */
function utf8(value: string): number {
  return Buffer.byteLength(value, 'utf8');
}

/** Characters inclusive C14N escapes in text, CDATA and attribute values. */
function countEscaped(value: string): number {
  let count = 0;
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (
      code === 0x26 ||
      code === 0x3c ||
      code === 0x3e ||
      code === 0x22 ||
      code === 0x09 ||
      code === 0x0a ||
      code === 0x0d
    ) {
      count += 1;
    }
  }
  return count;
}

/** Worst-case byte cost of a value once C14N escapes it (six bytes per special char). */
function escapedBytes(value: string): number {
  return utf8(value) + 5 * countEscaped(value);
}

/** Byte cost of a namespace declaration `xmlns[:prefix]="uri"` (leading space included). */
function declarationCost(prefix: string, uri: string): number {
  const name = prefix === '' ? 'xmlns' : `xmlns:${prefix}`;
  return 1 + utf8(name) + 2 + escapedBytes(uri) + 1;
}

/**
 * A conservative upper bound on the UTF-8 size of a node's **inclusive** C14N
 * form (the SMP canonicaliser, `C14nCanonicalization`). Inclusive C14N may render
 * every in-scope namespace declaration on an element, so — unlike the exclusive
 * bound in `xml/c14n.ts` — this charges the whole in-scope set per element. It
 * also charges element/attribute markup (UTF-8), escaped text/CDATA, processing
 * instructions, the ancestor `xml:lang` / `xml:space` xml-crypto copies onto the
 * apex, and (for a document node) the newline between top-level children.
 * Comments are dropped by this canonicaliser, so they cost nothing. The walk is
 * O(nodes + characters) with no input-proportional allocation.
 *
 * `skip` lets the caller exclude a direct child (the document digest covers the
 * root without its envelope signature) before it is cloned.
 */
export function inclusiveCanonicalSizeUpperBound(
  node: Node,
  ancestorNamespaces: readonly NamespacePrefix[] = [],
  skip?: (child: Node) => boolean,
): number {
  let total = 0;

  const visitNode = (child: Node): void => {
    switch (child.nodeType) {
      case 1:
        visitElement(child as Element, false);
        return;
      case 3: // text
      case 4: // CDATA — written as escaped character data
        total += 5 * utf8(child.nodeValue ?? '');
        return;
      case 7: // processing instruction
        total += 4 + utf8(child.nodeName ?? '') + 1 + utf8(child.nodeValue ?? '');
        return;
      case 8: // comment: dropped by this canonicaliser
        return;
      default:
        return;
    }
  };

  const visitElement = (element: Element, checkSkip: boolean): void => {
    const name = element.nodeName;
    total += 1 + utf8(name) + 1; // '<name'
    for (let i = 0; i < element.attributes.length; i += 1) {
      const attribute = element.attributes.item(i);
      if (!attribute) continue;
      const attributeName = attribute.nodeName;
      if (attributeName === 'xmlns' || attributeName.startsWith('xmlns:')) {
        // Every declaration xml-crypto renders is either a literal declaration in
        // this subtree (charged here, once per declaration) or part of the top
        // element's ancestor set (charged on the apex below). A descendant's
        // element or attribute prefix is always declared literally somewhere in
        // the subtree by the time it is used — an undeclared prefix is a parse
        // error — so only the apex can rely on a declaration above the subtree.
        const prefix = attributeName === 'xmlns' ? '' : attributeName.slice('xmlns:'.length);
        total += declarationCost(prefix, attribute.value ?? '');
      } else {
        total += 1 + utf8(attributeName) + 2 + escapedBytes(attribute.value ?? '') + 1;
      }
    }
    total += 1; // '>'
    const children = element.childNodes;
    for (let i = 0; i < children.length; i += 1) {
      const child = children.item(i);
      // `skip` removes only the *direct* children of the bound's starting node
      // (the envelope signature the digest excludes), never a nested element.
      if (child && !(checkSkip && skip && skip(child))) visitNode(child);
    }
    total += 2 + utf8(name) + 1; // '</name>'
  };

  if (node.nodeType === 1) {
    const element = node as Element;
    const charged = new Set<string>();
    let inheritedDefault: string | null = null;
    for (const namespace of ancestorNamespaces) {
      if (charged.has(namespace.prefix)) continue;
      charged.add(namespace.prefix);
      total += declarationCost(namespace.prefix, namespace.namespaceURI);
      if (namespace.prefix === '' && namespace.namespaceURI !== '') {
        inheritedDefault = namespace.namespaceURI;
      }
    }
    // Declarations `findAncestorNsForElement` drops — notably the default
    // namespace, which it excludes when the apex has no prefix.
    let ancestor: Node | null = element.parentNode;
    while (ancestor && ancestor.nodeType === 1) {
      const parent = ancestor as Element;
      for (let i = 0; i < parent.attributes.length; i += 1) {
        const attribute = parent.attributes.item(i);
        if (!attribute) continue;
        const attributeName = attribute.nodeName;
        if (attributeName !== 'xmlns' && !attributeName.startsWith('xmlns:')) continue;
        const prefix = attributeName === 'xmlns' ? '' : attributeName.slice('xmlns:'.length);
        if (charged.has(prefix)) continue;
        charged.add(prefix);
        const value = attribute.value ?? '';
        total += declarationCost(prefix, value);
        if (prefix === '' && value !== '') inheritedDefault = value;
      }
      ancestor = parent.parentNode;
    }
    // xml-crypto renders an inherited default namespace twice on the apex: once
    // from its `nodeDefaultNs !== defaultNs` branch and once from the ancestor
    // loop, which treats only a *literal* apex declaration as shadowing.
    if (inheritedDefault !== null) total += declarationCost('', inheritedDefault);
    // xml-crypto copies every ancestor attribute in the XML namespace
    // (`xml:lang`, `xml:space`, `xml:base`, `xml:id`, ...) onto the apex.
    // Charge every occurrence; over-counting is sound.
    ancestor = element.parentNode;
    while (ancestor && ancestor.nodeType === 1) {
      const parent = ancestor as Element;
      for (let i = 0; i < parent.attributes.length; i += 1) {
        const attribute = parent.attributes.item(i);
        if (!attribute) continue;
        if (attribute.namespaceURI === XML_NAMESPACE || attribute.prefix === 'xml') {
          total += 1 + utf8(attribute.nodeName) + 2 + escapedBytes(attribute.value ?? '') + 1;
        }
      }
      ancestor = parent.parentNode;
    }
    visitElement(element, true);
  } else {
    const children = node.childNodes;
    for (let i = 0; i < children.length; i += 1) {
      const child = children.item(i);
      if (child) {
        total += 1; // document-level newline
        visitNode(child);
      }
    }
  }
  return total;
}

/**
 * Inclusive C14N of a node only when its conservative expansion bound fits the
 * budget. The bound is checked before the canonicaliser runs, so an
 * expansion-amplifying SMP response never allocates the canonical string.
 */
export function inclusiveCanonicalizeWithin(node: Node, maxBytes: number): string {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
    throw new RangeError('canonicalisation budget must be a non-negative safe integer');
  }
  const ancestorNamespaces = node.nodeType === 1 ? findAncestorNsForElement(node as Element) : [];
  const bound = inclusiveCanonicalSizeUpperBound(node, ancestorNamespaces);
  if (bound > maxBytes) throw new CanonicalizationLimitExceeded(bound, maxBytes);
  xmlHooks.onCanonicalize?.();
  return canonicalizer.process(node, { ancestorNamespaces });
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
export function verifySmpSignature(
  document: Document,
  limits: LookupLimits = defaultLookupLimits,
): SmpSignatureVerification {
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

  // Bound the canonicalisation before cloning or canonicalising. The document
  // digest covers the root without its envelope ds:Signature; SignedInfo is
  // canonicalised separately. Their sum must fit the total budget, so an
  // expansion-amplifying response never allocates the clone or the strings.
  const isSignature = (child: Node): boolean =>
    child.nodeType === 1 && (child as Element).namespaceURI === DS_NS && (child as Element).localName === 'Signature';
  const digestBound = inclusiveCanonicalSizeUpperBound(root, [], isSignature);
  const signedInfoBound = inclusiveCanonicalSizeUpperBound(signedInfo, findAncestorNsForElement(signedInfo));
  if (digestBound + signedInfoBound > limits.maxCanonicalBytes) {
    return fail('the SMP response exceeds the canonicalisation budget');
  }

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
