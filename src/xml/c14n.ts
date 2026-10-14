import { createHash } from 'node:crypto';
import { ExclusiveCanonicalization } from 'xml-crypto';
import { XMLNS_NS } from '../constants.js';
import { xmlHooks } from './hooks.js';

const canonicalizer = new ExclusiveCanonicalization();

// xml-crypto sorts namespace declarations with String.prototype.localeCompare,
// which is case-insensitive and therefore diverges from the Canonical XML
// requirement (sort by prefix in codepoint order, e.g. "S12" before "ds").
// Without this, exclusive C14N of a SignedInfo that carries an uppercase prefix
// in its InclusiveNamespaces PrefixList (as Apache WSS4J/phase4 emits) does not
// match the signed bytes. Use a spec-compliant comparator.
(canonicalizer as unknown as { nsCompare: (a: { prefix?: string }, b: { prefix?: string }) => number }).nsCompare = (
  a,
  b,
) => {
  const pa = a.prefix ?? '';
  const pb = b.prefix ?? '';
  return pa === pb ? 0 : pa < pb ? -1 : 1;
};

/**
 * Exclusive XML canonicalisation, as mandated by [CEFEAS4] §3.2.6 (the
 * CanonicalizationMethod and every non-attachment Transform).
 *
 * We deliberately use only the low-level canonicaliser from xml-crypto and
 * implement reference resolution, digest comparison and key handling ourselves.
 * xml-crypto's high-level SignedXml verification has a history of
 * signature-bypass advisories (see README "Dependencies"); none of that code is
 * on this path.
 *
 * When `inclusivePrefixes` is given, `InclusiveNamespaces/PrefixList` semantics
 * are applied to the apex element, which is what a WS-Security receiver expects
 * for the `env` prefix.
 */
export function canonicalize(node: Element | Document, inclusivePrefixes?: readonly string[]): string {
  const opts =
    inclusivePrefixes && inclusivePrefixes.length > 0 ? { inclusiveNamespacesPrefixList: [...inclusivePrefixes] } : {};
  xmlHooks.onCanonicalize?.();
  return canonicalizer.process(node, opts);
}

/** A conservative upper bound on the canonical size was exceeded. */
export class CanonicalizationLimitExceeded extends Error {
  constructor(
    readonly bound: number,
    readonly maxBytes: number,
  ) {
    super(`canonicalization expansion (at most ${bound} bytes) exceeds the budget of ${maxBytes} bytes`);
    this.name = 'CanonicalizationLimitExceeded';
  }
}

/**
 * A conservative upper bound on the UTF-8 size of a node's exclusive-C14N form.
 *
 * This is deliberately an upper bound, not the exact output size: it sums every
 * element's markup and closing tag, its attributes with worst-case escaping
 * (six bytes per input character), every in-scope namespace declaration that
 * exclusive C14N might repeat on an element (a long URI declared once can be
 * rendered on every descendant that uses it), and CDATA/comments/PIs. It walks
 * the already-constructed DOM, so it bounds the *canonical string* allocation,
 * which is the allocation this check guards. The DOM itself is bounded earlier
 * by the byte/depth/node preflight.
 */
export function canonicalSizeUpperBound(root: Element | Document): number {
  let total = 0;
  const namespaceStack: number[] = [];
  let namespaceSum = 0;

  const visitNode = (node: Node): void => {
    switch (node.nodeType) {
      case 1:
        visitElement(node as Element);
        return;
      case 3: // text
        total += 6 * (node.nodeValue?.length ?? 0);
        return;
      case 4: // CDATA — rendered as escaped character data
        total += 6 * (node.nodeValue?.length ?? 0) + 4;
        return;
      case 8: // comment
        total += 7 + 6 * (node.nodeValue?.length ?? 0);
        return;
      case 7: // processing instruction
        total += 3 + (node.nodeName?.length ?? 0) + 6 * (node.nodeValue?.length ?? 0) + 2;
        return;
      default:
        return;
    }
  };

  const visitElement = (element: Element): void => {
    const name = element.nodeName;
    total += 2 + name.length; // '<' + name
    let declared = 0;
    const attributes = element.attributes;
    if (attributes) {
      for (let i = 0; i < attributes.length; i += 1) {
        const attribute = attributes.item(i);
        if (!attribute) continue;
        const attributeName = attribute.nodeName;
        const valueCost = 6 * (attribute.value?.length ?? 0);
        if (attributeName === 'xmlns' || attributeName.startsWith('xmlns:')) {
          const cost = 1 + attributeName.length + 3 + valueCost;
          namespaceStack.push(cost);
          namespaceSum += cost;
          declared += 1;
        } else {
          total += 1 + attributeName.length + 3 + valueCost;
        }
      }
    }
    total += namespaceSum; // every in-scope namespace may be rendered here
    total += 1; // '>'
    const children = element.childNodes;
    if (children) {
      for (let i = 0; i < children.length; i += 1) {
        const child = children.item(i);
        if (child) visitNode(child);
      }
    }
    total += 3 + name.length; // '</' + name + '>'
    for (let i = 0; i < declared; i += 1) namespaceSum -= namespaceStack.pop()!;
  };

  if (root.nodeType === 1) {
    visitElement(root as Element);
  } else {
    const children = (root as Node).childNodes;
    if (children) {
      for (let i = 0; i < children.length; i += 1) {
        const child = children.item(i);
        if (child) visitNode(child);
      }
    }
  }
  return total;
}

function assertCanonicalBudget(maxBytes: number): void {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
    throw new RangeError('canonicalization budget must be a non-negative safe integer');
  }
}

/**
 * Canonicalise a node only when its conservative expansion bound fits the
 * budget. The bound is checked *before* the canonicaliser runs, so an
 * expansion-amplifying document never allocates the canonical string.
 */
export function canonicalizeWithin(
  node: Element | Document,
  maxBytes: number,
  inclusivePrefixes?: readonly string[],
): string {
  assertCanonicalBudget(maxBytes);
  const bound = canonicalSizeUpperBound(node);
  if (bound > maxBytes) throw new CanonicalizationLimitExceeded(bound, maxBytes);
  return canonicalize(node, inclusivePrefixes);
}

/** Base64 SHA-256 of a node's canonical form, bounded, hashing the string directly. */
export function canonicalizeDigestWithin(
  node: Element | Document,
  maxBytes: number,
  inclusivePrefixes?: readonly string[],
): string {
  const canonical = canonicalizeWithin(node, maxBytes, inclusivePrefixes);
  return createHash('sha256').update(canonical, 'utf8').digest('base64');
}

/** Base64 SHA-256 digest of the canonical form of a node. */
export function canonicalizeDigest(node: Element | Document): string {
  return createHash('sha256').update(canonicalize(node), 'utf8').digest('base64');
}

/** Base64 SHA-256 digest of raw bytes. */
export function sha256Digest(data: Buffer | Uint8Array): string {
  return createHash('sha256').update(data).digest('base64');
}

/**
 * Make inclusive-namespace prefixes explicit on the canonicalisation apex.
 *
 * Exclusive C14N with `InclusiveNamespaces/PrefixList` must emit the listed
 * prefixes' declarations on the apex element. Apache Santuario (used by many
 * receivers) synthesizes them from the ancestors even when they are not written
 * on the element; xml-crypto only renders declarations that are literally
 * present. Before verifying a received signature we therefore copy any missing
 * listed prefix from its ancestor onto the element, so both implementations
 * canonicalise identically.
 */
export function materializeInclusiveNamespaces(element: Element, prefixes: readonly string[]): void {
  for (const prefix of prefixes) {
    if (!prefix || prefix === '#default') continue;
    if (element.getAttribute(`xmlns:${prefix}`)) continue;
    const uri = findAncestorNamespaceUri(element, prefix);
    if (uri) element.setAttributeNS(XMLNS_NS, `xmlns:${prefix}`, uri);
  }
}

function findAncestorNamespaceUri(element: Element, prefix: string): string | null {
  let node: Node | null = element.parentNode;
  while (node && node.nodeType === 1) {
    const el = node as Element;
    const declared = el.getAttribute(`xmlns:${prefix}`);
    if (declared) return declared;
    if (el.prefix === prefix) return el.namespaceURI;
    node = el.parentNode;
  }
  return null;
}
