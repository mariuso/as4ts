import { createHash } from 'node:crypto';
import { ExclusiveCanonicalization } from 'xml-crypto';
import { XMLNS_NS } from '../constants.js';

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
  return canonicalizer.process(node, opts);
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
