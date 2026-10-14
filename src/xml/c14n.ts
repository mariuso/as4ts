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

/** UTF-8 byte length, without allocating. */
function utf8(value: string): number {
  return Buffer.byteLength(value, 'utf8');
}

/** Characters exclusive C14N escapes in text, CDATA and attribute values. */
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

/** Worst-case byte cost of a value once exclusive C14N escapes it. */
function escapedBytes(value: string): number {
  return utf8(value) + 5 * countEscaped(value);
}

/** Byte cost of a namespace declaration `xmlns[:prefix]="uri"` (leading space included). */
function declarationCost(prefix: string, uri: string): number {
  const name = prefix === '' ? 'xmlns' : `xmlns:${prefix}`;
  return 1 + utf8(name) + 2 + escapedBytes(uri) + 1;
}

/**
 * The in-scope URI for a prefix at `element` (including `element` itself).
 * `#default` means the default namespace. Returns null when no declaration is in
 * scope or when it is unset (`xmlns=""`).
 */
function inScopeNamespace(element: Element, prefix: string): string | null {
  const wanted = prefix === '#default' ? null : prefix;
  let node: Node | null = element;
  while (node && node.nodeType === 1) {
    const current = node as Element;
    if (wanted === null) {
      const declared = current.getAttribute('xmlns');
      if (declared !== null) return declared === '' ? null : declared;
      if (!current.prefix && current.namespaceURI) return current.namespaceURI;
    } else {
      const declared = current.getAttribute(`xmlns:${wanted}`);
      if (declared !== null) return declared === '' ? null : declared;
      if (current.prefix === wanted && current.namespaceURI) return current.namespaceURI;
    }
    node = current.parentNode;
  }
  return null;
}

/**
 * A conservative upper bound on the UTF-8 size of a node's exclusive-C14N form,
 * built from the rules the canonicaliser actually applies:
 *
 *  - element and attribute names are measured in UTF-8 bytes, with their markup
 *    and closing tags;
 *  - text, CDATA and attribute values are charged worst-case escaping (five extra
 *    bytes per special character);
 *  - the namespaces an element *visibly uses* — its own namespace and each
 *    prefixed attribute's namespace, taken from `namespaceURI` the way xml-crypto
 *    does — so a declaration made on an ancestor outside the subtree is still
 *    charged once per element that uses it;
 *  - every `xmlns`/`xmlns:*` attribute literally present (including
 *    `materializeInclusiveNamespaces` redeclarations), charged once on the
 *    declaring element and not cascaded to descendants;
 *  - the inclusive prefixes on the apex, resolved through the ancestor chain;
 *  - comments (dropped by this canonicaliser, but charged harmlessly) and
 *    processing instructions.
 *
 * The walk is O(nodes + characters) with no allocation proportional to the input,
 * so it bounds the *canonical string* allocation — the allocation this check
 * guards. The DOM itself is bounded earlier by the SAX preflight.
 */
export function canonicalSizeUpperBound(root: Element | Document, inclusivePrefixes?: readonly string[]): number {
  let total = 0;

  const visitNode = (node: Node): void => {
    switch (node.nodeType) {
      case 1:
        visitElement(node as Element);
        return;
      case 3: // text
      case 4: // CDATA — written as escaped character data
        total += escapedBytes(node.nodeValue ?? '');
        return;
      case 8: // comment (dropped by C14N; charged conservatively)
        total += 7 + escapedBytes(node.nodeValue ?? '');
        return;
      case 7: // processing instruction
        total += 4 + utf8(node.nodeName ?? '') + 1 + utf8(node.nodeValue ?? '');
        return;
      default:
        return;
    }
  };

  const visitElement = (element: Element): void => {
    const name = element.nodeName;
    total += 1 + utf8(name) + 1; // '<name>'
    total += 2 + utf8(name) + 1; // '</name>'

    let defaultNamespace: string | null = null;
    const prefixes = new Map<string, string>();
    const ownPrefix = element.prefix ?? '';
    if (ownPrefix !== '') prefixes.set(ownPrefix, element.namespaceURI ?? '');
    else defaultNamespace = element.namespaceURI ?? '';

    const attributes = element.attributes;
    if (attributes) {
      for (let i = 0; i < attributes.length; i += 1) {
        const attribute = attributes.item(i);
        if (!attribute) continue;
        const attributeName = attribute.nodeName;
        if (attributeName === 'xmlns' || attributeName.startsWith('xmlns:')) {
          const prefix = attributeName === 'xmlns' ? '' : attributeName.slice('xmlns:'.length);
          total += declarationCost(prefix, attribute.value ?? '');
          continue;
        }
        total += 1 + utf8(attributeName) + 2 + escapedBytes(attribute.value ?? '') + 1;
        const attributePrefix = attribute.prefix ?? '';
        if (attributePrefix !== '' && !prefixes.has(attributePrefix)) {
          prefixes.set(attributePrefix, attribute.namespaceURI ?? '');
        }
      }
    }
    if (defaultNamespace !== null) total += declarationCost('', defaultNamespace);
    for (const [prefix, uri] of prefixes) total += declarationCost(prefix, uri);

    const children = element.childNodes;
    if (children) {
      for (let i = 0; i < children.length; i += 1) {
        const child = children.item(i);
        if (child) visitNode(child);
      }
    }
  };

  const apex = root.nodeType === 1 ? (root as Element) : (root as Document).documentElement;
  if (root.nodeType === 1) {
    visitElement(root as Element);
  } else {
    const children = (root as Node).childNodes;
    if (children) {
      for (let i = 0; i < children.length; i += 1) {
        const child = children.item(i);
        if (child) {
          total += 1; // document-level newline between top-level nodes
          visitNode(child);
        }
      }
    }
  }
  if (apex && inclusivePrefixes && inclusivePrefixes.length > 0) {
    for (const prefix of inclusivePrefixes) {
      const uri = inScopeNamespace(apex, prefix);
      if (uri !== null && uri !== '') total += declarationCost(prefix === '#default' ? '' : prefix, uri);
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
  const bound = canonicalSizeUpperBound(node, inclusivePrefixes);
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
