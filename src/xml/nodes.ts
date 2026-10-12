import { DOMParser, XMLSerializer } from '@xmldom/xmldom';
import {
  SOAP_ENV_NS,
  EBMS_NS,
  WSU_NS,
  WSSE_NS,
  WSSE11_NS,
  DS_NS,
  XENC_NS,
  XENC11_NS,
  ALGO_EXC_C14N,
  XMLNS_NS,
} from '../constants.js';

/** Prefix -> namespace for the document we build. */
export const NS = {
  env: SOAP_ENV_NS,
  eb: EBMS_NS,
  wsu: WSU_NS,
  wsse: WSSE_NS,
  wsse11: WSSE11_NS,
  ds: DS_NS,
  xenc: XENC_NS,
  xenc11: XENC11_NS,
  ec: ALGO_EXC_C14N,
  ebbp: 'http://docs.oasis-open.org/ebxml-bp/ebbp-signals-2.0',
} as const;

export type Prefix = keyof typeof NS;

export function parseXml(source: string | Buffer): Document {
  const parser = new DOMParser();
  return parser.parseFromString(typeof source === 'string' ? source : source.toString('utf8'), 'application/xml');
}

export function serializeXml(node: Node): string {
  return new XMLSerializer().serializeToString(node);
}

/**
 * Create an element with a fixed prefix. Attributes whose name contains a colon
 * are resolved to their namespace through {@link NS} so that canonicalisation
 * sees real namespaced attributes (wsu:Id and friends), not prefixed strings.
 */
export function element(
  doc: Document,
  nsPrefix: Prefix,
  name: string,
  attributes: Record<string, string> = {},
  text?: string,
): Element {
  const node = doc.createElementNS(NS[nsPrefix], `${nsPrefix}:${name}`);
  for (const [attrName, value] of Object.entries(attributes)) setAttr(node, attrName, value);
  if (text !== undefined) node.appendChild(doc.createTextNode(text));
  return node;
}

export function setAttr(node: Element, name: string, value: string): void {
  if (name.startsWith('xmlns:')) {
    node.setAttributeNS(XMLNS_NS, name, value);
    return;
  }
  const colon = name.indexOf(':');
  if (colon > 0) {
    const prefix = name.slice(0, colon) as Prefix;
    const ns = NS[prefix];
    if (ns) {
      node.setAttributeNS(ns, name, value);
      return;
    }
  }
  node.setAttribute(name, value);
}

/** Declare namespace prefixes directly on an element. */
export function declareNs(node: Element, prefixes: readonly Prefix[]): void {
  for (const p of prefixes) node.setAttributeNS(XMLNS_NS, `xmlns:${p}`, NS[p]);
}

export function append(parent: Node, ...children: Node[]): void {
  for (const child of children) parent.appendChild(child);
}

export function elementsByLocalName(node: Node | null, ns: string, localName: string): Element[] {
  if (!node) return [];
  const out: Element[] = [];
  const all = (node as Document | Element).getElementsByTagNameNS(ns, localName);
  for (let i = 0; i < all.length; i += 1) {
    const item = all.item(i);
    if (item) out.push(item);
  }
  return out;
}

export function firstByLocalName(node: Node | null, ns: string, localName: string): Element | null {
  return elementsByLocalName(node, ns, localName)[0] ?? null;
}

export function textOf(node: Element | null): string | null {
  if (!node) return null;
  const value = node.textContent;
  return value === null || value === undefined ? null : value;
}

export function attrOf(node: Element | null, name: string, ns?: string): string | null {
  if (!node) return null;
  const value = ns ? node.getAttributeNS(ns, name) : node.getAttribute(name);
  return value === null || value === '' ? null : value;
}
