import { DOMParser } from '@xmldom/xmldom';
import type { InboundFailureReason } from './types.js';

/**
 * A strict, bounded XML parse for inbound bytes (Phase 1 spike).
 *
 * The shared `parseXml` used for building and for responses is deliberately
 * permissive. Inbound attachments are attacker-controlled, so this path rejects
 * malformed content, DOCTYPEs, and documents beyond a depth/node budget, and it
 * honours the document's declared encoding rather than assuming UTF-8. Errors are
 * values-reasons, not silent repairs.
 */
export class XmlFault extends Error {
  constructor(
    readonly reason: InboundFailureReason,
    message: string,
  ) {
    super(message);
    this.name = 'XmlFault';
  }
}

export interface XmlLimits {
  /** Byte cap enforced before the DOM parser is invoked. */
  readonly maxBytes: number;
  readonly maxDepth: number;
  /** Cap on every node type (elements, text, comments, ...), not only elements. */
  readonly maxNodes: number;
}

export const defaultXmlLimits: XmlLimits = { maxBytes: 64 * 1024 * 1024, maxDepth: 64, maxNodes: 100_000 };

/** Decode UTF-8 strictly, so an invalid byte is rejected rather than replaced. */
function decodeUtf8(bytes: Buffer): string {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new XmlFault('xml.malformed', 'invalid UTF-8 encoding');
  }
}

/** Decode an XML document per its BOM/declaration; reject unsupported encodings. */
function decodeXml(bytes: Buffer): string {
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    return decodeUtf8(bytes.subarray(3));
  }
  const head = bytes.subarray(0, Math.min(bytes.length, 256)).toString('latin1');
  const declared = /<\?xml[^>]*encoding\s*=\s*["']([^"']+)["']/i.exec(head)?.[1]?.trim().toLowerCase();
  if (!declared || declared === 'utf-8' || declared === 'utf8') return decodeUtf8(bytes);
  if (declared === 'iso-8859-1' || declared === 'latin1' || declared === 'us-ascii' || declared === 'ascii') {
    return bytes.toString('latin1');
  }
  throw new XmlFault('xml.malformed', `unsupported XML encoding ${declared}`);
}

export function parseStrictXml(bytes: Buffer, limits: XmlLimits = defaultXmlLimits): Document {
  if (bytes.length === 0) throw new XmlFault('xml.malformed', 'empty XML document');
  if (bytes.byteLength > limits.maxBytes) throw new XmlFault('xml.too-large', 'XML bytes exceed the limit');
  const text = decodeXml(bytes);
  if (/<!doctype/i.test(text)) throw new XmlFault('xml.doctype', 'DOCTYPE is not accepted');

  const problems: string[] = [];
  let document: Document;
  try {
    document = new DOMParser({
      errorHandler: {
        warning: (message: unknown) => problems.push(String(message)),
        error: (message: unknown) => problems.push(String(message)),
        fatalError: (message: unknown) => problems.push(String(message)),
      },
    }).parseFromString(text, 'application/xml');
  } catch (err) {
    throw new XmlFault('xml.malformed', err instanceof Error ? err.message : String(err));
  }
  if (problems.length > 0) throw new XmlFault('xml.malformed', problems[0]!);

  const root = document.documentElement;
  if (!root) throw new XmlFault('xml.malformed', 'no root element');
  enforceBudget(root, limits);
  return document;
}

function enforceBudget(root: Element, limits: XmlLimits): void {
  let nodes = 1;
  const stack: Array<{ node: Node; depth: number }> = [{ node: root, depth: 1 }];
  while (stack.length > 0) {
    const current = stack.pop()!;
    if (current.depth > limits.maxDepth) throw new XmlFault('xml.too-deep', 'XML depth budget exceeded');
    if (nodes > limits.maxNodes) throw new XmlFault('xml.too-many-nodes', 'XML node budget exceeded');
    const children = current.node.childNodes;
    if (!children) continue;
    for (let i = 0; i < children.length; i += 1) {
      const child = children.item(i);
      if (!child) continue;
      nodes += 1;
      stack.push({ node: child, depth: child.nodeType === 1 ? current.depth + 1 : current.depth });
    }
  }
}
