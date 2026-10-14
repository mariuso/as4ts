import { DOMParser } from '@xmldom/xmldom';
import { SaxesParser, type SaxesTagNS } from 'saxes';
import { xmlHooks } from '../xml/hooks.js';
import type { InboundFailureReason } from './types.js';
import { LexicalGuard, XmlLexicalFault, decodeXmlDocument } from './xml-lexical.js';

/**
 * A strictly bounded XML parse for inbound bytes (Item 4).
 *
 * The receiving path must never hand attacker-controlled bytes to a DOM parser
 * before the input has been validated and structurally bounded. The sequence is:
 *
 *   validate configuration and the input-byte cap
 *   → strict decoding (XML 1.0 only, BOM/declaration agreement, ASCII enforced)
 *   → bounded SAX preflight (depth, nodes, attributes, lexical tokens, DTD)
 *   → DOM construction
 *   → (defence in depth) post-DOM structural check
 *
 * The preflight is the first effective structural limit: it rejects an
 * over-budget document *before* the DOM is allocated. Encoding uses the shared
 * {@link decodeXmlDocument} policy, and token bounds use the shared
 * {@link LexicalGuard}, so this path cannot drift from the streaming SBDH reader.
 * Errors are value-reasons, not silent repairs.
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
  /** Byte cap on the uncompressed XML representation, enforced before parsing. */
  readonly maxBytes: number;
  /** Element nesting bound, enforced before the DOM parser is invoked. */
  readonly maxDepth: number;
  /**
   * Node bound, enforced before the DOM parser is invoked. A node is an element,
   * a text node (entity references expand into one text node), a CDATA section,
   * a comment, or a processing instruction — including those outside the root.
   */
  readonly maxNodes: number;
  /** Attributes plus namespace declarations on any one element. */
  readonly maxAttributes: number;
  /** One text, attribute, comment, CDATA or markup token, in UTF-8 bytes. */
  readonly maxTokenBytes: number;
}

export const defaultXmlLimits: XmlLimits = {
  maxBytes: 64 * 1024 * 1024,
  maxDepth: 64,
  maxNodes: 100_000,
  maxAttributes: 64,
  maxTokenBytes: 64 * 1024,
};

/**
 * Validate every limit as a finite, non-negative safe integer. `0` is a
 * legitimate value meaning "nothing is allowed" (any input exceeds it). An
 * invalid configuration is an explicit `limits.invalid` failure, never a
 * silently removed bound.
 */
export function validateXmlLimits(limits: XmlLimits): void {
  const entries: ReadonlyArray<readonly [string, number]> = [
    ['maxBytes', limits.maxBytes],
    ['maxDepth', limits.maxDepth],
    ['maxNodes', limits.maxNodes],
    ['maxAttributes', limits.maxAttributes],
    ['maxTokenBytes', limits.maxTokenBytes],
  ];
  for (const [name, value] of entries) {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new XmlFault('limits.invalid', `XML limit ${name} must be a non-negative safe integer`);
    }
  }
}

function mapLexical(error: unknown): never {
  if (error instanceof XmlLexicalFault) {
    if (error.kind === 'doctype') throw new XmlFault('xml.doctype', error.message);
    if (error.kind === 'token') throw new XmlFault('xml.token-too-large', error.message);
    throw new XmlFault('xml.malformed', error.message);
  }
  throw error instanceof Error ? error : new Error(String(error));
}

/** Decode under the shared policy, mapping every decoding fault to `malformed`. */
function decode(bytes: Buffer): string {
  try {
    return decodeXmlDocument(bytes);
  } catch (error) {
    if (error instanceof XmlLexicalFault) throw new XmlFault('xml.malformed', error.message);
    throw error;
  }
}

/**
 * Bounded SAX preflight. It parses the complete document (including trailing
 * content), enforces the structural bounds while the document is consumed rather
 * than after a tree is built, counts comments and processing instructions both
 * inside and outside the root, and reports a real DTD declaration while ignoring
 * the same text inside a comment or CDATA section. Only counters are retained —
 * never an event list.
 */
function preflight(text: string, limits: XmlLimits): void {
  const guard = new LexicalGuard(limits.maxTokenBytes);
  const parser = new SaxesParser({ xmlns: true });
  let parseError: string | null = null;
  let doctype = false;
  parser.on('error', (error) => {
    parseError ??= error.message;
  });
  parser.on('doctype', () => {
    doctype = true;
  });

  let depth = 0;
  let nodes = 0;
  const countNode = (): void => {
    nodes += 1;
    if (nodes > limits.maxNodes) throw new XmlFault('xml.too-many-nodes', 'XML node budget exceeded');
  };

  parser.on('opentag', (node: SaxesTagNS) => {
    depth += 1;
    if (depth > limits.maxDepth) throw new XmlFault('xml.too-deep', 'XML depth budget exceeded');
    const attributes = Object.values(node.attributes);
    if (attributes.length > limits.maxAttributes) {
      throw new XmlFault('xml.too-many-attributes', 'XML attribute budget exceeded');
    }
    for (const attribute of attributes) {
      if (Buffer.byteLength(attribute.value, 'utf8') > limits.maxTokenBytes) {
        throw new XmlFault('xml.token-too-large', 'XML lexical token exceeds the byte limit');
      }
    }
    countNode();
  });
  parser.on('closetag', () => {
    depth -= 1;
  });
  parser.on('text', countNode);
  parser.on('cdata', countNode);
  parser.on('comment', countNode);
  parser.on('processinginstruction', countNode);

  try {
    guard.scan(text);
  } catch (error) {
    mapLexical(error);
  }
  try {
    parser.write(text);
  } catch (error) {
    mapLexical(error);
  }
  try {
    parser.close();
  } catch (error) {
    mapLexical(error);
  }
  if (doctype) throw new XmlFault('xml.doctype', 'DOCTYPE is not accepted');
  if (parseError) throw new XmlFault('xml.malformed', parseError);
}

/** Defence in depth: the actual DOM must also satisfy the structural bounds. */
function enforceDomBudget(document: Document, limits: XmlLimits): void {
  let nodes = 0;
  const stack: Array<{ node: Node; depth: number }> = [{ node: document, depth: 0 }];
  while (stack.length > 0) {
    const current = stack.pop()!;
    const children = current.node.childNodes;
    if (!children) continue;
    for (let i = 0; i < children.length; i += 1) {
      const child = children.item(i);
      if (!child) continue;
      nodes += 1;
      if (nodes > limits.maxNodes) throw new XmlFault('xml.too-many-nodes', 'XML node budget exceeded');
      const childDepth = child.nodeType === 1 ? current.depth + 1 : current.depth;
      if (childDepth > limits.maxDepth) throw new XmlFault('xml.too-deep', 'XML depth budget exceeded');
      stack.push({ node: child, depth: childDepth });
    }
  }
}

export function parseStrictXml(bytes: Buffer, limits: XmlLimits = defaultXmlLimits): Document {
  validateXmlLimits(limits);
  if (bytes.length === 0) throw new XmlFault('xml.malformed', 'empty XML document');
  if (bytes.byteLength > limits.maxBytes) throw new XmlFault('xml.too-large', 'XML bytes exceed the limit');

  const text = decode(bytes);
  preflight(text, limits);

  const problems: string[] = [];
  let document: Document;
  try {
    xmlHooks.onDomParse?.();
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
  enforceDomBudget(document, limits);
  return document;
}
