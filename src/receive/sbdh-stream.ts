import { SaxesParser, type SaxesTagNS } from 'saxes';
import type { ScopedId } from '../types.js';
import {
  DEFAULT_PARTY_SCHEME,
  DEFAULT_SCOPE_SCHEME,
  SBDH_NS,
  compareFacts,
  type SbdhExpected,
  type SbdhFacts,
} from './sbdh.js';
import { abortableStream } from './streams.js';
import type { SbdhConsistency, SbdhResourceLimit } from './types.js';

/**
 * Streaming Standard Business Document Header inspection (Phase 6).
 *
 * The recovered document is parsed incrementally (SAX): only the bounded SBDH
 * information needed for comparison is retained, while structural parsing
 * continues through the whole document so malformed XML after the header and a
 * second header are still detected. Header limits (`headerBytes`, `headerNodes`,
 * `headerDepth`, `attributes`, `tokenBytes`) are separate from the document-wide
 * byte/depth bounds, so a large invoice no longer trips a global node budget just
 * for having many elements.
 *
 * Consistent / inconsistent / missing / resource-limit / malformed remain
 * distinct; aborts and read errors propagate to the caller's transport handling.
 */
export interface SbdhStreamLimits {
  /** Whole recovered document, in bytes. */
  readonly documentBytes: number;
  /** Whole-document nesting bound (protects the parser stack). */
  readonly documentDepth: number;
  /** Bytes within the SBDH header subtree. */
  readonly headerBytes: number;
  /** Nodes (elements and text) within the header subtree. */
  readonly headerNodes: number;
  /** Header nesting bound. */
  readonly headerDepth: number;
  /** Attributes on any one element. */
  readonly attributes: number;
  /** One text or attribute value. */
  readonly tokenBytes: number;
}

/** Default streaming SBDH limits (header bounds are intentionally small). */
export const defaultSbdhStreamLimits: Omit<SbdhStreamLimits, 'documentBytes'> = {
  documentDepth: 256,
  headerBytes: 256 * 1024,
  headerNodes: 4096,
  headerDepth: 32,
  attributes: 64,
  tokenBytes: 64 * 1024,
};

class ResourceLimit extends Error {
  constructor(readonly reason: SbdhResourceLimit) {
    super(reason);
    this.name = 'ResourceLimit';
  }
}

class StructuralError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'StructuralError';
  }
}

interface ScopeRecord {
  type: string | null;
  instance: string | null;
  scheme: string | null;
}

/** Detect the document encoding from a BOM or XML declaration, or null if unsupported. */
function detectEncoding(prefix: Buffer): 'utf-8' | 'latin1' | null {
  if (prefix.length >= 3 && prefix[0] === 0xef && prefix[1] === 0xbb && prefix[2] === 0xbf) return 'utf-8';
  const head = prefix.subarray(0, Math.min(prefix.length, 256)).toString('latin1');
  const declared = /<\?xml[^>]*encoding\s*=\s*["']([^"']+)["']/i.exec(head)?.[1]?.trim().toLowerCase();
  if (!declared || declared === 'utf-8' || declared === 'utf8') return 'utf-8';
  if (declared === 'iso-8859-1' || declared === 'latin1' || declared === 'us-ascii' || declared === 'ascii') {
    return 'latin1';
  }
  return null;
}

export async function checkSbdhStream(
  source: AsyncIterable<Uint8Array>,
  limits: SbdhStreamLimits,
  expected: SbdhExpected,
  signal?: AbortSignal,
): Promise<SbdhConsistency> {
  const iterator = abortableStream(source, signal)[Symbol.asyncIterator]();

  // Gather enough of the prefix to detect the encoding before decoding.
  const prefixChunks: Buffer[] = [];
  let prefixBytes = 0;
  let finished = false;
  while (prefixBytes < 256) {
    const next = await iterator.next();
    if (next.done) {
      finished = true;
      break;
    }
    const chunk = Buffer.from(next.value);
    prefixChunks.push(chunk);
    prefixBytes += chunk.length;
  }
  const encoding = detectEncoding(Buffer.concat(prefixChunks));
  if (encoding === null) return { status: 'malformed', detail: 'unsupported XML encoding' };

  const decoder = encoding === 'utf-8' ? new TextDecoder('utf-8', { fatal: true }) : null;
  const decode = (bytes: Buffer): string =>
    decoder ? decoder.decode(bytes, { stream: true }) : bytes.toString('latin1');

  const parser = new SaxesParser({ xmlns: true });
  let parseError: string | null = null;
  parser.on('error', (error) => {
    parseError ??= error.message;
  });
  parser.on('doctype', () => {
    parseError ??= 'DOCTYPE is not accepted';
  });

  const stack: Array<{ local: string; uri: string }> = [];
  let root: { local: string; uri: string } | null = null;
  let depth = 0;
  let headerSeen = 0;
  let headerOpen = false;
  let headerDepth = 0;
  let headerNodes = 0;
  let headerBytes = 0;
  let documentBytes = 0;
  const sender: { value: string | null; authority: string | null } = { value: null, authority: null };
  const receiver: { value: string | null; authority: string | null } = { value: null, authority: null };
  const scopes: ScopeRecord[] = [];
  let currentScope: ScopeRecord | null = null;

  const path = (): string[] => stack.map((frame) => frame.local);

  const append = (target: { value: string | null }, text: string): void => {
    const value = (target.value ?? '') + text;
    if (value.length > limits.tokenBytes) throw new ResourceLimit('xml.token-too-large');
    target.value = value;
  };

  parser.on('opentag', (node: SaxesTagNS) => {
    const attributes = Object.values(node.attributes);
    if (attributes.length > limits.attributes) throw new ResourceLimit('xml.too-many-attributes');
    for (const attribute of attributes) {
      if (attribute.value.length > limits.tokenBytes) throw new ResourceLimit('xml.token-too-large');
    }
    depth += 1;
    if (depth > limits.documentDepth) throw new ResourceLimit('xml.too-deep');
    stack.push({ local: node.local, uri: node.uri });
    if (!root) root = { local: node.local, uri: node.uri };

    if (headerOpen) {
      headerNodes += 1;
      if (headerNodes > limits.headerNodes) throw new ResourceLimit('xml.too-many-nodes');
      headerDepth += 1;
      if (headerDepth > limits.headerDepth) throw new ResourceLimit('xml.too-deep');
    }

    const trail = path();
    const parent = trail[trail.length - 2];
    const grandparent = trail[trail.length - 3];
    if (
      node.local === 'StandardBusinessDocumentHeader' &&
      node.uri === SBDH_NS &&
      trail.length === 2 &&
      root?.local === 'StandardBusinessDocument' &&
      root.uri === SBDH_NS
    ) {
      headerSeen += 1;
      if (headerSeen > 1) throw new StructuralError('more than one StandardBusinessDocumentHeader');
      headerOpen = true;
      headerDepth = 0;
    }
    if (node.local === 'Identifier' && grandparent === 'StandardBusinessDocumentHeader') {
      const authority = node.attributes['Authority']?.value ?? null;
      if (parent === 'Sender') sender.authority = authority;
      else if (parent === 'Receiver') receiver.authority = authority;
    }
    if (node.local === 'Scope' && node.uri === SBDH_NS && parent === 'BusinessScope') {
      currentScope = { type: null, instance: null, scheme: null };
      scopes.push(currentScope);
    }
  });

  parser.on('text', (text: string) => {
    if (!headerOpen) return;
    headerNodes += 1;
    if (headerNodes > limits.headerNodes) throw new ResourceLimit('xml.too-many-nodes');
    if (text.length > limits.tokenBytes) throw new ResourceLimit('xml.token-too-large');
    const trail = path();
    const leaf = trail[trail.length - 1];
    const parent = trail[trail.length - 2];
    const grandparent = trail[trail.length - 3];
    if (leaf === 'Identifier' && parent === 'Sender' && grandparent === 'StandardBusinessDocumentHeader') {
      append(sender, text);
    } else if (leaf === 'Identifier' && parent === 'Receiver' && grandparent === 'StandardBusinessDocumentHeader') {
      append(receiver, text);
    } else if (currentScope && leaf === 'Type' && parent === 'Scope') {
      currentScope.type = (currentScope.type ?? '') + text;
    } else if (currentScope && leaf === 'InstanceIdentifier' && parent === 'Scope') {
      currentScope.instance = (currentScope.instance ?? '') + text;
    } else if (currentScope && leaf === 'Identifier' && parent === 'Scope') {
      currentScope.scheme = (currentScope.scheme ?? '') + text;
    }
  });

  parser.on('closetag', (node: SaxesTagNS) => {
    const trail = path();
    if (headerOpen && trail.length === 2 && trail[1] === 'StandardBusinessDocumentHeader') headerOpen = false;
    if (node.local === 'Scope' && currentScope) currentScope = null;
    stack.pop();
    depth -= 1;
  });

  const feed = (bytes: Buffer): void => {
    documentBytes += bytes.length;
    if (documentBytes > limits.documentBytes) throw new ResourceLimit('xml.too-large');
    if (headerOpen) {
      headerBytes += bytes.length;
      if (headerBytes > limits.headerBytes) throw new ResourceLimit('xml.too-large');
    }
    let text: string;
    try {
      text = decode(bytes);
    } catch {
      throw new StructuralError('invalid text encoding');
    }
    try {
      parser.write(text);
    } catch (error) {
      // A ResourceLimit/StructuralError thrown from a handler must not be
      // reclassified as a generic parse error.
      if (error instanceof ResourceLimit || error instanceof StructuralError) throw error;
      throw new StructuralError(error instanceof Error ? error.message : String(error));
    }
    if (parseError) throw new StructuralError(parseError);
  };

  try {
    feed(Buffer.concat(prefixChunks));
    if (!finished) {
      for (;;) {
        const next = await iterator.next();
        if (next.done) break;
        feed(Buffer.from(next.value));
      }
    }
    if (decoder) {
      // Flush any characters held by the streaming decoder.
      const tail = decoder.decode();
      if (tail.length > 0) {
        parser.write(tail);
        if (parseError) throw new StructuralError(parseError);
      }
    }
    parser.close();
    if (parseError) throw new StructuralError(parseError);

    const readRoot = (): { local: string; uri: string } | null => root;
    const isSbdhRoot = ((): boolean => {
      const node = readRoot();
      return node !== null && node.local === 'StandardBusinessDocument' && node.uri === SBDH_NS;
    })();
    if (!isSbdhRoot) return { status: 'missing' };

    const facts: SbdhFacts = {
      sender: scoped(sender, DEFAULT_PARTY_SCHEME),
      receiver: scoped(receiver, DEFAULT_PARTY_SCHEME),
      process: resolveScope(scopes, 'PROCESSID'),
      documentType: resolveScope(scopes, 'DOCUMENTID'),
    };
    const mismatches = compareFacts(facts, expected);
    return mismatches.length > 0 ? { status: 'inconsistent', mismatches } : { status: 'consistent' };
  } catch (error) {
    if (error instanceof ResourceLimit) return { status: 'resource-limit', reason: error.reason };
    if (error instanceof StructuralError) return { status: 'malformed', detail: error.message };
    throw error; // abort / read errors propagate to the caller's transport handling
  }
}

function scoped(
  participant: { value: string | null; authority: string | null },
  defaultScheme: string,
): ScopedId | null {
  const value = participant.value?.trim();
  if (!value) return null;
  return { scheme: participant.authority?.trim() || defaultScheme, value };
}

function resolveScope(scopes: readonly ScopeRecord[], type: string): ScopedId | null {
  const matches = scopes.filter((scope) => (scope.type?.trim().toUpperCase() ?? '') === type);
  if (matches.length > 1) throw new StructuralError(`more than one ${type} Scope`);
  const scope = matches[0];
  if (!scope) return null;
  const value = scope.instance?.trim();
  if (!value) return null;
  return { scheme: scope.scheme?.trim() || DEFAULT_SCOPE_SCHEME[type] || '', value };
}
