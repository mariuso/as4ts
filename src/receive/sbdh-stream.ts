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
import {
  LexicalGuard,
  XmlLexicalFault,
  detectEncoding,
  inspectDeclaration,
  makeDecoder,
  type TagEvent,
} from './xml-lexical.js';

/**
 * Streaming Standard Business Document Header inspection (Phase 6).
 *
 * The recovered document is parsed incrementally (SAX): only the bounded SBDH
 * facts needed for comparison are retained, while structural parsing continues
 * through the whole document, so malformed XML after the header and a second
 * header are still detected.
 *
 * Resource bounds are enforced while input is consumed, not after a token has
 * been accumulated: a lexical guard tracks token openings with explicit states,
 * bounds each token (text run, element tag, comment, CDATA, processing
 * instruction) in UTF-8 bytes before the SAX parser sees it, and rejects a
 * DOCTYPE as soon as its opening is recognised. The header byte budget is
 * measured from the lexical span of the SBDH header element itself. Aborts and
 * read errors propagate; the source iterator is always closed.
 */
export interface SbdhStreamLimits {
  /** Whole recovered document, in bytes. */
  readonly documentBytes: number;
  /** Whole-document nesting bound (protects the parser stack). */
  readonly documentDepth: number;
  /** Bytes within the SBDH header element (including its opening markup). */
  readonly headerBytes: number;
  /** Nodes (elements and text) within the header element. */
  readonly headerNodes: number;
  /** Header nesting bound. */
  readonly headerDepth: number;
  /** Attributes on any one element. */
  readonly attributes: number;
  /** One text, attribute, comment, CDATA or markup token, in UTF-8 bytes. */
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

/** The SBDH header element's local name. */
const HEADER_LOCAL_NAME = 'StandardBusinessDocumentHeader';
const ROOT_LOCAL_NAME = 'StandardBusinessDocument';

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
  typeSeen: number;
  instanceSeen: number;
  schemeSeen: number;
}

/** The SBDH fields that carry simple character content (no child elements). */
const SIMPLE_FIELDS: ReadonlyArray<readonly string[]> = [
  [ROOT_LOCAL_NAME, HEADER_LOCAL_NAME, 'Sender', 'Identifier'],
  [ROOT_LOCAL_NAME, HEADER_LOCAL_NAME, 'Receiver', 'Identifier'],
  [ROOT_LOCAL_NAME, HEADER_LOCAL_NAME, 'BusinessScope', 'Scope', 'Type'],
  [ROOT_LOCAL_NAME, HEADER_LOCAL_NAME, 'BusinessScope', 'Scope', 'InstanceIdentifier'],
  [ROOT_LOCAL_NAME, HEADER_LOCAL_NAME, 'BusinessScope', 'Scope', 'Identifier'],
];

export async function checkSbdhStream(
  source: AsyncIterable<Uint8Array>,
  limits: SbdhStreamLimits,
  expected: SbdhExpected,
  signal?: AbortSignal,
): Promise<SbdhConsistency> {
  const iterator = abortableStream(source, signal)[Symbol.asyncIterator]();
  let documentBytes = 0;
  const charge = (count: number): void => {
    documentBytes += count;
    if (documentBytes > limits.documentBytes) throw new ResourceLimit('xml.too-large');
  };

  try {
    // Read until the optional XML declaration is determined. The retained prefix
    // stays small: an absent declaration is decided at the first byte, and the
    // declaration bound is enforced against the declaration itself, so the
    // outcome never depends on the chunking and leading whitespace is not
    // accumulated.
    let prefix = Buffer.alloc(0);
    let finished = false;
    for (;;) {
      const status = inspectDeclaration(prefix);
      if (status === 'complete' || status === 'absent') break;
      if (status === 'too-long') throw new StructuralError('XML declaration exceeds the declaration limit');
      const next = await iterator.next();
      if (next.done) {
        finished = true;
        break;
      }
      const chunk = Buffer.from(next.value);
      charge(chunk.length);
      prefix = Buffer.concat([prefix, chunk]);
    }
    const encoding = detectEncoding(prefix);
    const decoder = makeDecoder(encoding);

    // The lexical span of the SBDH header element, in cumulative UTF-8 bytes.
    // The guard reports the exact byte span of every element tag; the parser's
    // element events are paired with them, in order, and the span is selected
    // only for the namespace-validated, direct-child SBDH header. Every pair is
    // checked for kind and qualified name, so an absent or mismatched event fails
    // closed rather than silently skipping header-byte accounting. The lists are
    // per chunk (not document-wide), and once the header's span is selected it is
    // preserved, so a later lookalike cannot replace it.
    let headerSpanStart: number | null = null;
    let headerSpanEnd: number | null = null;
    const chunkTags: TagEvent[] = [];
    let chunkTagCursor = 0;
    const guard = new LexicalGuard(limits.tokenBytes, (tag) => chunkTags.push(tag));

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
    const sender: { value: string | null; authority: string | null } = { value: null, authority: null };
    const receiver: { value: string | null; authority: string | null } = { value: null, authority: null };
    let senderSeen = 0;
    let receiverSeen = 0;
    let senderIdSeen = 0;
    let receiverIdSeen = 0;
    let businessScopeSeen = 0;
    const scopes: ScopeRecord[] = [];
    let currentScope: ScopeRecord | null = null;
    let scopeDepth = 0;
    let openField: readonly string[] | null = null;
    let openFieldDepth = 0;

    const atPath = (names: readonly string[]): boolean =>
      stack.length === names.length && names.every((name, i) => stack[i]!.local === name && stack[i]!.uri === SBDH_NS);

    const setOnce = (current: number, what: string, assign: () => void): number => {
      if (current > 0) throw new StructuralError(`more than one ${what}`);
      assign();
      return current + 1;
    };

    // Pair a parser element event with the guard's next tag event. A missing or
    // mismatched pair means the two event streams disagree (for example on what
    // constitutes whitespace inside a tag); fail closed rather than silently
    // miss the header's span.
    const pairTag = (kind: TagEvent['kind'], node: SaxesTagNS): TagEvent => {
      const tag = chunkTags[chunkTagCursor++];
      const name = node.prefix ? `${node.prefix}:${node.local}` : node.local;
      if (!tag || tag.kind !== kind || tag.name !== name) {
        throw new StructuralError('the lexical scanner and the XML parser disagree on an element event');
      }
      return tag;
    };

    parser.on('opentag', (node: SaxesTagNS) => {
      const tag = pairTag('open', node);
      // Simple-content fields carry no child elements. Reject a nested element
      // rather than silently dropping its content.
      if (openField !== null) throw new StructuralError(`unexpected element inside ${openField[openField.length - 1]}`);
      const attributes = Object.values(node.attributes);
      if (attributes.length > limits.attributes) throw new ResourceLimit('xml.too-many-attributes');
      for (const attribute of attributes) {
        if (Buffer.byteLength(attribute.value, 'utf8') > limits.tokenBytes) {
          throw new ResourceLimit('xml.token-too-large');
        }
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
      // The header is the root's direct child in the SBDH namespace.
      if (!headerOpen && stack.length === 2 && atPath([ROOT_LOCAL_NAME, HEADER_LOCAL_NAME])) {
        headerSeen = setOnce(headerSeen, HEADER_LOCAL_NAME, () => {});
        headerOpen = true;
        headerDepth = 0;
        if (tag) {
          headerSpanStart = tag.start;
          headerSpanEnd = tag.selfClosing ? tag.end : null;
        }
      }
      if (!headerOpen) {
        const field = SIMPLE_FIELDS.find((path) => atPath(path));
        if (field) {
          openField = field;
          openFieldDepth = stack.length;
        }
        return;
      }
      if (atPath([ROOT_LOCAL_NAME, HEADER_LOCAL_NAME, 'Sender'])) {
        senderSeen = setOnce(senderSeen, 'Sender', () => {});
      }
      if (atPath([ROOT_LOCAL_NAME, HEADER_LOCAL_NAME, 'Receiver'])) {
        receiverSeen = setOnce(receiverSeen, 'Receiver', () => {});
      }
      if (atPath([ROOT_LOCAL_NAME, HEADER_LOCAL_NAME, 'Sender', 'Identifier'])) {
        senderIdSeen = setOnce(senderIdSeen, 'Sender/Identifier', () => {
          sender.authority = node.attributes['Authority']?.value ?? null;
        });
      }
      if (atPath([ROOT_LOCAL_NAME, HEADER_LOCAL_NAME, 'Receiver', 'Identifier'])) {
        receiverIdSeen = setOnce(receiverIdSeen, 'Receiver/Identifier', () => {
          receiver.authority = node.attributes['Authority']?.value ?? null;
        });
      }
      if (atPath([ROOT_LOCAL_NAME, HEADER_LOCAL_NAME, 'BusinessScope'])) {
        businessScopeSeen = setOnce(businessScopeSeen, 'BusinessScope', () => {});
      }
      if (atPath([ROOT_LOCAL_NAME, HEADER_LOCAL_NAME, 'BusinessScope', 'Scope'])) {
        currentScope = { type: null, instance: null, scheme: null, typeSeen: 0, instanceSeen: 0, schemeSeen: 0 };
        scopes.push(currentScope);
        scopeDepth = stack.length;
      }
      if (currentScope && atPath([ROOT_LOCAL_NAME, HEADER_LOCAL_NAME, 'BusinessScope', 'Scope', 'Type'])) {
        currentScope.typeSeen = setOnce(currentScope.typeSeen, 'Scope/Type', () => {});
      }
      if (
        currentScope &&
        atPath([ROOT_LOCAL_NAME, HEADER_LOCAL_NAME, 'BusinessScope', 'Scope', 'InstanceIdentifier'])
      ) {
        currentScope.instanceSeen = setOnce(currentScope.instanceSeen, 'Scope/InstanceIdentifier', () => {});
      }
      if (currentScope && atPath([ROOT_LOCAL_NAME, HEADER_LOCAL_NAME, 'BusinessScope', 'Scope', 'Identifier'])) {
        currentScope.schemeSeen = setOnce(currentScope.schemeSeen, 'Scope/Identifier', () => {});
      }
      const field = SIMPLE_FIELDS.find((path) => atPath(path));
      if (field) {
        openField = field;
        openFieldDepth = stack.length;
      }
    });

    const appendField = (current: string | null, text: string, assign: (value: string) => void): void => {
      const value = (current ?? '') + text;
      if (Buffer.byteLength(value, 'utf8') > limits.tokenBytes) throw new ResourceLimit('xml.token-too-large');
      assign(value);
    };
    const handleText = (text: string): void => {
      if (!headerOpen) return;
      headerNodes += 1;
      if (headerNodes > limits.headerNodes) throw new ResourceLimit('xml.too-many-nodes');
      if (Buffer.byteLength(text, 'utf8') > limits.tokenBytes) throw new ResourceLimit('xml.token-too-large');
      // Character data (including CDATA) accumulates within one element; a second
      // element of the same kind is a cardinality error caught at opentag.
      if (atPath([ROOT_LOCAL_NAME, HEADER_LOCAL_NAME, 'Sender', 'Identifier'])) {
        appendField(sender.value, text, (value) => {
          sender.value = value;
        });
      } else if (atPath([ROOT_LOCAL_NAME, HEADER_LOCAL_NAME, 'Receiver', 'Identifier'])) {
        appendField(receiver.value, text, (value) => {
          receiver.value = value;
        });
      } else if (currentScope && atPath([ROOT_LOCAL_NAME, HEADER_LOCAL_NAME, 'BusinessScope', 'Scope', 'Type'])) {
        appendField(currentScope.type, text, (value) => {
          currentScope!.type = value;
        });
      } else if (
        currentScope &&
        atPath([ROOT_LOCAL_NAME, HEADER_LOCAL_NAME, 'BusinessScope', 'Scope', 'InstanceIdentifier'])
      ) {
        appendField(currentScope.instance, text, (value) => {
          currentScope!.instance = value;
        });
      } else if (currentScope && atPath([ROOT_LOCAL_NAME, HEADER_LOCAL_NAME, 'BusinessScope', 'Scope', 'Identifier'])) {
        appendField(currentScope.scheme, text, (value) => {
          currentScope!.scheme = value;
        });
      }
    };
    parser.on('text', handleText);
    parser.on('cdata', handleText);

    parser.on('closetag', (node: SaxesTagNS) => {
      const tag = pairTag('close', node);
      // End a field / scope only when the exact element being collected closes.
      if (openField !== null && stack.length === openFieldDepth) openField = null;
      if (currentScope !== null && stack.length === scopeDepth) currentScope = null;
      if (headerOpen && stack.length === 2 && stack[1]!.local === HEADER_LOCAL_NAME && stack[1]!.uri === SBDH_NS) {
        headerOpen = false;
        if (tag) headerSpanEnd = tag.end;
      }
      if (headerOpen) headerDepth -= 1;
      stack.pop();
      depth -= 1;
    });

    // Enforce the header byte budget against the actual header span once the
    // parser has confirmed the header is the SBDH header.
    const enforceHeaderBytes = (): void => {
      if (headerSeen === 0 || headerSpanStart === null) return;
      const end = headerSpanEnd ?? guard.position;
      if (end - headerSpanStart > limits.headerBytes) throw new ResourceLimit('xml.too-large');
    };

    const process = (text: string): void => {
      // Reset the per-chunk association: the guard reports every element tag in
      // this chunk before the parser consumes them.
      chunkTags.length = 0;
      chunkTagCursor = 0;
      guard.scan(text);
      try {
        parser.write(text);
      } catch (error) {
        if (error instanceof ResourceLimit || error instanceof StructuralError || error instanceof XmlLexicalFault)
          throw error;
        throw new StructuralError(error instanceof Error ? error.message : String(error));
      }
      enforceHeaderBytes();
      if (parseError) throw new StructuralError(parseError);
    };

    const feed = (bytes: Buffer, alreadyCharged: boolean): void => {
      if (!alreadyCharged) charge(bytes.length);
      let text: string;
      try {
        text = decoder.decode(bytes);
      } catch (error) {
        throw error instanceof StructuralError || error instanceof XmlLexicalFault
          ? error
          : new StructuralError('invalid text encoding');
      }
      process(text);
    };

    feed(prefix, true);
    if (!finished) {
      for (;;) {
        const next = await iterator.next();
        if (next.done) break;
        feed(Buffer.from(next.value), false);
      }
    }
    // Flush any characters the streaming decoder held back; an incomplete final
    // sequence is malformed, not a raw decoder error.
    let tail: string;
    try {
      tail = decoder.flush();
    } catch {
      throw new StructuralError('incomplete or invalid text encoding');
    }
    if (tail.length > 0) process(tail);
    parser.close();
    if (parseError) throw new StructuralError(parseError);

    const sbdhRoot = root as { local: string; uri: string } | null;
    if (!sbdhRoot || sbdhRoot.local !== ROOT_LOCAL_NAME || sbdhRoot.uri !== SBDH_NS) {
      return { status: 'missing' };
    }
    if (headerSeen === 0) return { status: 'missing' };

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
    if (error instanceof XmlLexicalFault) {
      return error.kind === 'token'
        ? { status: 'resource-limit', reason: 'xml.token-too-large' }
        : { status: 'malformed', detail: error.message };
    }
    if (error instanceof StructuralError) return { status: 'malformed', detail: error.message };
    throw error; // abort / read errors propagate to the caller's transport handling
  } finally {
    // Close the source on every exit (resource limit, malformed, missing,
    // cancellation), preserving the shared adapter's non-blocking cleanup.
    try {
      const returned: unknown = iterator.return?.(undefined as never);
      if (returned) void Promise.resolve(returned).catch(() => {});
    } catch {
      // ignore
    }
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
