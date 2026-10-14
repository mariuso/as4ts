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
 * facts needed for comparison are retained, while structural parsing continues
 * through the whole document, so malformed XML after the header and a second
 * header are still detected.
 *
 * Resource bounds are enforced while input is consumed, not after a token has
 * been accumulated: a lexical guard bounds each lexical token (text run, tag,
 * comment, CDATA, processing instruction) in UTF-8 bytes before the SAX parser
 * sees it. Header bytes/nodes/depth/attributes are separate from the document
 * byte/depth bounds. Aborts and read errors propagate; the source iterator is
 * always closed.
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

/** How much of the document may be buffered to read the XML declaration. */
const DECLARATION_LIMIT = 1024;

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

/**
 * Bounds the current lexical token in UTF-8 bytes as characters are consumed, so
 * an oversized value never reaches the SAX parser's own accumulation.
 */
class LexicalGuard {
  private state: 'text' | 'tag' | 'comment' | 'cdata' | 'pi' = 'text';
  private bytes = 0;
  private quote: number | null = null;
  private tail = '';

  constructor(private readonly maxBytes: number) {}

  scan(text: string): void {
    for (const char of text) {
      const code = char.codePointAt(0) ?? 0;
      const size = code < 0x80 ? 1 : code < 0x800 ? 2 : code < 0x10000 ? 3 : 4;
      this.bytes += size;
      if (this.bytes > this.maxBytes) throw new ResourceLimit('xml.token-too-large');
      this.tail = (this.tail + char).slice(-9);
      switch (this.state) {
        case 'text':
          if (char === '<') this.enter('tag', size);
          break;
        case 'tag':
          if (this.tail.startsWith('<!--')) this.enter('comment', 4);
          else if (this.tail === '<![CDATA[') this.enter('cdata', 9);
          else if (this.tail === '<?') this.enter('pi', 2);
          else if (this.quote !== null) {
            if (code === this.quote) this.quote = null;
          } else if (char === '"' || char === "'") this.quote = code;
          else if (char === '>') this.enter('text', 0);
          break;
        case 'comment':
          if (this.tail.endsWith('-->')) this.enter('text', 0);
          break;
        case 'cdata':
          if (this.tail.endsWith(']]>')) this.enter('text', 0);
          break;
        case 'pi':
          if (this.tail.endsWith('?>')) this.enter('text', 0);
          break;
      }
    }
  }

  private enter(state: LexicalGuard['state'], bytes: number): void {
    this.state = state;
    this.bytes = bytes;
    this.quote = null;
  }
}

type Encoding = 'utf-8' | 'latin1' | 'ascii';

/** Whether the prefix is enough to decide the encoding. */
function declarationComplete(prefix: Buffer): boolean {
  let start = 0;
  if (prefix.length >= 3 && prefix[0] === 0xef && prefix[1] === 0xbb && prefix[2] === 0xbf) {
    // A UTF-8 BOM decides nothing on its own: keep reading until the declaration
    // is complete so a conflicting declaration cannot hide behind the BOM.
    start = 3;
  } else if (
    prefix.length >= 2 &&
    ((prefix[0] === 0xff && prefix[1] === 0xfe) || (prefix[0] === 0xfe && prefix[1] === 0xff))
  ) {
    return true; // a UTF-16 BOM is rejected outright
  }
  const trimmed = prefix.subarray(start).toString('latin1').replace(/^\s+/, '');
  if (trimmed.startsWith('<?')) return trimmed.includes('?>');
  // Anything else is a real tag or still just whitespace.
  return trimmed.length > 0 && trimmed.startsWith('<');
}

/** Decide the encoding, or throw malformed for an unsupported/conflicting one. */
function detectEncoding(prefix: Buffer): Encoding {
  const hasUtf8Bom = prefix.length >= 3 && prefix[0] === 0xef && prefix[1] === 0xbb && prefix[2] === 0xbf;
  if (
    !hasUtf8Bom &&
    prefix.length >= 2 &&
    ((prefix[0] === 0xff && prefix[1] === 0xfe) || (prefix[0] === 0xfe && prefix[1] === 0xff))
  ) {
    throw new StructuralError('unsupported XML encoding (UTF-16 byte order mark)');
  }
  const head = prefix
    .subarray(hasUtf8Bom ? 3 : 0)
    .toString('latin1')
    .replace(/^\s+/, '');
  const declaration = head.startsWith('<?xml');
  if (declaration && !head.includes('?>')) {
    throw new StructuralError('unterminated XML declaration within the declaration limit');
  }
  const declared = declaration
    ? /^<\?xml[^>]*encoding\s*=\s*["']([^"']+)["']/i.exec(head)?.[1]?.trim().toLowerCase()
    : undefined;
  if (declared === undefined) return 'utf-8';
  if (declared === 'utf-8' || declared === 'utf8') return 'utf-8';
  if (declared === 'us-ascii' || declared === 'ascii') return 'ascii';
  if (declared === 'iso-8859-1' || declared === 'latin1') {
    if (hasUtf8Bom) throw new StructuralError('the byte order mark conflicts with the declared encoding');
    return 'latin1';
  }
  throw new StructuralError(`unsupported XML encoding ${declared}`);
}

function makeDecoder(encoding: Encoding): { decode(bytes: Buffer): string; flush(): string } {
  if (encoding === 'utf-8') {
    const decoder = new TextDecoder('utf-8', { fatal: true });
    return {
      decode: (bytes) => decoder.decode(bytes, { stream: true }),
      flush: () => decoder.decode(),
    };
  }
  if (encoding === 'ascii') {
    return {
      decode: (bytes) => {
        for (const byte of bytes) if (byte > 0x7f) throw new StructuralError('non-ASCII byte in an ASCII document');
        return bytes.toString('latin1');
      },
      flush: () => '',
    };
  }
  return { decode: (bytes) => bytes.toString('latin1'), flush: () => '' };
}

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
    // Read enough of the prefix to decide the encoding, charging document bytes.
    let prefix = Buffer.alloc(0);
    let finished = false;
    while (prefix.length < DECLARATION_LIMIT && !declarationComplete(prefix)) {
      const next = await iterator.next();
      if (next.done) {
        finished = true;
        break;
      }
      const chunk = Buffer.from(next.value);
      charge(chunk.length);
      prefix = Buffer.concat([prefix, chunk]);
    }
    if (documentBytes > limits.documentBytes) throw new ResourceLimit('xml.too-large');
    const encoding = detectEncoding(prefix);
    const decoder = makeDecoder(encoding);

    const guard = new LexicalGuard(limits.tokenBytes);
    const parser = new SaxesParser({ xmlns: true, position: true });
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

    // Header byte capture, chunk-boundary independent: retain the decoded header
    // text and count its UTF-8 bytes as it arrives.
    let capturing = false;
    let captureFrom = 0;
    let capturedBytes = 0;
    let currentText = '';
    let chunkStart = 0;
    const localOffset = (): number => Math.max(0, Math.min(currentText.length, parser.position - chunkStart));
    const capture = (part: string): void => {
      capturedBytes += Buffer.byteLength(part, 'utf8');
      if (capturedBytes > limits.headerBytes) throw new ResourceLimit('xml.too-large');
    };

    const atPath = (names: readonly string[]): boolean =>
      stack.length === names.length && names.every((name, i) => stack[i]!.local === name && stack[i]!.uri === SBDH_NS);

    const setOnce = (current: number, what: string, assign: () => void): number => {
      if (current > 0) throw new StructuralError(`more than one ${what}`);
      assign();
      return current + 1;
    };

    parser.on('opentag', (node: SaxesTagNS) => {
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
      if (atPath(['StandardBusinessDocument', 'StandardBusinessDocumentHeader'])) {
        headerSeen = setOnce(headerSeen, 'StandardBusinessDocumentHeader', () => {});
        headerOpen = true;
        headerDepth = 0;
        capturing = true;
        captureFrom = localOffset();
      }
      if (!headerOpen) return;
      if (atPath(['StandardBusinessDocument', 'StandardBusinessDocumentHeader', 'Sender'])) {
        senderSeen = setOnce(senderSeen, 'Sender', () => {});
      }
      if (atPath(['StandardBusinessDocument', 'StandardBusinessDocumentHeader', 'Receiver'])) {
        receiverSeen = setOnce(receiverSeen, 'Receiver', () => {});
      }
      if (atPath(['StandardBusinessDocument', 'StandardBusinessDocumentHeader', 'Sender', 'Identifier'])) {
        senderIdSeen = setOnce(senderIdSeen, 'Sender/Identifier', () => {
          sender.authority = node.attributes['Authority']?.value ?? null;
        });
      }
      if (atPath(['StandardBusinessDocument', 'StandardBusinessDocumentHeader', 'Receiver', 'Identifier'])) {
        receiverIdSeen = setOnce(receiverIdSeen, 'Receiver/Identifier', () => {
          receiver.authority = node.attributes['Authority']?.value ?? null;
        });
      }
      if (atPath(['StandardBusinessDocument', 'StandardBusinessDocumentHeader', 'BusinessScope'])) {
        businessScopeSeen = setOnce(businessScopeSeen, 'BusinessScope', () => {});
      }
      if (atPath(['StandardBusinessDocument', 'StandardBusinessDocumentHeader', 'BusinessScope', 'Scope'])) {
        currentScope = { type: null, instance: null, scheme: null, typeSeen: 0, instanceSeen: 0, schemeSeen: 0 };
        scopes.push(currentScope);
      }
      if (
        currentScope &&
        atPath(['StandardBusinessDocument', 'StandardBusinessDocumentHeader', 'BusinessScope', 'Scope', 'Type'])
      ) {
        currentScope.typeSeen = setOnce(currentScope.typeSeen, 'Scope/Type', () => {});
      }
      if (
        currentScope &&
        atPath([
          'StandardBusinessDocument',
          'StandardBusinessDocumentHeader',
          'BusinessScope',
          'Scope',
          'InstanceIdentifier',
        ])
      ) {
        currentScope.instanceSeen = setOnce(currentScope.instanceSeen, 'Scope/InstanceIdentifier', () => {});
      }
      if (
        currentScope &&
        atPath(['StandardBusinessDocument', 'StandardBusinessDocumentHeader', 'BusinessScope', 'Scope', 'Identifier'])
      ) {
        currentScope.schemeSeen = setOnce(currentScope.schemeSeen, 'Scope/Identifier', () => {});
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
      if (atPath(['StandardBusinessDocument', 'StandardBusinessDocumentHeader', 'Sender', 'Identifier'])) {
        appendField(sender.value, text, (value) => {
          sender.value = value;
        });
      } else if (atPath(['StandardBusinessDocument', 'StandardBusinessDocumentHeader', 'Receiver', 'Identifier'])) {
        appendField(receiver.value, text, (value) => {
          receiver.value = value;
        });
      } else if (
        currentScope &&
        atPath(['StandardBusinessDocument', 'StandardBusinessDocumentHeader', 'BusinessScope', 'Scope', 'Type'])
      ) {
        appendField(currentScope.type, text, (value) => {
          currentScope!.type = value;
        });
      } else if (
        currentScope &&
        atPath([
          'StandardBusinessDocument',
          'StandardBusinessDocumentHeader',
          'BusinessScope',
          'Scope',
          'InstanceIdentifier',
        ])
      ) {
        appendField(currentScope.instance, text, (value) => {
          currentScope!.instance = value;
        });
      } else if (
        currentScope &&
        atPath(['StandardBusinessDocument', 'StandardBusinessDocumentHeader', 'BusinessScope', 'Scope', 'Identifier'])
      ) {
        appendField(currentScope.scheme, text, (value) => {
          currentScope!.scheme = value;
        });
      }
    };
    // CDATA is character data and must participate in the field values.
    parser.on('text', handleText);
    parser.on('cdata', handleText);

    parser.on('closetag', (node: SaxesTagNS) => {
      if (headerOpen && stack.length === 2 && stack[1]!.local === 'StandardBusinessDocumentHeader') {
        if (capturing) {
          capture(currentText.slice(captureFrom, localOffset()));
          capturing = false;
        }
        headerOpen = false;
      }
      if (headerOpen) headerDepth -= 1;
      if (node.local === 'Scope' && currentScope) currentScope = null;
      stack.pop();
      depth -= 1;
    });

    const feed = (bytes: Buffer, alreadyCharged: boolean): void => {
      if (!alreadyCharged) charge(bytes.length);
      let text: string;
      try {
        text = decoder.decode(bytes);
      } catch (error) {
        throw error instanceof StructuralError ? error : new StructuralError('invalid text encoding');
      }
      guard.scan(text);
      currentText = text;
      chunkStart = consumedChars;
      const capturingBefore = capturing;
      captureFrom = capturingBefore ? 0 : captureFrom;
      try {
        parser.write(text);
      } catch (error) {
        if (error instanceof ResourceLimit || error instanceof StructuralError) throw error;
        throw new StructuralError(error instanceof Error ? error.message : String(error));
      }
      consumedChars += text.length;
      // Capture exactly the header span: a fully-inside chunk, or the tail of the
      // chunk where the header opened (the close, if it happened in this chunk, was
      // already captured by the handler).
      if (capturing) {
        if (capturingBefore) capture(text);
        else capture(currentText.slice(captureFrom));
      }
      if (parseError) throw new StructuralError(parseError);
    };
    let consumedChars = 0;

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
    if (tail.length > 0) {
      guard.scan(tail);
      currentText = tail;
      chunkStart = consumedChars;
      parser.write(tail);
      consumedChars += tail.length;
      if (parseError) throw new StructuralError(parseError);
    }
    parser.close();
    if (parseError) throw new StructuralError(parseError);

    const sbdhRoot = root as { local: string; uri: string } | null;
    if (!sbdhRoot || sbdhRoot.local !== 'StandardBusinessDocument' || sbdhRoot.uri !== SBDH_NS) {
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
