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

/**
 * How many bytes of a document may be buffered to read the XML declaration.
 * Enforced against the declaration itself, independent of how the input is
 * chunked.
 */
const DECLARATION_LIMIT = 1024;

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

/** UTF-8 byte length of a single code point. */
function codePointBytes(code: number): number {
  if (code < 0x80) return 1;
  if (code < 0x800) return 2;
  if (code < 0x10000) return 3;
  return 4;
}

type LexicalState = 'text' | 'markup' | 'element' | 'comment' | 'cdata' | 'pi' | 'declaration';

interface TagEvent {
  /** Raw element name, including any namespace prefix. */
  readonly name: string;
  readonly kind: 'open' | 'close';
  readonly selfClosing: boolean;
  /** Cumulative UTF-8 byte offset of the opening `<`. */
  readonly start: number;
  /** Cumulative UTF-8 byte offset just past the closing `>`. */
  readonly end: number;
}

/**
 * Bounds the current lexical token in UTF-8 bytes as characters are consumed, so
 * an oversized value never reaches the SAX parser's own accumulation.
 *
 * Token openings are recognised with explicit, token-local states and a bounded
 * lookahead (`opener`, at most the length of `<!DOCTYPE`). Once inside a
 * comment, CDATA section or processing instruction, only its real terminator
 * ends it. Every per-token buffer is reset at a token boundary, so recognition
 * never depends on the previous token. A DOCTYPE is rejected the moment its
 * opening is recognised, before the SAX parser can accumulate its internal
 * subset. Element tags are reported with their exact byte span so the caller can
 * account for a specific element without buffering document text.
 */
class LexicalGuard {
  private state: LexicalState = 'text';
  private bytes = 0;
  private consumed = 0;
  private quote: number | null = null;
  private opener = '';
  private tail = '';
  private tokenStart = 0;
  private name = '';
  private nameDone = true;
  private closing = false;
  private selfClosing = false;

  constructor(
    private readonly maxBytes: number,
    private readonly onTag?: (tag: TagEvent) => void,
  ) {}

  /** Cumulative UTF-8 bytes consumed so far. */
  get position(): number {
    return this.consumed;
  }

  scan(text: string): void {
    for (const char of text) {
      const code = char.codePointAt(0) ?? 0;
      const size = codePointBytes(code);
      // A '<' in text starts a new markup token; the counter resets before the
      // byte is charged so an exactly-full text token is not rejected.
      if (this.state === 'text' && char === '<') {
        this.bytes = 0;
        this.tokenStart = this.consumed;
      }
      this.consumed += size;
      this.bytes += size;
      if (this.bytes > this.maxBytes) throw new ResourceLimit('xml.token-too-large');
      this.step(char, code);
    }
  }

  private step(char: string, code: number): void {
    switch (this.state) {
      case 'text':
        if (char === '<') {
          this.state = 'markup';
          this.opener = '<';
          this.quote = null;
          this.tail = '';
        }
        return;
      case 'markup':
        this.opener += char;
        this.classify();
        return;
      case 'element':
        if (!this.nameDone && this.quote === null) {
          if (char === '>' || char === '/' || char === ' ' || char === '\t' || char === '\n' || char === '\r') {
            this.nameDone = true;
          } else {
            this.name += char;
          }
        }
        if (this.quote !== null) {
          if (code === this.quote) this.quote = null;
        } else if (char === '"' || char === "'") {
          this.quote = code;
        } else if (char === '/') {
          this.selfClosing = true;
        } else if (char === '>') {
          const kind: TagEvent['kind'] = this.closing ? 'close' : 'open';
          const event: TagEvent = {
            name: this.name,
            kind,
            selfClosing: this.selfClosing,
            start: this.tokenStart,
            end: this.consumed,
          };
          this.onTag?.(event);
          // A self-closing tag ends two elements (open then close) in the SAX
          // event stream; mirror that so the ordered association stays aligned.
          if (this.selfClosing) this.onTag?.({ ...event, kind: 'close' });
          this.endToken();
        }
        return;
      case 'comment':
        this.tail = (this.tail + char).slice(-3);
        if (this.tail === '-->') this.endToken();
        return;
      case 'cdata':
        this.tail = (this.tail + char).slice(-3);
        if (this.tail === ']]>') this.endToken();
        return;
      case 'pi':
        this.tail = (this.tail + char).slice(-2);
        if (this.tail === '?>') this.endToken();
        return;
      case 'declaration':
        if (char === '>') this.endToken();
        return;
    }
  }

  private classify(): void {
    const opener = this.opener;
    if (opener === '<?') {
      this.openToken('pi');
      return;
    }
    if (opener.startsWith('<!')) {
      if (opener === '<!--') return this.openToken('comment');
      if (opener === '<![CDATA[') return this.openToken('cdata');
      if (opener === '<!DOCTYPE') throw new StructuralError('DOCTYPE is not accepted');
      if ('<!--'.startsWith(opener) || '<![CDATA['.startsWith(opener) || '<!DOCTYPE'.startsWith(opener)) return;
      return this.openToken('declaration');
    }
    this.state = 'element';
    this.opener = '';
    this.tail = '';
    this.quote = null;
    this.closing = opener.startsWith('</');
    this.name = this.closing ? '' : opener.slice(1);
    this.nameDone = false;
    this.selfClosing = false;
  }

  /** Continue the same token in a specialised state (byte counter is preserved). */
  private openToken(state: LexicalState): void {
    this.state = state;
    this.opener = '';
    this.tail = '';
    this.quote = null;
    this.name = '';
    this.nameDone = true;
    this.closing = false;
    this.selfClosing = false;
  }

  /** Finish the current token: the next character begins a fresh one. */
  private endToken(): void {
    this.state = 'text';
    this.bytes = 0;
    this.opener = '';
    this.tail = '';
    this.quote = null;
    this.name = '';
    this.nameDone = true;
    this.closing = false;
    this.selfClosing = false;
  }
}

type Encoding = 'utf-8' | 'latin1' | 'ascii';

function hasUtf8Bom(buffer: Buffer): boolean {
  return buffer.length >= 3 && buffer[0] === 0xef && buffer[1] === 0xbb && buffer[2] === 0xbf;
}

function hasUtf16Bom(buffer: Buffer): boolean {
  return (
    buffer.length >= 2 && ((buffer[0] === 0xff && buffer[1] === 0xfe) || (buffer[0] === 0xfe && buffer[1] === 0xff))
  );
}

type DeclarationStatus = 'pending' | 'absent' | 'complete' | 'too-long';

/**
 * Classify the buffer's leading bytes as: still pending (too little to decide
 * whether the optional XML declaration is present), absent (no declaration),
 * complete (a full declaration is present) or too-long (a declaration is
 * present but exceeds the declaration limit).
 *
 * This depends only on the bytes seen, never on how they were chunked. A partial
 * byte-order mark stays pending, and only the exact `<?xml` opening (its name
 * followed by whitespace or `?`) counts as a declaration — a processing
 * instruction such as `<?xml-stylesheet …?>` is not one. The declaration must
 * start at the very first byte, so leading whitespace means "absent" and the
 * prefix never accumulates it.
 */
function inspectDeclaration(buffer: Buffer): DeclarationStatus {
  let start = 0;
  const first = buffer.length > 0 ? buffer[0] : -1;
  if (first === 0xef) {
    if (buffer.length < 3) {
      if (buffer.length >= 2 && buffer[1] !== 0xbb) return 'absent';
      return 'pending'; // could still be a UTF-8 byte order mark
    }
    if (buffer[1] !== 0xbb || buffer[2] !== 0xbf) return 'absent';
    start = 3;
  } else if (first === 0xfe || first === 0xff) {
    if (buffer.length < 2) return 'pending'; // a partial UTF-16 byte order mark
    return 'complete'; // rejected by detectEncoding
  }
  const rest = buffer.subarray(start);
  if (rest.length === 0) return 'pending';
  if (rest[0] !== 0x3c /* '<' */) return 'absent';
  const opener = rest.subarray(0, Math.min(rest.length, 5)).toString('latin1');
  if (opener.length < 5) return '<?xml'.startsWith(opener) ? 'pending' : 'absent';
  if (opener !== '<?xml') return 'absent';
  if (rest.length === 5) return 'pending'; // need one more byte to tell declaration from a PI
  const isNameChar = /[A-Za-z0-9_:.\-]/.test(String.fromCharCode(rest[5]!));
  if (isNameChar) return 'absent'; // e.g. <?xml-stylesheet …?>
  const close = rest.indexOf('?>');
  if (close < 0) return rest.length > DECLARATION_LIMIT ? 'too-long' : 'pending';
  return close + 2 > DECLARATION_LIMIT ? 'too-long' : 'complete';
}

/** True when the head begins with the exact XML declaration opening. */
function hasDeclarationOpening(head: string): boolean {
  if (!head.startsWith('<?xml')) return false;
  const next = head[5];
  return next === undefined || /\s/.test(next) || next === '?';
}

/** Decide the encoding, or throw malformed for an unsupported/conflicting one. */
function detectEncoding(buffer: Buffer): Encoding {
  const utf8Bom = hasUtf8Bom(buffer);
  if (!utf8Bom && hasUtf16Bom(buffer)) {
    throw new StructuralError('unsupported XML encoding (UTF-16 byte order mark)');
  }
  const head = buffer.subarray(utf8Bom ? 3 : 0, DECLARATION_LIMIT + 8).toString('latin1');
  if (!hasDeclarationOpening(head)) return 'utf-8';
  if (!head.includes('?>')) throw new StructuralError('unterminated XML declaration');
  // This reader implements XML 1.0 only. XML 1.1 is rejected because it changes
  // the whitespace and line-separator rules that the lexical scanner relies on.
  const version = /^<\?xml\s+version\s*=\s*["']([^"']+)["']/i.exec(head)?.[1]?.trim();
  if (version !== undefined && version !== '1.0') {
    throw new StructuralError(`unsupported XML version ${version} (only 1.0 is supported)`);
  }
  const declared = /^<\?xml[^>]*encoding\s*=\s*["']([^"']+)["']/i.exec(head)?.[1]?.trim().toLowerCase();
  if (declared === undefined) return 'utf-8';
  if (declared === 'utf-8' || declared === 'utf8') return 'utf-8';
  if (declared === 'us-ascii' || declared === 'ascii') return 'ascii';
  if (declared === 'iso-8859-1' || declared === 'latin1') {
    if (utf8Bom) throw new StructuralError('the byte order mark conflicts with the declared encoding');
    return 'latin1';
  }
  throw new StructuralError(`unsupported XML encoding ${declared}`);
}

interface Decoder {
  decode(bytes: Buffer): string;
  flush(): string;
}

function makeDecoder(encoding: Encoding): Decoder {
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
        if (error instanceof ResourceLimit || error instanceof StructuralError) throw error;
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
        throw error instanceof StructuralError ? error : new StructuralError('invalid text encoding');
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
