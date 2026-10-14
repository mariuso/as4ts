/**
 * Shared XML lexical and encoding protection for the receiving path (Item 4).
 *
 * Both the streaming SBDH inspector and the bounded DOM preflight need the same
 * guarantees: XML 1.0 only, strict UTF-8 (including finalisation), an explicit
 * supported-encoding list, BOM/declaration agreement, actual ASCII enforcement,
 * a complete bounded XML declaration, and a lexical guard that bounds every
 * token before a SAX parser can accumulate it. This module is the single
 * implementation of those rules so the two paths cannot drift.
 */

/** How many bytes of a document may be buffered to read the XML declaration. */
export const DECLARATION_LIMIT = 1024;

/**
 * A lexical or decoding fault. `kind` distinguishes the three failure classes so
 * a caller can map them to its own reasons without string matching.
 */
export type XmlLexicalKind = 'decode' | 'doctype' | 'token';

export class XmlLexicalFault extends Error {
  constructor(
    readonly kind: XmlLexicalKind,
    message: string,
  ) {
    super(message);
    this.name = 'XmlLexicalFault';
  }
}

export type Encoding = 'utf-8' | 'latin1' | 'ascii';

export function hasUtf8Bom(buffer: Buffer): boolean {
  return buffer.length >= 3 && buffer[0] === 0xef && buffer[1] === 0xbb && buffer[2] === 0xbf;
}

export function hasUtf16Bom(buffer: Buffer): boolean {
  return (
    buffer.length >= 2 && ((buffer[0] === 0xff && buffer[1] === 0xfe) || (buffer[0] === 0xfe && buffer[1] === 0xff))
  );
}

export type DeclarationStatus = 'pending' | 'absent' | 'complete' | 'too-long';

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
 * start at the very first byte, so leading whitespace means "absent".
 */
export function inspectDeclaration(buffer: Buffer): DeclarationStatus {
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

/** Decide the encoding, or throw for an unsupported/conflicting declaration. */
export function detectEncoding(buffer: Buffer): Encoding {
  const utf8Bom = hasUtf8Bom(buffer);
  if (!utf8Bom && hasUtf16Bom(buffer)) {
    throw new XmlLexicalFault('decode', 'unsupported XML encoding (UTF-16 byte order mark)');
  }
  const head = buffer.subarray(utf8Bom ? 3 : 0, DECLARATION_LIMIT + 8).toString('latin1');
  if (!hasDeclarationOpening(head)) return 'utf-8';
  if (!head.includes('?>')) throw new XmlLexicalFault('decode', 'unterminated XML declaration');
  // Only XML 1.0 is supported. XML 1.1 changes the whitespace and line-separator
  // rules that the lexical scanner relies on, so it is rejected rather than
  // silently mis-scanned.
  const version = /^<\?xml\s+version\s*=\s*["']([^"']+)["']/i.exec(head)?.[1]?.trim();
  if (version !== undefined && version !== '1.0') {
    throw new XmlLexicalFault('decode', `unsupported XML version ${version} (only 1.0 is supported)`);
  }
  const declared = /^<\?xml[^>]*encoding\s*=\s*["']([^"']+)["']/i.exec(head)?.[1]?.trim().toLowerCase();
  if (declared === undefined) return 'utf-8';
  if (declared === 'utf-8' || declared === 'utf8') return 'utf-8';
  if (declared === 'us-ascii' || declared === 'ascii') return 'ascii';
  if (declared === 'iso-8859-1' || declared === 'latin1') {
    if (utf8Bom) throw new XmlLexicalFault('decode', 'the byte order mark conflicts with the declared encoding');
    return 'latin1';
  }
  throw new XmlLexicalFault('decode', `unsupported XML encoding ${declared}`);
}

export interface Decoder {
  decode(bytes: Buffer): string;
  flush(): string;
}

export function makeDecoder(encoding: Encoding): Decoder {
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
        for (const byte of bytes) {
          if (byte > 0x7f) throw new XmlLexicalFault('decode', 'non-ASCII byte in an ASCII document');
        }
        return bytes.toString('latin1');
      },
      flush: () => '',
    };
  }
  return { decode: (bytes) => bytes.toString('latin1'), flush: () => '' };
}

/**
 * Decode a complete in-memory XML document under the shared policy. The returned
 * text is exactly what both the preflight and the DOM parser must consume, so the
 * two never decode with different assumptions.
 */
export function decodeXmlDocument(bytes: Buffer): string {
  if (hasUtf16Bom(bytes)) {
    throw new XmlLexicalFault('decode', 'unsupported XML encoding (UTF-16 byte order mark)');
  }
  const encoding = detectEncoding(bytes);
  const decoder = makeDecoder(encoding);
  try {
    const text = decoder.decode(bytes);
    const tail = decoder.flush();
    return tail.length > 0 ? text + tail : text;
  } catch (error) {
    if (error instanceof XmlLexicalFault) throw error;
    throw new XmlLexicalFault('decode', 'invalid text encoding');
  }
}

/** UTF-8 byte length of a single code point. */
export function codePointBytes(code: number): number {
  if (code < 0x80) return 1;
  if (code < 0x800) return 2;
  if (code < 0x10000) return 3;
  return 4;
}

type LexicalState = 'text' | 'markup' | 'element' | 'comment' | 'cdata' | 'pi' | 'declaration';

export interface TagEvent {
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
 * opening is recognised, before a SAX parser can accumulate its internal subset.
 * Element tags are reported with their exact byte span so a caller can account
 * for a specific element without buffering document text.
 */
export class LexicalGuard {
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
      if (this.bytes > this.maxBytes) throw new XmlLexicalFault('token', 'lexical token exceeds the byte limit');
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
          // event stream; mirror that so an ordered association stays aligned.
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
      if (opener === '<!DOCTYPE') throw new XmlLexicalFault('doctype', 'DOCTYPE is not accepted');
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
