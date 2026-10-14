import { EBMS_NS, SOAP_11_NS, SOAP_ENV_NS, WSU_NS } from '../constants.js';
import { defaultResponseLimits, type ResponseLimits } from '../response-limits.js';
import { attrOf, firstByLocalName, textOf } from './nodes.js';
import { XmlFault, parseStrictXml, type XmlFaultReason } from './strict.js';

/** Bounds applied to the MIME wrapper before the SOAP part is parsed. */
const MAX_MIME_PARTS = 32;
const MAX_MIME_HEADER_BYTES = 16 * 1024;

export interface ParsedEbmsError {
  readonly code: string;
  readonly severity: string;
  readonly category: string | null;
  /** `eb:Error/@shortDescription`, when present. */
  readonly shortDescription: string | null;
  /** The human-readable `eb:Description` child text, when present. */
  readonly description: string | null;
  readonly detail: string | null;
}

export interface ParsedSignal {
  readonly kind: 'receipt' | 'error' | 'user-message' | 'unrecognized';
  /** Raw SOAP envelope bytes exactly as received (MIME wrapper removed). */
  readonly raw: Buffer;
  readonly document: Document;
  /** The single eb:SignalMessage or eb:UserMessage we read. */
  readonly signalElement: Element;
  /** The eb:Messaging element holding it. */
  readonly messagingElement: Element;
  /** wsu:Id / id of the Messaging element, used to bind the signature. */
  readonly messagingId: string | null;
  /** Id of the SignalMessage/UserMessage, if any. */
  readonly signalId: string | null;
  readonly messageId: string | null;
  readonly refToMessageId: string | null;
  readonly timestamp: string | null;
  readonly errors: readonly ParsedEbmsError[];
}

/**
 * Why a response could not be read as a signal. `signal.shape` is the "valid XML
 * but not a single unambiguous signal" case; the rest are strict-parser reasons
 * (`xml.malformed`, `xml.doctype`, `xml.too-large`, ...). The value is
 * secret-free and never echoes response content.
 */
export type ParseSignalReason = XmlFaultReason | 'signal.shape';

export type ParseSignalResult =
  { readonly ok: true; readonly signal: ParsedSignal } | { readonly ok: false; readonly reason: ParseSignalReason };

/** Choose the SOAP envelope out of a `multipart/related` or plain response. */
export function extractSoapEnvelope(contentType: string | undefined, body: Buffer): Buffer | null {
  const mediaType = (contentType ?? '').split(';')[0]?.trim().toLowerCase() ?? '';
  if (mediaType === 'multipart/related' || mediaType === 'multipart/mixed') {
    return extractFromMultipart(contentType ?? '', body);
  }
  return body.length > 0 ? body : null;
}

function extractFromMultipart(contentType: string, body: Buffer): Buffer | null {
  const boundaryMatch = /boundary\s*=\s*"?([^";]+)"?/i.exec(contentType);
  if (!boundaryMatch?.[1]) return null;
  const boundary = boundaryMatch[1];
  const marker = Buffer.from(`--${boundary}`);
  const text = body;

  const positions: number[] = [];
  let from = 0;
  for (;;) {
    const idx = text.indexOf(marker, from);
    if (idx < 0) break;
    positions.push(idx);
    from = idx + marker.byteLength;
  }
  if (positions.length < 2) return null;
  if (positions.length > MAX_MIME_PARTS + 1) return null;

  const parts: Buffer[] = [];
  for (let i = 0; i < positions.length; i += 1) {
    const start = positions[i]! + marker.byteLength;
    const end = i + 1 < positions.length ? positions[i + 1]! : text.byteLength;
    parts.push(text.subarray(start, end));
  }

  for (const part of parts) {
    const headerEnd = part.indexOf('\r\n\r\n');
    const sepLen = 4;
    if (headerEnd < 0) continue;
    if (headerEnd > MAX_MIME_HEADER_BYTES) return null;
    const headerText = part.subarray(0, headerEnd).toString('latin1');
    let content = part.subarray(headerEnd + sepLen);
    if (content.length >= 2 && content[content.length - 2] === 0x0d && content[content.length - 1] === 0x0a) {
      content = content.subarray(0, content.length - 2);
    }
    if (/application\/soap\+xml|text\/xml|application\/xml/i.test(headerText)) {
      if (/base64/i.test(headerText)) return Buffer.from(content.toString('latin1').replace(/\s+/g, ''), 'base64');
      return Buffer.from(content);
    }
  }
  return null;
}

/**
 * Parse a received signal message under the shared strict parser. This is pure
 * parsing; it makes no trust decision — but it is strict about both bytes and
 * shape, because a response with more than one eb:Messaging or SignalMessage is
 * exactly the shape a forged-receipt attack takes, and reading facts from
 * elements outside the expected structure is how such an attack succeeds.
 *
 * The bytes are validated (encoding, DOCTYPE, size, depth, nodes, attributes,
 * tokens) *before* any DOM is built: a malformed, encoding-mismatched,
 * DOCTYPE-bearing or over-limit response is never repaired. The envelope must be
 * SOAP 1.1 or 1.2 with exactly one Header and Body; Messaging must be a direct
 * child of Header; SignalMessage or UserMessage a direct child of Messaging.
 */
export function parseSignal(envelopeBytes: Buffer, limits: ResponseLimits = defaultResponseLimits): ParseSignalResult {
  let document: Document;
  try {
    document = parseStrictXml(envelopeBytes, {
      maxBytes: limits.maxXmlBytes,
      maxDepth: limits.maxDepth,
      maxNodes: limits.maxNodes,
      maxAttributes: limits.maxAttributes,
      maxTokenBytes: limits.maxTokenBytes,
    });
  } catch (error) {
    if (error instanceof XmlFault) return { ok: false, reason: error.reason };
    throw error;
  }

  const shape: ParseSignalResult = { ok: false, reason: 'signal.shape' };
  const envelope = document.documentElement;
  if (!envelope || envelope.localName !== 'Envelope') return shape;
  const soapNs = envelope.namespaceURI;
  if (!soapNs || !SUPPORTED_SOAP_NAMESPACES.has(soapNs)) return shape;

  const headers = directChildren(envelope, soapNs, 'Header');
  const bodies = directChildren(envelope, soapNs, 'Body');
  if (headers.length !== 1 || bodies.length !== 1) return shape;

  const messagingElements = directChildren(headers[0]!, EBMS_NS, 'Messaging');
  if (messagingElements.length !== 1) return shape;
  const messagingElement = messagingElements[0]!;

  const signalMessages = directChildren(messagingElement, EBMS_NS, 'SignalMessage');
  const userMessages = directChildren(messagingElement, EBMS_NS, 'UserMessage');
  if (signalMessages.length + userMessages.length !== 1) return shape;
  const signalMessage = signalMessages[0] ?? null;
  const userMessage = userMessages[0] ?? null;
  const signalElement: Element = signalMessage ?? userMessage!;

  const errorElements = directChildren(signalElement, EBMS_NS, 'Error');
  const receipts = directChildren(signalElement, EBMS_NS, 'Receipt');
  // A SignalMessage carries either a single Receipt or one or more Errors, never
  // both and never more than one Receipt.
  if (receipts.length > 1) return shape;
  if (receipts.length === 1 && errorElements.length > 0) return shape;

  const messageInfo = directChildren(signalElement, EBMS_NS, 'MessageInfo')[0] ?? null;
  const errors: ParsedEbmsError[] = errorElements.map((e) => ({
    code: attrOf(e, 'errorCode') ?? attrOf(e, 'code') ?? '',
    severity: attrOf(e, 'severity') ?? '',
    category: attrOf(e, 'category'),
    shortDescription: attrOf(e, 'shortDescription'),
    description: textOf(firstByLocalName(e, EBMS_NS, 'Description')),
    detail: textOf(firstByLocalName(e, EBMS_NS, 'ErrorDetail')),
  }));

  let kind: ParsedSignal['kind'];
  if (receipts.length === 1) kind = 'receipt';
  else if (errors.length > 0) kind = 'error';
  else if (userMessage) kind = 'user-message';
  else kind = 'unrecognized';

  return {
    ok: true,
    signal: {
      kind,
      raw: envelopeBytes,
      document,
      signalElement,
      messagingElement,
      messagingId:
        attrOf(messagingElement, 'Id', WSU_NS) ?? attrOf(messagingElement, 'Id') ?? attrOf(messagingElement, 'id'),
      signalId: attrOf(signalElement, 'Id') ?? attrOf(signalElement, 'id'),
      messageId: textOf(firstByLocalName(messageInfo, EBMS_NS, 'MessageId')),
      refToMessageId: textOf(firstByLocalName(messageInfo, EBMS_NS, 'RefToMessageId')),
      timestamp: textOf(firstByLocalName(messageInfo, EBMS_NS, 'Timestamp')),
      errors,
    },
  };
}

/** SOAP versions whose envelopes this parser accepts. */
const SUPPORTED_SOAP_NAMESPACES: ReadonlySet<string> = new Set([SOAP_ENV_NS, SOAP_11_NS]);

/** Direct element children with the given namespace and local name. */
function directChildren(node: Node, ns: string, localName: string): Element[] {
  const out: Element[] = [];
  const children = node.childNodes;
  for (let i = 0; i < children.length; i += 1) {
    const child = children.item(i);
    if (!child || child.nodeType !== 1) continue;
    const element = child as Element;
    if (element.namespaceURI === ns && element.localName === localName) out.push(element);
  }
  return out;
}
