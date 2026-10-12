import { EBMS_NS, SOAP_11_NS, SOAP_ENV_NS, WSU_NS } from '../constants.js';
import { attrOf, firstByLocalName, parseXml, textOf } from './nodes.js';

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
 * Parse a received signal message. This is pure parsing; it makes no trust
 * decision — but it is strict about shape, because a response with more than one
 * eb:Messaging or SignalMessage is exactly the shape a forged-receipt attack
 * takes, and reading facts from elements outside the expected structure is how
 * such an attack succeeds. The envelope must be SOAP 1.1 or 1.2 with exactly one
 * Header and Body; Messaging must be a direct child of Header; SignalMessage or
 * UserMessage a direct child of Messaging. A response that is not a single,
 * unambiguous signal returns null.
 */
export function parseSignal(envelopeBytes: Buffer): ParsedSignal | null {
  let document: Document;
  try {
    document = parseXml(envelopeBytes);
  } catch {
    return null;
  }
  const envelope = document.documentElement;
  if (!envelope || envelope.localName !== 'Envelope') return null;
  const soapNs = envelope.namespaceURI;
  if (!soapNs || !SUPPORTED_SOAP_NAMESPACES.has(soapNs)) return null;

  const headers = directChildren(envelope, soapNs, 'Header');
  const bodies = directChildren(envelope, soapNs, 'Body');
  if (headers.length !== 1 || bodies.length !== 1) return null;

  const messagingElements = directChildren(headers[0]!, EBMS_NS, 'Messaging');
  if (messagingElements.length !== 1) return null;
  const messagingElement = messagingElements[0]!;

  const signalMessages = directChildren(messagingElement, EBMS_NS, 'SignalMessage');
  const userMessages = directChildren(messagingElement, EBMS_NS, 'UserMessage');
  if (signalMessages.length + userMessages.length !== 1) return null;
  const signalMessage = signalMessages[0] ?? null;
  const userMessage = userMessages[0] ?? null;
  const signalElement: Element = signalMessage ?? userMessage!;

  const errorElements = directChildren(signalElement, EBMS_NS, 'Error');
  const receipts = directChildren(signalElement, EBMS_NS, 'Receipt');
  // A SignalMessage carries either a single Receipt or one or more Errors, never
  // both and never more than one Receipt.
  if (receipts.length > 1) return null;
  if (receipts.length === 1 && errorElements.length > 0) return null;

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
