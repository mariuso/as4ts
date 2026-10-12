import { EBMS_NS, WSU_NS } from '../constants.js';
import { attrOf, elementsByLocalName, firstByLocalName, parseXml, textOf } from './nodes.js';

export interface ParsedEbmsError {
  readonly code: string;
  readonly severity: string;
  readonly category: string | null;
  readonly shortDescription: string | null;
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
 * takes. A response that is not a single, unambiguous signal returns null.
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

  const messagingElements = elementsByLocalName(document, EBMS_NS, 'Messaging');
  if (messagingElements.length !== 1) return null;
  const messagingElement = messagingElements[0]!;

  const signalMessages = elementsByLocalName(messagingElement, EBMS_NS, 'SignalMessage');
  const userMessages = elementsByLocalName(messagingElement, EBMS_NS, 'UserMessage');
  if (signalMessages.length + userMessages.length !== 1) return null;
  const signalMessage = signalMessages[0] ?? null;
  const userMessage = userMessages[0] ?? null;
  const signalElement: Element = signalMessage ?? userMessage!;

  // A SignalMessage carries at most one Receipt or one Error (multiple Error
  // elements within one message are allowed, but not a sibling Receipt).
  if (signalMessage) {
    const receipts = elementsByLocalName(signalMessage, EBMS_NS, 'Receipt');
    if (receipts.length > 1) return null;
  }

  const messageInfo = firstByLocalName(signalElement, EBMS_NS, 'MessageInfo');
  const errorElements = elementsByLocalName(signalElement, EBMS_NS, 'Error');
  const errors: ParsedEbmsError[] = errorElements.map((e) => ({
    code: attrOf(e, 'errorCode') ?? attrOf(e, 'code') ?? '',
    severity: attrOf(e, 'severity') ?? '',
    category: attrOf(e, 'category'),
    shortDescription: textOf(firstByLocalName(e, EBMS_NS, 'Description')),
    detail: textOf(firstByLocalName(e, EBMS_NS, 'ErrorDetail')),
  }));

  const hasReceipt = firstByLocalName(signalElement, EBMS_NS, 'Receipt') !== null;

  let kind: ParsedSignal['kind'];
  if (hasReceipt && errors.length === 0) kind = 'receipt';
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
