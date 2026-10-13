import type { ScopedId } from '../types.js';
import { parseStrictXml, type XmlLimits } from './xml.js';

/**
 * A focused, bounded reader for the Standard Business Document Header. It reads
 * only the fields the AS4 headers must agree with and never models the business
 * document. Bounded by `limits` (byte cap and node budget) because the payload is
 * attacker-controlled.
 */
export interface SbdhFacts {
  readonly senderIdentifier: string | null;
  readonly receiverIdentifier: string | null;
  readonly scopeType: string | null;
  readonly documentType: string | null;
}

function byLocalName(node: Document | Element, name: string): Element[] {
  const out: Element[] = [];
  const all = node.getElementsByTagName('*');
  for (let i = 0; i < all.length; i += 1) {
    const element = all.item(i);
    if (element && element.localName === name) out.push(element);
  }
  return out;
}

function childText(parent: Element | null, localName: string): string | null {
  const children = parent?.childNodes;
  if (!children) return null;
  for (let i = 0; i < children.length; i += 1) {
    const child = children.item(i);
    if (!child || child.nodeType !== 1) continue;
    const element = child as Element;
    if (element.localName === localName) return element.textContent ?? null;
  }
  return null;
}

export function parseSbdh(bytes: Buffer, limits: XmlLimits): SbdhFacts {
  const document = parseStrictXml(bytes, limits);
  const sender = byLocalName(document, 'Sender')[0] ?? null;
  const receiver = byLocalName(document, 'Receiver')[0] ?? null;
  return {
    senderIdentifier: childText(sender, 'Identifier'),
    receiverIdentifier: childText(receiver, 'Identifier'),
    scopeType: scopeType(document),
    documentType: childText(byLocalName(document, 'DocumentIdentification')[0] ?? null, 'Type'),
  };
}

function scopeType(document: Document): string | null {
  const businessScope = byLocalName(document, 'BusinessScope')[0];
  if (!businessScope) return null;
  const scopes: Element[] = [];
  const all = businessScope.getElementsByTagName('*');
  for (let i = 0; i < all.length; i += 1) {
    const element = all.item(i);
    if (element && element.localName === 'Scope') scopes.push(element);
  }
  return scopes[0] ? childText(scopes[0], 'Type') : null;
}

/**
 * Compare the AS4 header facts with the SBDH facts, returning explicit
 * inconsistencies. Absent SBDH fields are not reported (the reader may not apply
 * to every document type). Comparison is exact on trimmed text; scheme-aware
 * normalisation is a documented open question.
 */
export function compareSbdh(
  facts: SbdhFacts,
  expected: {
    readonly originalSender: string;
    readonly finalRecipient: string;
    readonly process: string;
    readonly documentType: string;
  },
): string[] {
  const mismatches: string[] = [];
  if (facts.senderIdentifier !== null && facts.senderIdentifier !== expected.originalSender) {
    mismatches.push(`originalSender ${expected.originalSender} != SBDH Sender ${facts.senderIdentifier}`);
  }
  if (facts.receiverIdentifier !== null && facts.receiverIdentifier !== expected.finalRecipient) {
    mismatches.push(`finalRecipient ${expected.finalRecipient} != SBDH Receiver ${facts.receiverIdentifier}`);
  }
  if (facts.scopeType !== null && facts.scopeType !== expected.process) {
    mismatches.push(`process ${expected.process} != SBDH Scope Type ${facts.scopeType}`);
  }
  if (facts.documentType !== null && facts.documentType !== expected.documentType) {
    mismatches.push(`documentType ${expected.documentType} != SBDH DocumentIdentification Type ${facts.documentType}`);
  }
  return mismatches;
}

/** The document type encoded in an eb:Action (`scheme::value`). */
export function documentTypeFromAction(action: string): ScopedId | null {
  const separator = action.indexOf('::');
  if (separator < 0) return null;
  return { scheme: action.slice(0, separator), value: action.slice(separator + 2) };
}
