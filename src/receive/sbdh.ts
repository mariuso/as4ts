import type { ScopedId } from '../types.js';
import type { SbdhConsistency } from './types.js';
import { parseStrictXml, XmlFault, type XmlLimits } from './xml.js';

/**
 * A focused, bounded reader for the Standard Business Document Header (SBDH
 * §2.4). The process and document identifiers live in `Scope/InstanceIdentifier`
 * and their schemes in `Scope/Identifier`, selected by `Scope/Type` =
 * `PROCESSID` / `DOCUMENTID`; `DocumentIdentification/Type` is only the document
 * type name. Paths are rooted at `StandardBusinessDocumentHeader`.
 */
export interface SbdhFacts {
  readonly sender: ScopedId | null;
  readonly receiver: ScopedId | null;
  readonly process: ScopedId | null;
  readonly documentType: ScopedId | null;
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

function directByLocalName(parent: Element | null, name: string): Element[] {
  const out: Element[] = [];
  const children = parent?.childNodes;
  if (!children) return out;
  for (let i = 0; i < children.length; i += 1) {
    const child = children.item(i);
    if (!child || child.nodeType !== 1) continue;
    const element = child as Element;
    if (element.localName === name) out.push(element);
  }
  return out;
}

function directText(parent: Element | null, name: string): string | null {
  const element = directByLocalName(parent, name)[0];
  const value = element?.textContent;
  return value === null || value === undefined || value === '' ? null : value.trim();
}

function participant(header: Element, role: 'Sender' | 'Receiver'): ScopedId | null {
  const container = directByLocalName(header, role)[0] ?? null;
  const identifier = directByLocalName(container, 'Identifier')[0] ?? null;
  const value = identifier?.textContent?.trim();
  if (!value) return null;
  return { scheme: identifier?.getAttribute('Authority') ?? '', value };
}

/** A Scope's Type/InstanceIdentifier/Identifier as a scheme/value pair. */
function scopeByType(header: Element, type: string): ScopedId | null {
  const businessScope = directByLocalName(header, 'BusinessScope')[0] ?? null;
  for (const scope of directByLocalName(businessScope, 'Scope')) {
    if ((directText(scope, 'Type') ?? '').toUpperCase() !== type) continue;
    const value = directText(scope, 'InstanceIdentifier');
    if (!value) return null;
    return { scheme: directText(scope, 'Identifier') ?? '', value };
  }
  return null;
}

/** Read the SBDH facts, or null when there is no SBDH header at all. */
export function readSbdh(document: Document): SbdhFacts | null {
  const header = byLocalName(document, 'StandardBusinessDocumentHeader')[0];
  if (!header) return null;
  return {
    sender: participant(header, 'Sender'),
    receiver: participant(header, 'Receiver'),
    process: scopeByType(header, 'PROCESSID'),
    documentType: scopeByType(header, 'DOCUMENTID'),
  };
}

function compareScoped(what: string, actual: ScopedId | null, expected: ScopedId): string[] {
  if (actual === null) return [];
  const out: string[] = [];
  if (actual.value !== expected.value) out.push(`${what} ${expected.value} != SBDH ${actual.value}`);
  if (actual.scheme !== '' && expected.scheme !== '' && actual.scheme !== expected.scheme) {
    out.push(`${what} scheme ${expected.scheme} != SBDH ${actual.scheme}`);
  }
  return out;
}

export function compareSbdh(
  facts: SbdhFacts,
  expected: {
    readonly originalSender: ScopedId;
    readonly finalRecipient: ScopedId;
    readonly process: ScopedId;
    readonly documentType: ScopedId | null;
  },
): string[] {
  const mismatches = [
    ...compareScoped('originalSender', facts.sender, expected.originalSender),
    ...compareScoped('finalRecipient', facts.receiver, expected.finalRecipient),
    ...compareScoped('process', facts.process, expected.process),
  ];
  if (expected.documentType) {
    mismatches.push(...compareScoped('documentType', facts.documentType, expected.documentType));
  }
  return mismatches;
}

/** Parse and compare the SBDH, returning a distinct consistency status. */
export function checkSbdh(
  bytes: Buffer,
  limits: XmlLimits,
  expected: {
    readonly originalSender: ScopedId;
    readonly finalRecipient: ScopedId;
    readonly process: ScopedId;
    readonly documentType: ScopedId | null;
  },
): SbdhConsistency {
  let document: Document;
  try {
    document = parseStrictXml(bytes, limits);
  } catch (err) {
    if (err instanceof XmlFault) {
      if (err.reason === 'xml.too-large') return { status: 'too-large' };
      return { status: 'malformed', detail: err.message };
    }
    throw err;
  }
  const facts = readSbdh(document);
  if (!facts) return { status: 'missing' };
  const mismatches = compareSbdh(facts, expected);
  return mismatches.length > 0 ? { status: 'inconsistent', mismatches } : { status: 'consistent' };
}

/** The document type encoded in an eb:Action (`scheme::value`). */
export function documentTypeFromAction(action: string): ScopedId | null {
  const separator = action.indexOf('::');
  if (separator < 0) return null;
  return { scheme: action.slice(0, separator), value: action.slice(separator + 2) };
}
