import type { ScopedId } from '../types.js';
import type { SbdhConsistency } from './types.js';
import { parseStrictXml, XmlFault, type XmlLimits } from './xml.js';

/**
 * A focused, bounded reader for the Standard Business Document Header (SBDH
 * §2.4). Paths are rooted at a `StandardBusinessDocument` in the Peppol SBDH
 * namespace with a direct `StandardBusinessDocumentHeader` child; the process and
 * document identifiers live in `Scope/InstanceIdentifier` and their schemes in
 * `Scope/Identifier`, selected by `Scope/Type` = `PROCESSID` / `DOCUMENTID`.
 * Duplicate required fields are a structural error, and the specified default
 * schemes are applied before comparison.
 */
const SBDH_NS = 'http://www.unece.org/cefact/namespaces/StandardBusinessDocumentHeader';
/** Default schemes the SBDH specifies for the standard scope types (UNVERIFIED). */
const DEFAULT_PARTY_SCHEME = 'iso6523-actorid-upis';
const DEFAULT_SCOPE_SCHEME: Readonly<Record<string, string>> = {
  PROCESSID: 'cenbii-procid-ubl',
  DOCUMENTID: 'busdox-docid-qns',
};

class SbdhStructureError extends Error {}

export interface SbdhFacts {
  readonly sender: ScopedId | null;
  readonly receiver: ScopedId | null;
  readonly process: ScopedId | null;
  readonly documentType: ScopedId | null;
}

function directChildrenNs(parent: Element | null, ns: string, localName: string): Element[] {
  const out: Element[] = [];
  const children = parent?.childNodes;
  if (!children) return out;
  for (let i = 0; i < children.length; i += 1) {
    const child = children.item(i);
    if (!child || child.nodeType !== 1) continue;
    const element = child as Element;
    if (element.namespaceURI === ns && element.localName === localName) out.push(element);
  }
  return out;
}

function exactlyOne(parent: Element | null, ns: string, localName: string, what: string): Element | null {
  const matches = directChildrenNs(parent, ns, localName);
  if (matches.length > 1) throw new SbdhStructureError(`more than one ${what}`);
  return matches[0] ?? null;
}

function text(element: Element | null): string | null {
  const value = element?.textContent?.trim();
  return value === null || value === undefined || value === '' ? null : value;
}

function participant(header: Element, role: 'Sender' | 'Receiver'): ScopedId | null {
  const container = exactlyOne(header, SBDH_NS, role, role);
  if (!container) return null;
  const identifier = exactlyOne(container, SBDH_NS, 'Identifier', `${role}/Identifier`);
  const value = text(identifier);
  if (value === null) return null;
  const authority = identifier?.getAttribute('Authority');
  return { scheme: authority ? authority : DEFAULT_PARTY_SCHEME, value };
}

function scopeByType(header: Element, type: string): ScopedId | null {
  const businessScope = exactlyOne(header, SBDH_NS, 'BusinessScope', 'BusinessScope');
  if (!businessScope) return null;
  const matches = directChildrenNs(businessScope, SBDH_NS, 'Scope').filter(
    (scope) => (text(exactlyOne(scope, SBDH_NS, 'Type', 'Scope/Type')) ?? '').toUpperCase() === type,
  );
  if (matches.length > 1) throw new SbdhStructureError(`more than one ${type} Scope`);
  const scope = matches[0];
  if (!scope) return null;
  const value = text(exactlyOne(scope, SBDH_NS, 'InstanceIdentifier', 'Scope/InstanceIdentifier'));
  if (value === null) return null;
  const scheme = text(exactlyOne(scope, SBDH_NS, 'Identifier', 'Scope/Identifier')) ?? DEFAULT_SCOPE_SCHEME[type] ?? '';
  return { scheme, value };
}

/** Read the SBDH facts, or null when there is no proper SBDH header at the expected position. */
export function readSbdh(document: Document): SbdhFacts | null {
  const root = document.documentElement;
  if (!root || root.localName !== 'StandardBusinessDocument' || root.namespaceURI !== SBDH_NS) return null;
  const header = exactlyOne(root, SBDH_NS, 'StandardBusinessDocumentHeader', 'StandardBusinessDocumentHeader');
  if (!header) return null;
  return {
    sender: participant(header, 'Sender'),
    receiver: participant(header, 'Receiver'),
    process: scopeByType(header, 'PROCESSID'),
    documentType: scopeByType(header, 'DOCUMENTID'),
  };
}

function compareScoped(what: string, actual: ScopedId, expected: ScopedId): string[] {
  const out: string[] = [];
  if (actual.value !== expected.value) out.push(`${what} ${expected.value} != SBDH ${actual.value}`);
  if (expected.scheme !== '' && actual.scheme !== expected.scheme) {
    out.push(`${what} scheme ${expected.scheme} != SBDH ${actual.scheme}`);
  }
  return out;
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
      // Byte, node and depth exhaustion are resource limits, not malformed XML.
      // Preserve the reason so the caller can tell them apart.
      if (err.reason === 'xml.too-large' || err.reason === 'xml.too-many-nodes' || err.reason === 'xml.too-deep') {
        return { status: 'resource-limit', reason: err.reason };
      }
      return { status: 'malformed', detail: err.message };
    }
    throw err;
  }

  let facts: SbdhFacts | null;
  try {
    facts = readSbdh(document);
  } catch (err) {
    if (err instanceof SbdhStructureError) return { status: 'malformed', detail: err.message };
    throw err;
  }
  if (!facts) return { status: 'missing' };

  // Every required comparison must be possible; a missing field is not a match.
  const mismatches: string[] = [];
  if (!facts.sender) mismatches.push('SBDH Sender identifier is missing');
  else mismatches.push(...compareScoped('originalSender', facts.sender, expected.originalSender));
  if (!facts.receiver) mismatches.push('SBDH Receiver identifier is missing');
  else mismatches.push(...compareScoped('finalRecipient', facts.receiver, expected.finalRecipient));
  if (!facts.process) mismatches.push('SBDH PROCESSID scope is missing');
  else mismatches.push(...compareScoped('process', facts.process, expected.process));
  if (expected.documentType) {
    if (!facts.documentType) mismatches.push('SBDH DOCUMENTID scope is missing');
    else mismatches.push(...compareScoped('documentType', facts.documentType, expected.documentType));
  }

  return mismatches.length > 0 ? { status: 'inconsistent', mismatches } : { status: 'consistent' };
}

/** The document type encoded in an eb:Action (`scheme::value`). */
export function documentTypeFromAction(action: string): ScopedId | null {
  const separator = action.indexOf('::');
  if (separator < 0) return null;
  return { scheme: action.slice(0, separator), value: action.slice(separator + 2) };
}
