import type { ScopedId } from '../types.js';

/**
 * Shared SBDH facts and comparison (SBDH §2.4). The document is inspected
 * incrementally by `src/receive/sbdh-stream.ts`, which retains only these facts
 * and compares them with {@link compareFacts}; the process and document
 * identifiers live in `Scope/InstanceIdentifier` with their schemes in
 * `Scope/Identifier`, selected by `Scope/Type` = `PROCESSID` / `DOCUMENTID`.
 */
export const SBDH_NS = 'http://www.unece.org/cefact/namespaces/StandardBusinessDocumentHeader';
/** Default schemes the SBDH specifies for the standard scope types (UNVERIFIED). */
export const DEFAULT_PARTY_SCHEME = 'iso6523-actorid-upis';
export const DEFAULT_SCOPE_SCHEME: Readonly<Record<string, string>> = {
  PROCESSID: 'cenbii-procid-ubl',
  DOCUMENTID: 'busdox-docid-qns',
};

export interface SbdhFacts {
  readonly sender: ScopedId | null;
  readonly receiver: ScopedId | null;
  readonly process: ScopedId | null;
  readonly documentType: ScopedId | null;
}

/** The facts an SBDH is compared against. */
export interface SbdhExpected {
  readonly originalSender: ScopedId;
  readonly finalRecipient: ScopedId;
  readonly process: ScopedId;
  readonly documentType: ScopedId | null;
}

function compareScoped(what: string, actual: ScopedId, expected: ScopedId): string[] {
  const out: string[] = [];
  if (actual.value !== expected.value) out.push(`${what} ${expected.value} != SBDH ${actual.value}`);
  if (expected.scheme !== '' && actual.scheme !== expected.scheme) {
    out.push(`${what} scheme ${expected.scheme} != SBDH ${actual.scheme}`);
  }
  return out;
}

/** Every required comparison must be possible; a missing field is not a match. */
export function compareFacts(facts: SbdhFacts, expected: SbdhExpected): string[] {
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
  return mismatches;
}

/** The document type encoded in an eb:Action (`scheme::value`). */
export function documentTypeFromAction(action: string): ScopedId | null {
  const separator = action.indexOf('::');
  if (separator < 0) return null;
  return { scheme: action.slice(0, separator), value: action.slice(separator + 2) };
}
