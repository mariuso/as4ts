/**
 * Classifier entry point.
 *
 * `sendAs4` returns facts; this maps a fact to the action a caller should take.
 * It is pure and has no I/O, no network and no key material.
 */
export { classify, classifyEbmsError, DEFAULT_CLASSIFY_TABLE, EBMS_ERROR_TABLE } from './outcome.js';
export type { ClassifyTable, EbmsErrorInput, OutcomeClass } from './outcome.js';
export type {
  EbmsErrorEvidence,
  ErrorSignalResult,
  NoSignalResult,
  NotSentReason,
  NotSentResult,
  ReceiptFailureReason,
  ReceiptUnverifiedResult,
  ReceiptVerifiedResult,
  SendAs4Result,
  TransportFailureResult,
} from './types.js';
