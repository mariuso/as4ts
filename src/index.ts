import { defaultEntropy } from './entropy.js';
import { sendAs4Internal } from './send.js';
import type { SendAs4Input, SendAs4Result } from './types.js';

export { signerFromKey } from './signer.js';
export { peppolProfile } from './profile.js';

export type {
  CertificatePurpose,
  CertificateValidation,
  CertificateValidationInput,
  EbmsErrorEvidence,
  ErrorCorrelation,
  ErrorSignalResult,
  HttpOptions,
  NoSignalResult,
  NotSentReason,
  NotSentResult,
  OnEvent,
  ParticipantId,
  Profile,
  ReceiptEvidence,
  ReceiptFailureReason,
  ReceiptUnverifiedResult,
  ReceiptVerifiedResult,
  ScopedId,
  SendAs4Input,
  SendAs4Result,
  SendEvent,
  SendPhase,
  Signer,
  TransportFailureResult,
  ValidateCertificate,
} from './types.js';

/**
 * Perform exactly one AS4 send attempt. Never retries, never queues, never
 * throws for an expected failure: every outcome is returned as a fact.
 *
 * The result is deliberately not a decision: use `classify` from the
 * `./classifier` entry point to map a fact to accepted / retryable / fatal /
 * unknown.
 *
 * The entropy source (session key, IV, ids) is deliberately not an input: a
 * caller-supplied one could reuse a key/IV pair and break encryption. Tests use
 * `sendAs4Internal` from `./internal.js`.
 */
export async function sendAs4(input: SendAs4Input): Promise<SendAs4Result> {
  return sendAs4Internal(input, defaultEntropy());
}
