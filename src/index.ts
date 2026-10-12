import { defaultEntropy } from './entropy.js';
import { prepareAs4Internal } from './prepare.js';
import { sendAs4Internal } from './send.js';
import type { PrepareAs4Input, PrepareAs4Result, SendAs4Input, SendAs4Result } from './types.js';

export { signerFromKey } from './signer.js';
export { peppolProfile } from './profile.js';
export { transmitAs4 } from './transmit.js';
export { loadPreparedMessage } from './artifact.js';

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
  PrepareAs4Input,
  PrepareAs4Result,
  PreparedMessage,
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
  TransmitAs4Input,
  TransportFailureResult,
  ValidateCertificate,
} from './types.js';
export type { SignedReference } from './xml/ws-security.js';

/**
 * Perform exactly one AS4 send attempt: prepare a message and transmit it once.
 * Never retries, never queues, never throws for an expected failure. This is the
 * convenience path over `prepareAs4` + `transmitAs4`; use those directly when a
 * caller needs to persist an artifact or retry an uncertain outcome.
 */
export async function sendAs4(input: SendAs4Input): Promise<SendAs4Result> {
  return sendAs4Internal(input, defaultEntropy());
}

/**
 * Prepare exactly one immutable outbound message: validate the receiver
 * certificate, spool the encrypted payload and sign the envelope. The returned
 * artifact can be transmitted any number of times with `transmitAs4` and reloaded
 * from disk with `loadPreparedMessage`. Never throws for an expected failure.
 */
export async function prepareAs4(input: PrepareAs4Input): Promise<PrepareAs4Result> {
  return prepareAs4Internal(input, defaultEntropy());
}
