/**
 * `as4ts/receive` — the receiving entry point.
 *
 * One message in, facts out: `openAs4Message` verifies and unpacks a single
 * inbound UserMessage (never acknowledging, never storing) and `respondAs4Message`
 * returns the exact signed response bytes once the caller has durably accepted
 * the document. Expected failures are values, never throws. The HTTP endpoint,
 * storage, duplicate suppression and the serviced-participant decision stay with
 * the caller.
 *
 * The HTTP adapter must set `Content-Type` from the response `contentType` and
 * transmit `body` unchanged. Both a receipt and an ebMS error are carried as
 * HTTP 200 `application/soap+xml`.
 */
export { openAs4Message } from './open.js';
export { respondAs4Message } from './respond.js';
export { keyHolderFromKey } from './key-holder.js';
export { ebmsErrorFor, notServicedError } from './error.js';
export { defaultInboundLimits } from './types.js';

// Shared conveniences a receiver needs: sign responses and reference the profile.
export { signerFromKey } from '../signer.js';
export { peppolProfile } from '../profile.js';

export type {
  AcceptanceDecision,
  AcceptResponseInput,
  EbmsErrorSpec,
  EvidenceHandle,
  InboundCorrelation,
  InboundEvent,
  InboundFailure,
  InboundFailureReason,
  InboundKeyHolder,
  InboundLimits,
  InboundPhase,
  InboundStage,
  OnInboundEvent,
  OpenAs4MessageInput,
  OpenResult,
  OpenSuccess,
  PayloadHandle,
  ReceiptContext,
  RejectResponseInput,
  RepresentationHandle,
  RespondAs4MessageInput,
  RespondFailure,
  RespondResult,
  RespondSuccess,
  SbdhConsistency,
} from './types.js';
export type { Profile, ScopedId, Signer, ValidateCertificate } from '../types.js';
export type { VerifiedReference, VerifiedTransform } from '../xml/ws-security.js';
