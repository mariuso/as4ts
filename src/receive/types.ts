import type { Readable } from 'node:stream';
import type { Profile, ScopedId, Signer, ValidateCertificate } from '../types.js';
import type { SignedReference } from '../xml/ws-security.js';

/**
 * Receiving contracts (Phase 1). These are internal until the `as4ts/receive`
 * entry point is wired in a later phase; they fix the shape so `open` and
 * `respond` cannot drift.
 *
 * Principle: one message in, facts out. `openAs4Message` verifies and unpacks a
 * single inbound UserMessage and returns verified facts plus owned handles; it
 * never acknowledges and never stores. `respondAs4Message` is called by the
 * caller after it has durably stored the document and returns the exact response
 * bytes.
 */

/**
 * A key holder that can unwrap the encrypted session key of an inbound message.
 * Kept separate from {@link Signer}: a managed key service may permit decryption
 * or signing, but not both.
 */
export interface InboundKeyHolder {
  /** The holder's AP certificate (PEM), used for evidence and identity binding. */
  readonly certificate: string;
  /**
   * Unwrap the RSA-OAEP(SHA-256, MGF1-SHA-256) encrypted session key. Must
   * return a valid AES-128 key (16 bytes) or reject; must honour `signal`.
   */
  unwrap(wrappedKey: Uint8Array, signal?: AbortSignal): Promise<Uint8Array>;
}

/** Where in inbound processing a failure occurred. */
export type InboundStage =
  | 'transport'
  | 'mime'
  | 'xml'
  | 'signature'
  | 'certificate'
  | 'decrypt'
  | 'decompress'
  | 'addressing'
  | 'payload'
  | 'internal';

/** Machine-readable failure reasons, grouped by stage. */
export type InboundFailureReason =
  // transport / size
  | 'body.too-large'
  | 'aborted'
  // mime
  | 'mime.content-type-invalid'
  | 'mime.boundary-invalid'
  | 'mime.parts-too-many'
  | 'mime.header-too-large'
  | 'mime.part-too-large'
  | 'mime.malformed'
  | 'mime.no-soap-part'
  | 'mime.duplicate-content-id'
  // xml
  | 'xml.malformed'
  | 'xml.doctype'
  | 'xml.too-deep'
  | 'xml.too-many-nodes'
  // signature
  | 'signature.malformed'
  | 'signature.bad-signature'
  | 'signature.digest-mismatch'
  | 'signature.coverage'
  | 'signature.attachment-digest'
  // certificate
  | 'certificate.untrusted'
  | 'certificate.revoked'
  | 'certificate.unavailable'
  // decrypt
  | 'decrypt.unsupported-algorithm'
  | 'decrypt.key-unwrap'
  | 'decrypt.bad-key-length'
  | 'decrypt.gcm-auth'
  // decompress
  | 'decompress.failed'
  | 'decompress.too-large'
  // addressing / profile
  | 'addressing.party-mismatch'
  | 'addressing.unsupported'
  | 'addressing.mpc'
  | 'addressing.sbdh-mismatch'
  // local
  | 'payload.spool-failed'
  | 'internal.error';

/**
 * Facts recovered before a failure, when they could be trusted. Absent when the
 * failure happened before there was enough trustworthy context to correlate.
 */
export interface InboundCorrelation {
  readonly messageId: string;
  readonly senderId?: string;
  readonly receiverId?: string;
}

/**
 * A receiving failure is a value. It records a stage and reason, whether it can
 * be answered with a signed ebMS error signal, and — only when trustworthy — the
 * correlation needed to build that error. Everything else (transport rejection,
 * a SOAP fault, an uncorrelated parse failure) is the caller's to surface.
 */
export interface InboundFailure {
  readonly ok: false;
  readonly stage: InboundStage;
  readonly reason: InboundFailureReason;
  /** Secret-free detail. */
  readonly detail?: string;
  readonly correlation?: InboundCorrelation;
  /** True when a signed ebMS error signal can be constructed for this failure. */
  readonly answerable: boolean;
}

/** Limits applied before any trust decision and retained afterwards. */
export interface InboundLimits {
  readonly maxRequestBytes: number;
  readonly maxEnvelopeBytes: number;
  readonly maxParts: number;
  readonly maxHeaderBytes: number;
  readonly maxPartBytes: number;
  readonly maxDecompressedBytes: number;
  readonly maxBoundaryLength: number;
}

export const defaultInboundLimits: InboundLimits = {
  maxRequestBytes: 64 * 1024 * 1024,
  maxEnvelopeBytes: 1024 * 1024,
  maxParts: 8,
  maxHeaderBytes: 16 * 1024,
  maxPartBytes: 64 * 1024 * 1024,
  maxDecompressedBytes: 256 * 1024 * 1024,
  maxBoundaryLength: 70,
};

/** Observation hook for inbound phases. Observe only; never receives secrets. */
export type InboundPhase =
  | 'read-body'
  | 'parse-mime'
  | 'parse-xml'
  | 'verify-signature'
  | 'validate-certificate'
  | 'decrypt'
  | 'decompress'
  | 'build-receipt';

export interface InboundEvent {
  readonly phase: InboundPhase;
  readonly durationMs: number;
}

export type OnInboundEvent = (event: InboundEvent) => void;

/** Everything `openAs4Message` needs for one inbound request. */
export interface OpenAs4MessageInput {
  /** The request `Content-Type` header (carries the MIME boundary). */
  readonly contentType: string | undefined;
  /** The complete request body, already transfer-decoded by the caller. */
  readonly body: AsyncIterable<Uint8Array>;
  /** The key holder that unwraps the inbound session key. */
  readonly keyHolder: InboundKeyHolder;
  /** Required. Validates the sender certificate (purpose `message-signer`). */
  readonly validateCertificate: ValidateCertificate;
  /** Required. Our own AP identity, to bind the message's `To` party. */
  readonly receiverIdentity: ScopedId;
  readonly profile?: Profile;
  readonly limits?: InboundLimits;
  /** Spool directory for the quarantined ciphertext. Defaults to the OS temp directory. */
  readonly spoolDirectory?: string;
  readonly signal?: AbortSignal;
  readonly onEvent?: OnInboundEvent;
  readonly now: () => Date;
}

/** A pointer to the decrypted, decompressed business document. */
export interface PayloadHandle {
  readonly byteLength: number;
  /** Base64 SHA-256 of the exposed payload bytes. */
  readonly digestBase64: string;
  /** Read the payload (repeatable until disposed). */
  read(): Readable;
  dispose(): Promise<void>;
}

/**
 * Verified evidence retained for the caller's records. The original envelope
 * bytes are kept because verification helpers may materialise namespaces in the
 * working DOM.
 */
export interface EvidenceHandle {
  /** The original SOAP envelope bytes exactly as received. */
  readonly envelopeBytes: Uint8Array;
  /** Every reference the signature covered, as validated. */
  readonly signedReferences: readonly SignedReference[];
  readonly signerCertificate: string;
  dispose(): Promise<void>;
}

/**
 * Plain, serialisable context for `respondAs4Message` and for recovery. It is
 * deliberately not an opaque in-memory token: a caller that committed the
 * document but crashed before responding can persist this and rebuild the
 * response.
 */
export interface ReceiptContext {
  readonly messageId: string;
  readonly senderId: string;
  readonly receiverId: string;
  readonly timestamp: string;
  /** The verified references to echo in the receipt's NonRepudiationInformation. */
  readonly signedReferences: readonly SignedReference[];
}

export interface OpenSuccess {
  readonly ok: true;
  readonly messageId: string;
  readonly timestamp: string;
  readonly senderId: string;
  readonly receiverId: string;
  readonly service: ScopedId;
  readonly action: string;
  readonly agreement?: string;
  readonly conversationId?: string;
  readonly mpc?: string;
  readonly compressionType?: string;
  readonly signerCertificate: string;
  readonly payload: PayloadHandle;
  readonly evidence: EvidenceHandle;
  readonly receipt: ReceiptContext;
}

export type OpenResult = OpenSuccess | InboundFailure;

/** An ebMS error to return instead of a positive receipt. */
export interface EbmsErrorSpec {
  readonly code: string;
  readonly severity: 'failure' | 'warning';
  readonly shortDescription?: string;
  readonly detail?: string;
}

/**
 * The caller's explicit decision. A receipt is produced only for the two
 * committed outcomes; anything else requires an error. The package cannot prove
 * the caller committed anything — this decision is the caller's obligation.
 */
export type AcceptanceDecision =
  | { readonly kind: 'committed' }
  | { readonly kind: 'already-committed' }
  | { readonly kind: 'rejected'; readonly error: EbmsErrorSpec };

export interface RespondAs4MessageInput {
  readonly receipt: ReceiptContext;
  readonly decision: AcceptanceDecision;
  /** Signs the receipt or error signal. */
  readonly signer: Signer;
  readonly profile?: Profile;
  /** Deterministic clock for the response timestamp. */
  readonly now: () => Date;
  readonly signal?: AbortSignal;
  readonly onEvent?: OnInboundEvent;
}

export interface RespondSuccess {
  readonly ok: true;
  readonly status: number;
  readonly contentType: string;
  readonly headers: Readonly<Record<string, string>>;
  /** The exact response body bytes to persist and replay. */
  readonly body: Uint8Array;
}

export type RespondResult = RespondSuccess | { readonly ok: false; readonly reason: string };
