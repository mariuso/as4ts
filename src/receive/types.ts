import type { Readable } from 'node:stream';
import type { Profile, ScopedId, Signer, ValidateCertificate } from '../types.js';
import type { VerifiedReference } from '../xml/ws-security.js';
import type { MessageBudget } from './budget.js';

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
   * Unwrap the RSA-OAEP(SHA-256, MGF1-SHA-256) encrypted session key. Must return
   * a valid AES-128 key (16 bytes) or reject; must honour `signal`. A holder that
   * cannot serve the request should reject with an error carrying
   * `code === 'KEY_UNAVAILABLE'`.
   *
   * Ownership of the returned buffer transfers to the caller, which clears it.
   * A holder must return a fresh buffer and must not retain or reuse it.
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
  | 'mime.duplicate-header'
  | 'mime.no-soap-part'
  | 'mime.ambiguous-root'
  | 'mime.duplicate-content-id'
  // xml
  | 'xml.malformed'
  | 'xml.doctype'
  | 'xml.too-large'
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
  | 'encryption.invalid'
  | 'decrypt.unsupported-algorithm'
  | 'decrypt.key-unwrap'
  | 'decrypt.key-unavailable'
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
  /** local */
  | 'limits.invalid'
  | 'payload.spool-failed'
  | 'payload.too-large'
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
  /** Cap on the decrypted, pre-decompression representation (the compressed bytes for gzip). */
  readonly maxRepresentationBytes: number;
  /** Absolute cap on decompressed output for a single attachment. */
  readonly maxDecompressedBytes: number;
  /** Aggregate decompressed output across every attachment in one message. */
  readonly maxAggregateOutputBytes: number;
  /** Cap on XML bytes handed to the DOM parser. */
  readonly maxXmlBytes: number;
  readonly maxBoundaryLength: number;
  /** Maximum number of decryption credentials tried during rollover. */
  readonly maxKeyCandidates: number;
}

export const defaultInboundLimits: InboundLimits = {
  maxRequestBytes: 64 * 1024 * 1024,
  maxEnvelopeBytes: 1024 * 1024,
  maxParts: 8,
  maxHeaderBytes: 16 * 1024,
  maxPartBytes: 64 * 1024 * 1024,
  maxRepresentationBytes: 64 * 1024 * 1024,
  maxDecompressedBytes: 256 * 1024 * 1024,
  maxAggregateOutputBytes: 512 * 1024 * 1024,
  maxXmlBytes: 64 * 1024 * 1024,
  maxBoundaryLength: 70,
  maxKeyCandidates: 4,
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
  | 'materialize'
  | 'build-receipt'
  /** Emitted only when scratch cleanup fails, after the result is decided. */
  | 'cleanup';

export interface InboundEvent {
  readonly phase: InboundPhase;
  readonly durationMs: number;
  /** Present on a `cleanup` event: the secret-free reason cleanup failed. */
  readonly error?: string;
}

export type OnInboundEvent = (event: InboundEvent) => void;

/** Everything `openAs4Message` needs for one inbound request. */
export interface OpenAs4MessageInput {
  /** The request `Content-Type` header (carries the MIME boundary). */
  readonly contentType: string | undefined;
  /** The complete request body, already transfer-decoded by the caller. */
  readonly body: AsyncIterable<Uint8Array>;
  /**
   * The key holder(s) that can unwrap the inbound session key. A bounded
   * collection supports certificate rollover; `open` reports which credential it
   * used.
   */
  readonly keyHolder: InboundKeyHolder | readonly InboundKeyHolder[];
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
  /** Every reference the signature covered, as fully validated (transform parameters included). */
  readonly signedReferences: readonly VerifiedReference[];
  readonly signerCertificate: string;
  dispose(): Promise<void>;
}

/**
 * Plain, serialisable context for `respondAs4Message` and for recovery. It is
 * deliberately not an opaque in-memory token: a caller that committed the
 * document but crashed before responding can persist this and rebuild the
 * response. It carries the complete verified references — digest algorithm,
 * ordered transforms and their parameters — not just URI and digest.
 */
export interface ReceiptContext {
  readonly messageId: string;
  readonly senderId: string;
  readonly receiverId: string;
  readonly timestamp: string;
  /** The verified references to echo in the receipt's NonRepudiationInformation. */
  readonly signedReferences: readonly VerifiedReference[];
}

export interface OpenSuccess {
  readonly ok: true;
  readonly messageId: string;
  readonly timestamp: string;
  readonly senderId: string;
  readonly receiverId: string;
  /** The verified original sender participant (scheme/value). */
  readonly originalSender: ScopedId;
  /** The verified final recipient participant (scheme/value). */
  readonly finalRecipient: ScopedId;
  readonly service: ScopedId;
  readonly action: string;
  readonly agreement?: string;
  readonly conversationId?: string;
  readonly mpc?: string;
  readonly compressionType?: string;
  readonly signerCertificate: string;
  /** The credential (AP certificate) that actually unwrapped the session key. */
  readonly credentialCertificate: string;
  readonly payload: PayloadHandle;
  /** The authenticated compressed (or original) attachment representation. */
  readonly representation: RepresentationHandle;
  readonly evidence: EvidenceHandle;
  readonly receipt: ReceiptContext;
  /** The outcome of the SBDH consistency check over the authenticated payload. */
  readonly sbdh: SbdhConsistency;
  /** Release the payload, representation and evidence handles. Idempotent. */
  dispose(): Promise<void>;
}

/**
 * The outcome of the SBDH consistency check. Consistency is reported as distinct
 * facts so a caller can tell "verified consistent" from "could not check".
 */
export type SbdhConsistency =
  | { readonly status: 'consistent' }
  | { readonly status: 'inconsistent'; readonly mismatches: readonly string[] }
  | { readonly status: 'missing' }
  | { readonly status: 'malformed'; readonly detail: string }
  | { readonly status: 'too-large' };

export type OpenResult = OpenSuccess | InboundFailure;

/** An ebMS error to return instead of a positive receipt. */
export interface EbmsErrorSpec {
  readonly code: string;
  readonly severity: 'failure' | 'warning';
  readonly shortDescription?: string;
  readonly detail?: string;
}

/**
 * The caller's explicit decision for an accepted message. A receipt is produced
 * only for these two outcomes. The package cannot prove the caller committed
 * anything — this decision is the caller's obligation.
 */
export type AcceptanceDecision = 'committed' | 'already-committed';

interface RespondCommon {
  /** Signs the receipt or error signal. */
  readonly signer: Signer;
  readonly profile?: Profile;
  /** Deterministic clock for the response timestamp. */
  readonly now: () => Date;
  readonly signal?: AbortSignal;
  readonly onEvent?: OnInboundEvent;
}

/** Build a signed receipt for a message that was durably accepted. */
export interface AcceptResponseInput extends RespondCommon {
  readonly kind: 'accepted';
  readonly receipt: ReceiptContext;
  readonly decision: AcceptanceDecision;
}

/**
 * Build a signed ebMS error signal. It needs only the correlation recovered
 * before the failure — not receipt facts — so a caller answering an
 * `InboundFailure` never has to fabricate successful-verification evidence.
 */
export interface RejectResponseInput extends RespondCommon {
  readonly kind: 'rejected';
  readonly correlation: InboundCorrelation;
  readonly error: EbmsErrorSpec;
}

export type RespondAs4MessageInput = AcceptResponseInput | RejectResponseInput;

export interface RespondSuccess {
  readonly ok: true;
  readonly status: number;
  readonly contentType: string;
  readonly headers: Readonly<Record<string, string>>;
  /** The exact response body bytes to persist and replay. */
  readonly body: Uint8Array;
}

export type RespondResult = RespondSuccess | { readonly ok: false; readonly reason: string };

// ---------------------------------------------------------------------------
// Phase 2: receiving primitives
// ---------------------------------------------------------------------------

/**
 * The encryption-graph facts recovered from the Security header. This is a
 * structural descriptor only — parsing it performs no private-key operation. It
 * is validated by `parseInboundEncryption` before any credential is used.
 */
export interface InboundEncryption {
  /** The AES-128-GCM data-encryption algorithm URI, validated. */
  readonly dataAlgorithm: string;
  /** `EncryptedData/@MimeType` — the *original* attachment media type (SwA §5.5.3). */
  readonly mediaType: string;
  /** `EncryptedData/@Type`, validated to be attachment-content-only. */
  readonly dataType: string;
  /** The single ciphertext transform URI, validated. */
  readonly ciphertextTransform: string;
  /** The attachment href from `CipherReference`, e.g. `cid:...@host`. */
  readonly attachmentHref: string;
  /** RSA-OAEP wrapped session key bytes. */
  readonly wrappedKey: Uint8Array;
  /** The OAEP parameters the sender declared (all required and validated). */
  readonly oaep: {
    readonly digest: string;
    readonly mgf: string;
    /** OAEP label; the constrained profile allows only the empty label. */
    readonly label: Uint8Array;
  };
  /** The certificate the sender encrypted to, when the EncryptedKey names one. */
  readonly recipientCertificate?: string;
}

/** The ciphertext attachment resolved from the MIME parts by `cid:` href. */
export interface ResolvedAttachment {
  /** Content-ID without angle brackets. */
  readonly contentId: string;
  /**
   * The ciphertext source. A stream is accepted so the primitive bounds it while
   * spooling, without requiring the whole ciphertext in memory.
   */
  readonly source: AsyncIterable<Uint8Array>;
  /** Total ciphertext size when known (a stream may leave it undefined). */
  readonly byteLength?: number;
}

/** The compression declared for the payload, from validated metadata. */
export type CompressionDeclaration = { readonly kind: 'gzip'; readonly declaredBy: string } | { readonly kind: 'none' };

/**
 * The authenticated representation of the attachment — the original decrypted
 * bytes before decompression. For gzip that is the original compressed stream;
 * for uncompressed XML it is the original XML bytes. Recompression cannot
 * reconstruct the signed evidence, so this is retained verbatim.
 */
export interface RepresentationHandle {
  readonly byteLength: number;
  /** Raw-byte base64 SHA-256 of the representation. */
  readonly rawDigestBase64: string;
  /** The original media type restored from `EncryptedData/@MimeType`. */
  readonly mediaType: string;
  /** The transform digest verified against the authenticated reference. */
  readonly transformDigestBase64: string;
  /** Read the representation (repeatable until disposed). */
  read(): Readable;
  dispose(): Promise<void>;
}

/** The credential facts reported only after successful authentication. */
export interface CredentialFacts {
  /** AP certificate of the credential that unwrapped the session key. */
  readonly certificate: string;
}

/**
 * The result of recovering one inbound payload. `dispose()` is idempotent and
 * releases everything, including active readers.
 */
export interface InboundBundle {
  readonly ok: true;
  readonly payload: PayloadHandle;
  readonly representation: RepresentationHandle;
  readonly credential: CredentialFacts;
  dispose(): Promise<void>;
}

/** Everything `recoverInboundPayload` needs. Trust is established by Phase 3. */
export interface RecoverInboundPayloadInput {
  /** Structurally validated encryption descriptor. */
  readonly encryption: InboundEncryption;
  /** The ciphertext attachment resolved from the MIME parts. */
  readonly attachment: ResolvedAttachment;
  /**
   * The attachment reference the sender's XML signature authenticated: URI,
   * digest algorithm, digest, ordered transforms and parameters. Phase 2 checks
   * the decrypted bytes against it.
   */
  readonly reference: VerifiedReference;
  /** The validated compression declaration. */
  readonly compression: CompressionDeclaration;
  /** Candidate decryption credentials, tried in order (rollover). */
  readonly keyHolder: readonly InboundKeyHolder[];
  readonly limits: InboundLimits;
  /**
   * Message-scoped aggregate output budget. A caller recovering several
   * attachments passes the same instance so the total decompressed output across
   * the message is bounded, which a per-call limit cannot express.
   */
  readonly budget?: MessageBudget;
  readonly spoolDirectory?: string;
  readonly signal?: AbortSignal;
  readonly onEvent?: OnInboundEvent;
}

export type RecoverResult = InboundBundle | InboundFailure;
