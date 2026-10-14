import type { Readable } from 'node:stream';
import type { ResponseLimits } from './response-limits.js';
import type { SignedReference } from './xml/ws-security.js';

/** A participant identifier: a scheme and a value, e.g. iso6523-actorid-upis / 0192:123456789. */
export interface ParticipantId {
  readonly scheme: string;
  readonly value: string;
}

/** A document type or process identifier: a scheme and a value. */
export interface ScopedId {
  readonly scheme: string;
  readonly value: string;
}

/**
 * The network constants that describe one AS4 profile. The sender reads nothing
 * from these into the envelope except fixed identifiers; the default is the
 * Peppol AS4 profile (`peppolProfile`).
 */
export interface Profile {
  /** `eb:PartyId/@type`, e.g. the Peppol participant identifier type. */
  readonly partyIdType: string;
  /** `eb:AgreementRef` value. */
  readonly agreementRef: string;
  /** `eb:Role` of the sending access point. */
  readonly initiatorRole: string;
  /** `eb:Role` of the receiving access point. */
  readonly responderRole: string;
  /** `eb:UserMessage/@mpc` value. */
  readonly mpc: string;
  /** `MimeType` part property value in `eb:PayloadInfo`. */
  readonly mimeType: string;
}

/**
 * A signer produces an RSA PKCS#1 v1.5 / SHA-256 signature over bytes, and
 * carries the certificate whose public key must verify it. The private key
 * never leaves the implementation.
 *
 * A future receiver will need an additional operation on the same key holder:
 * unwrapping (decrypting) the session key of an inbound message. It is not
 * declared here yet because the receiver is not implemented, but an
 * implementation backed by a key service (HSM/KMS) should plan for that
 * unwrap-key operation on the same key/certificate pair now, so it does not
 * have to be retrofitted later.
 */
export interface Signer {
  /** The signer's X.509 certificate (PEM). */
  readonly certificate: string;
  /**
   * Sign `data` with RSA PKCS#1 v1.5 and SHA-256. When `signal` is provided and
   * already aborted, the operation is abandoned; a key holder backed by a remote
   * service (HSM/KMS) should propagate it to cancel that request.
   */
  sign(data: Uint8Array, signal?: AbortSignal): Promise<Uint8Array>;
}

/** What a certificate is being validated for. */
export type CertificatePurpose =
  /** The receiver's certificate we encrypt to (`receiver-encryption`). */
  | 'receiver-encryption'
  /** The access point that signed a receipt we received (`receipt-signer`). */
  | 'receipt-signer'
  /** The access point that signed an inbound user message (`message-signer`). */
  | 'message-signer'
  /** The service metadata publisher that signed an SMP response (`smp-signer`). */
  | 'smp-signer';

/**
 * The outcome of validating one certificate. The core never decides what this
 * means for retrying; that is `classify()`.
 */
export type CertificateValidation =
  | { readonly ok: true }
  | {
      readonly ok: false;
      readonly status: 'invalid' | 'revoked' | 'unavailable';
      readonly reason: string;
    };

export interface CertificateValidationInput {
  readonly certificatePem: string;
  readonly purpose: CertificatePurpose;
  readonly now: Date;
  /** Aborting must stop any network revocation check. */
  readonly signal?: AbortSignal;
}

/**
 * Required injected certificate validation. Every send calls this for the
 * receiver certificate before any bytes are spooled, and for the receipt signer
 * before a receipt is accepted. There is no code path that sends without it.
 */
export type ValidateCertificate = (input: CertificateValidationInput) => Promise<CertificateValidation>;

/** Phases reported to `onEvent`. Observe only. */
export type SendPhase =
  | 'validate-receiver'
  | 'prepare-payload'
  | 'sign'
  | 'http'
  | 'verify-receipt'
  /** Emitted only when spool cleanup fails, after the result is already decided. */
  | 'cleanup';

export interface SendEvent {
  readonly phase: SendPhase;
  readonly durationMs: number;
  /** Present on a `cleanup` event: the secret-free reason cleanup failed. */
  readonly error?: string;
}

/**
 * Observation hook. Called once per phase with the phase name and duration,
 * except that a `cleanup` event is emitted only when spool cleanup fails (and
 * carries an `error`). Exceptions are swallowed by the sender. It never receives
 * payload bytes, keys or certificates' private parts.
 */
export type OnEvent = (event: SendEvent) => void;

/** Operational HTTP/TLS inputs. TLS 1.2 and certificate verification cannot be disabled. */
export interface HttpOptions {
  /** Optional pinned CA bundle for the receiver's TLS certificate (tests). */
  readonly ca?: readonly string[];
  /** Optional TLS SNI override. */
  readonly serverName?: string;
  /** TCP/TLS connect timeout in milliseconds. */
  readonly connectMs: number;
  /** Total time budget for the HTTP exchange in milliseconds. */
  readonly totalMs: number;
}

/** Everything the sender needs for one attempt. It never reads files or environment. */ export interface SendAs4Input {
  /** Complete SBDH+business document, exactly as it must arrive. Opaque bytes. */
  readonly payload: Readable;
  /** AE endpoint URL from the receiver's SMP entry. */
  readonly endpointUrl: string;
  /** AS4 transport profile from the receiver's SMP entry, e.g. peppol-transport-as4-v2_0. */
  readonly transportProfile: string;
  /** Receiver access point X.509 certificate (PEM), from SMP. */
  readonly receiverCertificate: string;
  readonly senderParticipant: ParticipantId;
  readonly receiverParticipant: ParticipantId;
  readonly documentType: ScopedId;
  readonly process: ScopedId;
  /** Message id supplied by the caller. Reuse it when retrying an `unknown` outcome. */
  readonly as4MessageId: string;
  /** Signs the message. Replaces any private key in the public input. */
  readonly signer: Signer;
  /** Required. Validates the receiver certificate and the receipt signer. */
  readonly validateCertificate: ValidateCertificate;
  /** Profile constants. Defaults to `peppolProfile`. */
  readonly profile?: Profile;
  /** Aborting stops spooling, the HTTP request and the validator, and removes temp files. */
  readonly signal?: AbortSignal;
  readonly http: HttpOptions;
  /** Spool directory for the encrypted payload. Defaults to the OS temp directory. */
  readonly spoolDirectory?: string;
  /**
   * Limits for parsing a receipt or error signal returned by the receiver. Any
   * omitted property falls back to `defaultResponseLimits`.
   */
  readonly responseLimits?: Partial<ResponseLimits>;
  /** Observe phase timings. Never receives payload bytes, keys or certificates. */
  readonly onEvent?: OnEvent;
  /** Deterministic clock. */
  readonly now: () => Date;
}

export interface ReceiptEvidence {
  /** Timestamp from the receipt's MessageInfo. */
  readonly timestamp: string;
  /** The raw signal message bytes exactly as received. */
  readonly raw: Uint8Array;
  /** The signer's certificate (PEM) extracted from the receipt. */
  readonly signerCertificate: string;
  /** True when the receipt signer is byte-for-byte the certificate SMP published. */
  readonly signerMatchesSmPCertificate: boolean;
  /** The RefToMessageId carried by the receipt. */
  readonly refToMessageId: string;
}

export interface EbmsErrorEvidence {
  /** e.g. EBMS:0004. */
  readonly code: string;
  /** e.g. failure. */
  readonly severity: string;
  /** `eb:Error/@shortDescription`, when present. */
  readonly shortDescription?: string;
  /** The human-readable `eb:Description` element text, when present. */
  readonly description?: string;
  /** eb:ErrorDetail text, when present (often the receiver's real reason). */
  readonly detail?: string;
  /** The raw signal message bytes exactly as received. */
  readonly raw: Uint8Array;
}

/** Why a receipt was not accepted. All of these are facts, not decisions. */
export type ReceiptFailureReason =
  | 'receipt.malformed'
  | 'receipt.bad-signature'
  | 'receipt.digest-mismatch'
  | 'receipt.untrusted-signer'
  | 'receipt.revoked-signer'
  | 'receipt.wrong-signer'
  | 'receipt.ref-mismatch'
  /** The caller aborted while the receipt was being verified. */
  | 'receipt.aborted';

/** Local reasons a message was not sent at all. */
export type NotSentReason =
  | 'message-id.invalid'
  | 'signer.unusable'
  | 'signature.mismatch'
  | 'certificate.refused'
  | 'certificate.unavailable'
  | 'spool.failed'
  | 'aborted'
  | 'limits.invalid'
  | 'internal.error';

interface ResultBase {
  readonly as4MessageId: string;
  /** The timestamp placed in our user message; absent when no envelope was built. */
  readonly sentAt?: string;
  /** Reporting fact: common name of the receiver's certificate as published in SMP. */
  readonly receiverCertificateCommonName: string;
  /** Reporting fact: transport profile used. */
  readonly transportProfile: string;
}

export interface ReceiptVerifiedResult extends ResultBase {
  readonly outcome: 'receipt-verified';
  readonly receipt: ReceiptEvidence;
}

export interface ReceiptUnverifiedResult extends ResultBase {
  readonly outcome: 'receipt-unverified';
  readonly reason: ReceiptFailureReason;
  readonly raw: Uint8Array;
}

export interface ErrorSignalResult extends ResultBase {
  readonly outcome: 'error-signal';
  /** All ebMS errors carried by the signal, in document order. */
  readonly errors: readonly EbmsErrorEvidence[];
  readonly raw: Uint8Array;
  /** `RefToMessageId` carried by the signal, when present. */
  readonly refToMessageId: string | null;
  /** How that reference relates to the message we sent. See {@link ErrorCorrelation}. */
  readonly correlation: ErrorCorrelation;
}

/**
 * How an error signal's `RefToMessageId` relates to the message we sent. Only a
 * `matches` or `absent` reference lets the signal's errors establish a result for
 * our message; a `mismatched` one does not.
 */
export type ErrorCorrelation =
  /** The signal references the message we sent. */
  | 'matches'
  /** The signal carries no reference; the receiver may not have recovered it. */
  | 'absent'
  /** The signal references a different message. */
  | 'mismatched';

export interface NoSignalResult extends ResultBase {
  readonly outcome: 'no-signal';
  readonly status: number;
  readonly bodyEmpty: boolean;
  /**
   * Why the response was not a readable signal, when it contained a SOAP part:
   * a strict-parser reason (`xml.too-large`, `xml.doctype`, ...) or `signal.shape`.
   * Secret-free; never echoes response content.
   */
  readonly detail?: string;
}

export interface TransportFailureResult extends ResultBase {
  readonly outcome: 'transport-failure';
  /** Node error code, e.g. ENOTFOUND, ECONNREFUSED, ECONNRESET. */
  readonly errorCode?: string;
  /**
   * Conservative fact: true once the connection was established, after which the
   * request may have reached the receiver. Safe to retry only when this is false.
   */
  readonly requestMayHaveBeenSent: boolean;
  /** True when the attempt was stopped by the caller's AbortSignal. */
  readonly aborted: boolean;
}

export interface NotSentResult extends ResultBase {
  readonly outcome: 'not-sent';
  readonly reason: NotSentReason;
  /** Optional secret-free detail. */
  readonly detail?: string;
}

export type SendAs4Result =
  | ReceiptVerifiedResult
  | ReceiptUnverifiedResult
  | ErrorSignalResult
  | NoSignalResult
  | TransportFailureResult
  | NotSentResult;

/** Everything needed to prepare one immutable outbound message. */
export interface PrepareAs4Input {
  /** Complete SBDH+business document, exactly as it must arrive. Opaque bytes. */
  readonly payload: Readable;
  /** AE endpoint URL from the receiver's SMP entry. */
  readonly endpointUrl: string;
  /** AS4 transport profile from the receiver's SMP entry. */
  readonly transportProfile: string;
  readonly receiverCertificate: string;
  readonly senderParticipant: ParticipantId;
  readonly receiverParticipant: ParticipantId;
  readonly documentType: ScopedId;
  readonly process: ScopedId;
  /** Message id supplied by the caller. Reuse it when retrying an `unknown` outcome. */
  readonly as4MessageId: string;
  readonly signer: Signer;
  /** Required. Validates the receiver certificate before anything is spooled. */
  readonly validateCertificate: ValidateCertificate;
  readonly profile?: Profile;
  /** Aborting stops spooling and signing and removes the scratch files. */
  readonly signal?: AbortSignal;
  /** Directory in which the artifact directory is created. Defaults to the OS temp directory. */
  readonly artifactDirectory?: string;
  readonly onEvent?: OnEvent;
  readonly now: () => Date;
}

export type PrepareAs4Result =
  | { readonly outcome: 'prepared'; readonly message: PreparedMessage }
  | { readonly outcome: 'not-prepared'; readonly reason: NotSentReason; readonly detail?: string };

/**
 * An immutable, replayable outbound message. Transmitting it again re-sends the
 * exact same signed envelope and ciphertext, so a retry keeps the signed
 * references a receiver already acknowledged. Persist `directory` to survive a
 * restart and reload it with `loadPreparedMessage`.
 */
export interface PreparedMessage {
  readonly as4MessageId: string;
  readonly sentAt: string;
  readonly endpointUrl: string;
  readonly transportProfile: string;
  readonly receiverCertificateCommonName: string;
  /** The receiver certificate (PEM) the message was encrypted to. */
  readonly receiverCertificate: string;
  readonly documentType: ScopedId;
  readonly process: ScopedId;
  /** The exact signed SOAP envelope. */
  readonly soapXml: string;
  /** `cid:` href of the encrypted attachment. */
  readonly attachmentHref: string;
  readonly boundary: string;
  readonly soapContentId: string;
  readonly attachmentByteLength: number;
  /** The references the signature covers; reuse them verbatim to verify the receipt. */
  readonly signedReferences: readonly SignedReference[];
  /** Directory holding `metadata.json` and the encrypted attachment. */
  readonly directory: string;
  /** Read the encrypted attachment (repeatable). */
  readAttachment(): Readable;
  /** Remove the artifact from disk. */
  dispose(): Promise<void>;
}

export interface TransmitAs4Input {
  readonly message: PreparedMessage;
  /** Required. Validates the receipt signer before a receipt is accepted. */
  readonly validateCertificate: ValidateCertificate;
  readonly http: HttpOptions;
  readonly signal?: AbortSignal;
  readonly onEvent?: OnEvent;
  /**
   * Limits for parsing a receipt or error signal. Any omitted property falls
   * back to `defaultResponseLimits`.
   */
  readonly responseLimits?: Partial<ResponseLimits>;
  readonly now: () => Date;
}
