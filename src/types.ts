import type { Readable } from 'node:stream';

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
 */
export interface Signer {
  /** The signer's X.509 certificate (PEM). */
  readonly certificate: string;
  /** Sign `data` with RSA PKCS#1 v1.5 and SHA-256. */
  sign(data: Uint8Array): Promise<Uint8Array>;
}

/** What a certificate is being validated for. */
export type CertificatePurpose = 'receiver-encryption' | 'receipt-signer';

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
export type SendPhase = 'validate-receiver' | 'prepare-payload' | 'sign' | 'http' | 'verify-receipt';

export interface SendEvent {
  readonly phase: SendPhase;
  readonly durationMs: number;
}

/**
 * Observation hook. Called once per phase with the phase name and duration.
 * Exceptions are swallowed by the sender. It never receives payload bytes, keys
 * or certificates' private parts.
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
  /** Human readable description, when present. */
  readonly shortDescription?: string;
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
}

export interface NoSignalResult extends ResultBase {
  readonly outcome: 'no-signal';
  readonly status: number;
  readonly bodyEmpty: boolean;
}

export interface TransportFailureResult extends ResultBase {
  readonly outcome: 'transport-failure';
  /** Node error code, e.g. ENOTFOUND, ECONNREFUSED, ECONNRESET. */
  readonly errorCode?: string;
  /** True once any request body byte was written to the socket. */
  readonly requestBytesWritten: boolean;
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
