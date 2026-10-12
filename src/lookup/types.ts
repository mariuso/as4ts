import type { ParticipantId, ScopedId, ValidateCertificate } from '../types.js';

/** A DNS NAPTR record, as returned by Node's `resolveNaptr`. */
export interface NaptrRecord {
  readonly order: number;
  readonly preference: number;
  readonly flags: string;
  readonly service: string;
  readonly regexp: string;
  readonly replacement: string;
}

/** Resolve NAPTR records for a DNS name. Injectable; defaults to Node's. */
export type NaptrResolver = (domain: string) => Promise<readonly NaptrRecord[]>;

/** Everything one discovery needs. Data only: no file or environment reads. */
export interface LookupInput {
  /** The participant whose endpoint we look up, e.g. iso6523-actorid-upis / 0192:111... */
  readonly participant: ParticipantId;
  readonly documentType: ScopedId;
  readonly process: ScopedId;
  /** Defaults to `peppol-transport-as4-v2_0` ([PEPPOLAS4]). */
  readonly transportProfile?: string;
  /**
   * The SML DNS zone for the environment (production or test), e.g.
   * `participant.sml.test.tech.peppol.org`. Passed in, because the zone differs
   * per environment and is not fixed by the SML specification.
   */
  readonly sml: string;
  /** Required. Called for the SMP signer certificate with purpose `smp-signer`. */
  readonly validateCertificate: ValidateCertificate;
  /** Injectable NAPTR resolver. Defaults to `node:dns/promises`. */
  readonly resolveNaptr?: NaptrResolver;
  /** Injectable HTTP fetch. Defaults to Node's global `fetch`. */
  readonly fetch?: typeof fetch;
  /** Aborting stops DNS and HTTP. */
  readonly signal?: AbortSignal;
  /** Per HTTP request timeout in milliseconds. Defaults to 10 000. */
  readonly timeoutMs?: number;
  /** Deterministic clock, used for the service activation/expiration dates. */
  readonly now: () => Date;
}

/** The facts of a successful discovery. */
export interface LookupFound {
  readonly outcome: 'found';
  /** The receiver's AS4 endpoint URL. */
  readonly endpointUrl: string;
  /** The receiver access point certificate (PEM) the endpoint advertises. */
  readonly receiverCertificate: string;
  readonly transportProfile: string;
  /** The SMP URL the service metadata was fetched from (after any redirect). */
  readonly smpUrl: string;
  /** The signer certificate of the SMP response (PEM). */
  readonly signerCertificate: string;
  /** ServiceActivationDate, if advertised (xs:dateTime string). */
  readonly serviceActivationDate?: string;
  /** ServiceExpirationDate, if advertised (xs:dateTime string). */
  readonly serviceExpirationDate?: string;
}

/** There is no SML entry for the participant. */
export interface LookupNotRegistered {
  readonly outcome: 'not-registered';
  readonly detail?: string;
}

/** The participant exists but has no endpoint for this document type, process and transport profile. */
export interface LookupNotSupported {
  readonly outcome: 'not-supported';
  readonly detail?: string;
}

/** The SMP response's signature did not verify. */
export interface LookupSignatureInvalid {
  readonly outcome: 'signature-invalid';
  readonly reason: string;
}

/** DNS or HTTP failed. `retryable` says whether a retry could help. */
export interface LookupUnavailable {
  readonly outcome: 'unavailable';
  readonly reason: string;
  readonly retryable: boolean;
}

/** The result of one discovery, as a union of facts. Expected failures are values, never thrown. */
export type LookupResult =
  LookupFound | LookupNotRegistered | LookupNotSupported | LookupSignatureInvalid | LookupUnavailable;
