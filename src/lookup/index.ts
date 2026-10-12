import { PEPPOL_TRANSPORT_PROFILE } from '../constants.js';
import { safeMessage } from '../util.js';
import { parseXml } from '../xml/nodes.js';
import { httpGet, type HttpGetResponse } from './http.js';
import {
  chooseReference,
  parseServiceGroupReferences,
  participantSegment,
  selectEndpoint,
  serviceMetadataRedirectHref,
} from './smp.js';
import { verifySmpSignature } from './smp-signature.js';
import { classifyDnsError, defaultResolveNaptr, participantDnsName, smpBaseFromRecords } from './sml.js';
import type { LookupInput, LookupResult, NaptrRecord } from './types.js';

export type {
  LookupFound,
  LookupInput,
  LookupNotRegistered,
  LookupNotSupported,
  LookupResult,
  LookupSignatureInvalid,
  LookupUnavailable,
  NaptrRecord,
  NaptrResolver,
} from './types.js';
export { participantDnsName, participantHash } from './sml.js';
export { documentTypeMatches, participantSegment } from './smp.js';
export { PEPPOL_TRANSPORT_PROFILE } from '../constants.js';

const DEFAULT_TIMEOUT_MS = 10_000;

/**
 * Perform exactly one SML/SMP discovery and return facts. It never caches and
 * never retries: `unavailable.retryable` tells the caller whether a retry could
 * help. Every expected failure is a value, never a thrown exception.
 *
 * The SML zone is passed in (`input.sml`) because it differs per environment and
 * is not fixed by the SML specification. The SMP signer certificate is validated
 * with `validateCertificate` and purpose `smp-signer`.
 */
export async function lookupParticipant(input: LookupInput): Promise<LookupResult> {
  const transportProfile = input.transportProfile ?? PEPPOL_TRANSPORT_PROFILE;
  const resolveNaptr = input.resolveNaptr ?? defaultResolveNaptr;
  const fetchImpl = input.fetch ?? globalThis.fetch;
  const timeoutMs = input.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const now = input.now();

  if (input.signal?.aborted) return { outcome: 'unavailable', reason: 'aborted', retryable: true };

  try {
    // 1. SML: derive the DNS name and resolve the SMP base URL.
    const domain = participantDnsName(input.participant, input.sml);
    let records: readonly NaptrRecord[];
    try {
      records = await resolveNaptr(domain);
    } catch (err) {
      const dns = classifyDnsError(err);
      if (dns.notRegistered) return { outcome: 'not-registered', detail: domain };
      return { outcome: 'unavailable', reason: `SML DNS lookup failed: ${dns.reason}`, retryable: dns.retryable };
    }
    const base = smpBaseFromRecords(records, domain);
    if (!base.ok) return { outcome: 'unavailable', reason: base.reason, retryable: base.retryable };

    // 2. ServiceGroup: does the participant exist, and which document types does it publish?
    const segment = participantSegment(input.participant);
    const serviceGroupUrl = `${base.url}/${encodeURIComponent(segment)}`;
    const group = await fetchXml(serviceGroupUrl, fetchImpl, input.signal, timeoutMs);
    if (!group.ok) return group.result;
    if (group.response.status === 404) return { outcome: 'not-registered', detail: segment };
    const groupStatus = statusResult(group.response, serviceGroupUrl);
    if (groupStatus) return groupStatus;
    const groupDocument = parse(group.response.body);
    if (!groupDocument)
      return { outcome: 'unavailable', reason: `${serviceGroupUrl}: response is not XML`, retryable: false };
    const references = parseServiceGroupReferences(groupDocument);
    const chosen = chooseReference(references, input.documentType, serviceGroupUrl);
    if (!chosen) return { outcome: 'not-supported', detail: 'no SMP reference matches the document type' };

    // 3. SignedServiceMetadata, following an SMP Redirect at most once. Only
    // facts from the digest-covered document (signature removed) are read.
    let smpUrl = chosen.url;
    let fetched = await fetchXml(smpUrl, fetchImpl, input.signal, timeoutMs);
    if (!fetched.ok) return fetched.result;
    let status = statusResult(fetched.response, smpUrl);
    if (status) return status;
    let document = parse(fetched.response.body);
    if (!document) return { outcome: 'unavailable', reason: `${smpUrl}: response is not XML`, retryable: false };
    let verified = await verifyAndValidate(document, input, now);
    if (!verified.ok) return verified.result;

    const redirect = serviceMetadataRedirectHref(verified.verifiedDocument);
    if (redirect) {
      smpUrl = new URL(redirect, smpUrl).toString();
      fetched = await fetchXml(smpUrl, fetchImpl, input.signal, timeoutMs);
      if (!fetched.ok) return fetched.result;
      status = statusResult(fetched.response, smpUrl);
      if (status) return status;
      document = parse(fetched.response.body);
      if (!document) return { outcome: 'unavailable', reason: `${smpUrl}: response is not XML`, retryable: false };
      verified = await verifyAndValidate(document, input, now);
      if (!verified.ok) return verified.result;
      if (serviceMetadataRedirectHref(verified.verifiedDocument)) {
        return { outcome: 'unavailable', reason: 'SMP redirected more than once', retryable: false };
      }
    }

    // 4. Select the endpoint for the process, transport profile and dates, from
    // the verified document only.
    const selection = selectEndpoint(verified.verifiedDocument, {
      participant: input.participant,
      documentType: input.documentType,
      process: input.process,
      transportProfile,
      now,
    });
    if (!selection.found) return { outcome: 'not-supported', detail: selection.reason };

    return {
      outcome: 'found',
      endpointUrl: selection.endpoint.endpointUrl,
      receiverCertificate: selection.endpoint.receiverCertificate,
      transportProfile: selection.endpoint.transportProfile,
      smpUrl,
      signerCertificate: verified.signerCertificate,
      ...(selection.endpoint.serviceActivationDate
        ? { serviceActivationDate: selection.endpoint.serviceActivationDate }
        : {}),
      ...(selection.endpoint.serviceExpirationDate
        ? { serviceExpirationDate: selection.endpoint.serviceExpirationDate }
        : {}),
    };
  } catch (err) {
    return { outcome: 'unavailable', reason: safeMessage(err), retryable: false };
  }
}

type FetchXmlResult =
  { readonly ok: true; readonly response: HttpGetResponse } | { readonly ok: false; readonly result: LookupResult };

async function fetchXml(
  url: string,
  fetchImpl: typeof fetch,
  signal: AbortSignal | undefined,
  timeoutMs: number,
): Promise<FetchXmlResult> {
  const outcome = await httpGet(url, { fetch: fetchImpl, ...(signal ? { signal } : {}), timeoutMs });
  if (!outcome.ok)
    return { ok: false, result: { outcome: 'unavailable', reason: outcome.reason, retryable: outcome.retryable } };
  return { ok: true, response: outcome.response };
}

/** Map a non-2xx, non-404 SMP response to a result; null when it is a success. */
function statusResult(response: HttpGetResponse, url: string): LookupResult | null {
  if (response.status >= 200 && response.status < 300) return null;
  if (response.status >= 300 && response.status < 400) {
    return {
      outcome: 'unavailable',
      reason: `${url}: unexpected HTTP redirect ${response.location ?? ''}`.trim(),
      retryable: false,
    };
  }
  return { outcome: 'unavailable', reason: `${url}: HTTP ${response.status}`, retryable: response.status >= 500 };
}

function parse(body: Buffer): Document | null {
  try {
    const document = parseXml(body);
    return document.documentElement ? document : null;
  } catch {
    return null;
  }
}

type VerifyResult =
  | { readonly ok: true; readonly signerCertificate: string; readonly verifiedDocument: Document }
  | { readonly ok: false; readonly result: LookupResult };

async function verifyAndValidate(document: Document, input: LookupInput, now: Date): Promise<VerifyResult> {
  const signature = verifySmpSignature(document);
  if (!signature.ok) return { ok: false, result: { outcome: 'signature-invalid', reason: signature.reason } };
  let validation;
  try {
    validation = await input.validateCertificate({
      certificatePem: signature.signerCertificatePem,
      purpose: 'smp-signer',
      now,
      ...(input.signal ? { signal: input.signal } : {}),
    });
  } catch (err) {
    return {
      ok: false,
      result: { outcome: 'unavailable', reason: `SMP signer validation failed: ${safeMessage(err)}`, retryable: false },
    };
  }
  if (!validation.ok) {
    return {
      ok: false,
      result: {
        outcome: 'signature-invalid',
        reason: `SMP signer certificate ${validation.status}: ${validation.reason}`,
      },
    };
  }
  return {
    ok: true,
    signerCertificate: signature.signerCertificatePem,
    verifiedDocument: signature.verifiedDocument,
  };
}
