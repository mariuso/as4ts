import type { ParticipantId, ScopedId } from '../types.js';
import { attrOf, elementsByLocalName, firstByLocalName, textOf } from '../xml/nodes.js';
import { IDS_NS, PEPPOL_DOCTYPE_WILDCARD, SMP_NS, WSA_NS } from './constants.js';

/** Build the REST segment for a participant: `<meta scheme>::<value>`. SMP v1.4.0 §5.3.2. */
export function participantSegment(participant: ParticipantId): string {
  return `${participant.scheme}::${participant.value}`;
}

/** The `ServiceMetadataReference/@href` values of a ServiceGroup document. */
export function parseServiceGroupReferences(document: Document): string[] {
  return elementsByLocalName(document, SMP_NS, 'ServiceMetadataReference')
    .map((element) => element.getAttribute('href'))
    .filter((href): href is string => typeof href === 'string' && href.length > 0);
}

/** The href of an SMP `ServiceMetadata/Redirect`, if the resource is a redirect. */
export function serviceMetadataRedirectHref(document: Document): string | null {
  return attrOf(firstByLocalName(document, SMP_NS, 'Redirect'), 'href');
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

/** Decode the document type identifier from a SignedServiceMetadata/Redirect URL. */
export function documentTypeFromHref(href: string, base: string): ScopedId | null {
  let url: URL;
  try {
    url = new URL(href, base);
  } catch {
    return null;
  }
  const segments = url.pathname.split('/');
  const index = segments.indexOf('services');
  if (index < 0 || index + 1 >= segments.length) return null;
  const decoded = safeDecode(segments[index + 1]!);
  const separator = decoded.indexOf('::');
  if (separator < 0) return null;
  return { scheme: decoded.slice(0, separator), value: decoded.slice(separator + 2) };
}

/**
 * Whether a registered document type identifier matches the requested one.
 *
 * Implemented: exact scheme+value for the same scheme (e.g. `busdox-docid-qns`),
 * and a value match when the registered scheme is `peppol-doctype-wildcard`
 * (Policy for use of Identifiers v4.4.0 §5.1). The wildcard `*` must be the last
 * character and generalises zero or more further `@`-separated parts, so `a@b*`
 * matches `a@b` and `a@b@c` but not `a@c`. This is an approximation of the
 * Customization ID rules and is marked UNVERIFIED in the README.
 */
export function documentTypeMatches(requested: ScopedId, candidate: ScopedId): boolean {
  if (requested.scheme === candidate.scheme) {
    return candidate.value.endsWith('*')
      ? wildcardValueMatches(requested.value, candidate.value)
      : requested.value === candidate.value;
  }
  if (candidate.scheme === PEPPOL_DOCTYPE_WILDCARD) return wildcardValueMatches(requested.value, candidate.value);
  return false;
}

function wildcardValueMatches(value: string, pattern: string): boolean {
  if (!pattern.endsWith('*')) return value === pattern;
  const prefix = pattern.slice(0, -1);
  return value === prefix || value.startsWith(`${prefix}@`);
}

export interface ChosenReference {
  readonly url: string;
  readonly documentType: ScopedId;
}

/**
 * Pick the SMP reference whose document type matches the request. Exact matches
 * win over wildcard ones, then the more specific (longer) registration.
 */
export function chooseReference(hrefs: readonly string[], requested: ScopedId, base: string): ChosenReference | null {
  const matches: ChosenReference[] = [];
  for (const href of hrefs) {
    const documentType = documentTypeFromHref(href, base);
    if (!documentType) continue;
    if (documentTypeMatches(requested, documentType)) {
      matches.push({ url: new URL(href, base).toString(), documentType });
    }
  }
  if (matches.length === 0) return null;
  matches.sort((a, b) => {
    const aw = a.documentType.value.endsWith('*') ? 1 : 0;
    const bw = b.documentType.value.endsWith('*') ? 1 : 0;
    return aw - bw || b.documentType.value.length - a.documentType.value.length;
  });
  return matches[0]!;
}

export interface SelectedEndpoint {
  readonly endpointUrl: string;
  readonly receiverCertificate: string;
  readonly transportProfile: string;
  readonly serviceActivationDate?: string;
  readonly serviceExpirationDate?: string;
}

export type EndpointSelection =
  { readonly found: true; readonly endpoint: SelectedEndpoint } | { readonly found: false; readonly reason: string };

export interface SelectEndpointInput {
  readonly participant: ParticipantId;
  readonly documentType: ScopedId;
  readonly process: ScopedId;
  readonly transportProfile: string;
  readonly now: Date;
}

/**
 * Find the endpoint for the requested participant, document type, process and
 * transport profile, respecting the service activation/expiration dates. A
 * missing activation date means "valid since forever"; a missing expiration
 * date means "valid until eternity" (SMP v1.4.0 §4.3).
 *
 * Every element is matched in its specification namespace — never by local name
 * in any namespace — so a look-alike element in a foreign namespace is ignored.
 */
export function selectEndpoint(document: Document, input: SelectEndpointInput): EndpointSelection {
  const participantEl = firstByLocalName(document, IDS_NS, 'ParticipantIdentifier');
  if (!participantEl) return { found: false, reason: 'SMP response has no ParticipantIdentifier' };
  const gotScheme = attrOf(participantEl, 'scheme') ?? '';
  const gotValue = textOf(participantEl) ?? '';
  if (gotScheme !== input.participant.scheme || gotValue.toLowerCase() !== input.participant.value.toLowerCase()) {
    return { found: false, reason: 'SMP response is for a different participant' };
  }

  const documentEl = firstByLocalName(document, IDS_NS, 'DocumentIdentifier');
  const gotDocument: ScopedId = { scheme: attrOf(documentEl, 'scheme') ?? '', value: textOf(documentEl) ?? '' };
  if (!documentTypeMatches(input.documentType, gotDocument)) {
    return { found: false, reason: 'SMP response is for a different document type' };
  }

  for (const process of elementsByLocalName(document, SMP_NS, 'Process')) {
    const identifier = firstByLocalName(process, IDS_NS, 'ProcessIdentifier');
    if ((attrOf(identifier, 'scheme') ?? '') !== input.process.scheme) continue;
    if ((textOf(identifier) ?? '') !== input.process.value) continue;

    for (const endpoint of elementsByLocalName(process, SMP_NS, 'Endpoint')) {
      if ((attrOf(endpoint, 'transportProfile') ?? '') !== input.transportProfile) continue;
      const activation = textOf(firstByLocalName(endpoint, SMP_NS, 'ServiceActivationDate'));
      const expiration = textOf(firstByLocalName(endpoint, SMP_NS, 'ServiceExpirationDate'));
      if (!withinWindow(activation, expiration, input.now)) continue;
      const address = textOf(firstByLocalName(endpoint, WSA_NS, 'Address'));
      const certificateBase64 = textOf(firstByLocalName(endpoint, SMP_NS, 'Certificate'))?.replace(/\s+/g, '');
      if (!address || !certificateBase64) continue;
      return {
        found: true,
        endpoint: {
          endpointUrl: address,
          receiverCertificate: pem('CERTIFICATE', certificateBase64),
          transportProfile: input.transportProfile,
          ...(activation ? { serviceActivationDate: activation } : {}),
          ...(expiration ? { serviceExpirationDate: expiration } : {}),
        },
      };
    }
  }
  return { found: false, reason: 'no endpoint for the process, transport profile and dates requested' };
}

function withinWindow(activation: string | null, expiration: string | null, now: Date): boolean {
  if (activation) {
    const from = new Date(activation);
    if (!Number.isNaN(from.getTime()) && now < from) return false;
  }
  if (expiration) {
    const to = new Date(expiration);
    if (!Number.isNaN(to.getTime()) && now > to) return false;
  }
  return true;
}

function pem(label: string, base64: string): string {
  const wrapped = (base64.match(/.{1,64}/g) ?? []).join('\n');
  return `-----BEGIN ${label}-----\n${wrapped}\n-----END ${label}-----`;
}
