import { createHash } from 'node:crypto';
import { resolveNaptr } from 'node:dns/promises';
import { attrOf, elementsByLocalName, firstByLocalName, parseXml, textOf } from '../../src/xml/nodes.js';

// SMP XML namespaces, from the PEPPOL SMP specification.
const SMP_NS = 'http://busdox.org/serviceMetadata/publishing/1.0/';
const WSA_NS = 'http://www.w3.org/2005/08/addressing';

// OpenPeppol SML zones. The participant record is
// `<base32(sha256(value))>.iso6523-actorid-upis.<zone>`, queried by NAPTR.
const SML = {
  test: 'participant.sml.test.tech.peppol.org',
  prod: 'participant.sml.tech.peppol.org',
} as const;

export type SmEnv = 'test' | 'prod';

export interface SmpLookupOptions {
  /** Full participant id, e.g. `iso6523-actorid-upis::0192:222222222`. */
  readonly participant: string;
  readonly env: SmEnv;
  /** Substring of the document identifier to select among several, e.g. `Invoice-2`. */
  readonly documentType?: string;
}

export interface SmpServiceInfo {
  readonly documentScheme: string | null;
  readonly documentIdentifier: string | null;
  readonly processScheme: string | null;
  readonly processIdentifier: string | null;
  readonly transportProfile: string | null;
  readonly endpointUrl: string | null;
  readonly certificatePem: string | null;
}

function base32(buffer: Buffer): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const byte of buffer) bits += byte.toString(2).padStart(8, '0');
  while (bits.length % 5 !== 0) bits += '0';
  let out = '';
  for (let i = 0; i + 5 <= bits.length; i += 5) out += alphabet[parseInt(bits.slice(i, i + 5), 2)];
  return out;
}

async function resolveSmpBase(participant: string, env: SmEnv): Promise<string> {
  const value = participant.includes('::') ? participant.split('::')[1]! : participant;
  const hash = base32(createHash('sha256').update(value.toLowerCase(), 'utf8').digest());
  const domain = `${hash}.iso6523-actorid-upis.${SML[env]}`;
  const records = await resolveNaptr(domain);
  for (const r of records.sort((left, right) => left.order - right.order)) {
    if ((r.flags ?? '').toLowerCase() !== 'u' || (r.service ?? '').toLowerCase() !== 'meta:smp') continue;
    const delim = r.regexp[0]!;
    const [, pattern, replace] = r.regexp.split(delim);
    if (pattern === undefined || replace === undefined) continue;
    const url = domain.replace(new RegExp(`^${pattern}$`), replace);
    if (url.startsWith('https://') || url.startsWith('http://')) return url.replace(/\/$/, '');
  }
  throw new Error(`no usable NAPTR record for ${domain}`);
}

async function get(url: string): Promise<Document> {
  const res = await fetch(url, { headers: { Accept: '*/*' } });
  if (!res.ok) throw new Error(`GET ${url} -> HTTP ${res.status}`);
  return parseXml(Buffer.from(await res.arrayBuffer()));
}

function decodeDoc(href: string): string {
  const segment = decodeURIComponent(href).split('/services/')[1] ?? '';
  return segment.includes('::') ? segment.split('::').slice(1).join('::') : segment;
}

function parseService(doc: Document): SmpServiceInfo {
  const documentIdentifierEl = firstByLocalName(doc, '*', 'DocumentIdentifier');
  const processEl = firstByLocalName(doc, '*', 'ProcessIdentifier');
  const endpoint =
    elementsByLocalName(doc, SMP_NS, 'Endpoint').find((e) =>
      (attrOf(e, 'transportProfile') ?? '').startsWith('peppol-transport-as4'),
    ) ?? null;
  const address = firstByLocalName(endpoint, WSA_NS, 'Address');
  const certEl = firstByLocalName(endpoint, SMP_NS, 'Certificate');
  const certB64 = textOf(certEl)?.replace(/\s+/g, '');
  return {
    documentScheme: attrOf(documentIdentifierEl, 'scheme'),
    documentIdentifier: textOf(documentIdentifierEl),
    processScheme: attrOf(processEl, 'scheme'),
    processIdentifier: textOf(processEl),
    transportProfile: attrOf(endpoint, 'transportProfile'),
    endpointUrl: textOf(address),
    certificatePem: certB64
      ? `-----BEGIN CERTIFICATE-----\n${(certB64.match(/.{1,64}/g) ?? []).join('\n')}\n-----END CERTIFICATE-----`
      : null,
  };
}

export interface SmpLookupResult extends SmpServiceInfo {
  readonly smpBase: string;
  readonly references: readonly string[];
}

// Standard Peppol BIS Billing 3.0 Invoice document identifier. Used as the
// default when the caller gives no hint and the participant publishes it.
const PEPPOL_BIS_3_INVOICE =
  'urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice##urn:cen.eu:en16931:2017#compliant#urn:fdc:peppol.eu:2017:poacc:billing:3.0::2.1';

/** Resolve a participant's AS4 endpoint, certificate and business identifiers. */
export async function lookupParticipant(options: SmpLookupOptions): Promise<SmpLookupResult> {
  const smpBase = await resolveSmpBase(options.participant, options.env);
  const serviceGroup = await get(`${smpBase}/${encodeURIComponent(options.participant)}`);
  const refs = elementsByLocalName(serviceGroup, SMP_NS, 'ServiceMetadataReference')
    .map((el) => el.getAttribute('href'))
    .filter((href): href is string => Boolean(href));
  if (refs.length === 0) throw new Error('participant publishes no service metadata references');

  const wanted = options.documentType;
  const chosen = wanted
    ? (refs.find((href) => decodeDoc(href).includes(wanted)) ?? null)
    : (refs.find((href) => decodeDoc(href) === PEPPOL_BIS_3_INVOICE) ??
      refs.find(
        (href) => decodeDoc(href).includes('poacc:billing:3.0') && decodeDoc(href).includes('Invoice-2::Invoice'),
      ) ??
      refs[0]!);
  if (!chosen) throw new Error(`no SMP reference matches document type "${wanted}"`);

  return { smpBase, references: refs.map(decodeDoc), ...parseService(await get(chosen)) };
}
