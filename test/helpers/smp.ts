import { constants, createHash, sign as cryptoSign } from 'node:crypto';
import type { ParticipantId, ScopedId } from '../../src/types.js';
import { firstByLocalName, parseXml, serializeXml } from '../../src/xml/nodes.js';
import { inclusiveCanonicalize } from '../../src/lookup/smp-signature.js';
import type { TestCert } from './pki.js';

export const SMP_NS = 'http://busdox.org/serviceMetadata/publishing/1.0/';
export const IDS_NS = 'http://busdox.org/transport/identifiers/1.0/';
export const WSA_NS = 'http://www.w3.org/2005/08/addressing';
export const DS_NS = 'http://www.w3.org/2000/09/xmldsig#';

const ALGO_INCLUSIVE_C14N = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
const ALGO_ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';
const ALGO_RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
const ALGO_SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';

export interface ServiceGroupReference {
  readonly documentType: ScopedId;
  readonly href: string;
}

export function buildServiceGroup(participant: ParticipantId, references: readonly ServiceGroupReference[]): string {
  const refs = references
    .map((reference) => `    <ServiceMetadataReference href="${escapeAttribute(reference.href)}"/>`)
    .join('\n');
  return (
    `<?xml version="1.0" encoding="UTF-8"?>` +
    `<ServiceGroup xmlns="${SMP_NS}" xmlns:ids="${IDS_NS}">` +
    `<ids:ParticipantIdentifier scheme="${escapeAttribute(participant.scheme)}">${escapeText(participant.value)}</ids:ParticipantIdentifier>` +
    `<ServiceMetadataReferenceCollection>${refs}</ServiceMetadataReferenceCollection>` +
    `</ServiceGroup>`
  );
}

export interface SignedServiceMetadataOptions {
  readonly participant: ParticipantId;
  readonly documentType: ScopedId;
  readonly process: ScopedId;
  readonly transportProfile: string;
  readonly endpointUrl: string;
  readonly receiverCertificatePem: string;
  readonly serviceActivationDate?: string;
  readonly serviceExpirationDate?: string;
  /** Sign the document with this certificate. */
  readonly signer: TestCert;
  /** Emit a ServiceMetadata/Redirect instead of ServiceInformation. */
  readonly redirectHref?: string;
}

/**
 * Build a `SignedServiceMetadata` with a genuine enveloped inclusive-C14N
 * signature, matching Peppol SMP v1.4.0 §5.5.1. Useful for offline tests; real
 * captures are added separately by the owner.
 */
export function buildSignedServiceMetadata(options: SignedServiceMetadataOptions): string {
  const certificate = options.receiverCertificatePem.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, '');
  const serviceMetadata = options.redirectHref
    ? `<ServiceMetadata><Redirect href="${escapeAttribute(options.redirectHref)}"><CertificateUID>PID:test</CertificateUID></Redirect></ServiceMetadata>`
    : `<ServiceMetadata><ServiceInformation>` +
      `<ids:ParticipantIdentifier scheme="${escapeAttribute(options.participant.scheme)}">${escapeText(options.participant.value)}</ids:ParticipantIdentifier>` +
      `<ids:DocumentIdentifier scheme="${escapeAttribute(options.documentType.scheme)}">${escapeText(options.documentType.value)}</ids:DocumentIdentifier>` +
      `<ProcessList><Process>` +
      `<ids:ProcessIdentifier scheme="${escapeAttribute(options.process.scheme)}">${escapeText(options.process.value)}</ids:ProcessIdentifier>` +
      `<ServiceEndpointList><Endpoint transportProfile="${escapeAttribute(options.transportProfile)}">` +
      `<wsa:EndpointReference><wsa:Address>${escapeText(options.endpointUrl)}</wsa:Address></wsa:EndpointReference>` +
      `<RequireBusinessLevelSignature>false</RequireBusinessLevelSignature>` +
      `${date(options.serviceActivationDate, 'ServiceActivationDate')}` +
      `${date(options.serviceExpirationDate, 'ServiceExpirationDate')}` +
      `<Certificate>${certificate}</Certificate>` +
      `</Endpoint></ServiceEndpointList>` +
      `</Process></ProcessList>` +
      `</ServiceInformation></ServiceMetadata>`;

  const embedded = options.signer.certPem.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, '');
  const xml =
    `<?xml version="1.0" encoding="UTF-8"?>` +
    `<SignedServiceMetadata xmlns="${SMP_NS}" xmlns:ids="${IDS_NS}" xmlns:wsa="${WSA_NS}" xmlns:ds="${DS_NS}">` +
    serviceMetadata +
    `<ds:Signature>` +
    `<ds:SignedInfo>` +
    `<ds:CanonicalizationMethod Algorithm="${ALGO_INCLUSIVE_C14N}"/>` +
    `<ds:SignatureMethod Algorithm="${ALGO_RSA_SHA256}"/>` +
    `<ds:Reference URI="">` +
    `<ds:Transforms><ds:Transform Algorithm="${ALGO_ENVELOPED}"/></ds:Transforms>` +
    `<ds:DigestMethod Algorithm="${ALGO_SHA256}"/>` +
    `<ds:DigestValue></ds:DigestValue>` +
    `</ds:Reference>` +
    `</ds:SignedInfo>` +
    `<ds:SignatureValue></ds:SignatureValue>` +
    `<ds:KeyInfo><ds:X509Data><ds:X509Certificate>${embedded}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>` +
    `</ds:Signature>` +
    `</SignedServiceMetadata>`;

  const document = parseXml(xml);
  const signature = firstByLocalName(document, DS_NS, 'Signature')!;
  const signedInfo = firstByLocalName(signature, DS_NS, 'SignedInfo')!;

  const clone = document.cloneNode(true) as Document;
  const clonedSignature = firstByLocalName(clone, DS_NS, 'Signature')!;
  clonedSignature.parentNode!.removeChild(clonedSignature);
  const digest = createHash('sha256').update(inclusiveCanonicalize(clone.documentElement!), 'utf8').digest('base64');
  setText(firstByLocalName(signature, DS_NS, 'DigestValue')!, digest);

  const signatureValue = cryptoSign('sha256', Buffer.from(inclusiveCanonicalize(signedInfo), 'utf8'), {
    key: options.signer.keyObject,
    padding: constants.RSA_PKCS1_PADDING,
  }).toString('base64');
  setText(firstByLocalName(signature, DS_NS, 'SignatureValue')!, signatureValue);

  return serializeXml(document);
}

function date(value: string | undefined, name: string): string {
  return value ? `<${name}>${escapeText(value)}</${name}>` : '';
}

function setText(element: Element, text: string): void {
  while (element.firstChild) element.removeChild(element.firstChild);
  element.appendChild(element.ownerDocument!.createTextNode(text));
}

function escapeText(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function escapeAttribute(value: string): string {
  return escapeText(value).replace(/"/g, '&quot;');
}
