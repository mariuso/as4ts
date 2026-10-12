import { constants, createHash, verify as cryptoVerify } from 'node:crypto';
import type { X509Certificate } from 'node:crypto';
import { ALGO_EXC_C14N, ALGO_RSA_SHA256, ALGO_SHA256, DS_NS, WSSE_NS, WSU_NS } from '../constants.js';
import { normalizePem, parseCertificate } from '../util.js';
import { canonicalize, canonicalizeDigest, materializeInclusiveNamespaces } from './c14n.js';
import { attrOf, elementsByLocalName, firstByLocalName, textOf } from './nodes.js';

/** One reference declared in a signature's SignedInfo: its URI and base64 digest. */
export interface SignedReference {
  readonly uri: string;
  readonly digest: string;
}

/** The facts a verified WS-Security signature yields. Direction-neutral. */
export interface VerifiedSignature {
  /** The signer's X.509 certificate (PEM), taken from the signed KeyInfo. */
  readonly signerCertificatePem: string;
  readonly signerCertificate: X509Certificate;
  /** Every reference declared in SignedInfo, including non-envelope (`cid:`) ones. */
  readonly references: readonly SignedReference[];
  /** The in-envelope elements whose digests actually verified. */
  readonly coveredElements: readonly Element[];
}

export type SignatureFailureReason = 'malformed' | 'bad-signature' | 'digest-mismatch';

export interface SignatureVerificationFailure {
  readonly ok: false;
  readonly reason: SignatureFailureReason;
  readonly detail: string;
}

export type SignatureVerification =
  { readonly ok: true; readonly signature: VerifiedSignature } | SignatureVerificationFailure;

/**
 * Verify the WS-Security XML signature of an envelope and report what it covers.
 *
 * This is the direction-neutral half of receipt verification: it checks the
 * signature with no knowledge of what the message means, so a future receiver
 * can verify an inbound user message with the same code. It applies:
 *
 *  - exclusive C14N (`InclusiveNamespaces/PrefixList` honoured) and RSA-SHA256
 *    over `ds:SignedInfo`;
 *  - the duplicate-id rejection: a reference URI is resolved only when exactly
 *    one element carries the id, so an attacker cannot shadow it;
 *  - SHA-256 reference digests, with the digest of each resolvable in-envelope
 *    element compared to its `DigestValue` (non-envelope `cid:` references are
 *    returned but not resolved here).
 *
 * It does **not** decide what the signature must cover, and it does **not**
 * validate the signer certificate: both are the caller's policy. Every failure
 * is a value with a reason in the `malformed` / `bad-signature` /
 * `digest-mismatch` family; nothing is thrown.
 */
export function verifyWsSecuritySignature(doc: Document): SignatureVerification {
  const signature = findSignature(doc);
  if (!signature) return fail('malformed', 'no WS-Security signature found');

  const signerPem = extractSignerCertificate(doc, signature);
  if (!signerPem) return fail('malformed', 'no signer certificate found');
  const signer = parseCertificate(signerPem);

  const signedInfo = firstByLocalName(signature, DS_NS, 'SignedInfo');
  if (!signedInfo) return fail('malformed', 'no SignedInfo');

  const c14nMethod = firstByLocalName(signedInfo, DS_NS, 'CanonicalizationMethod');
  if (attrOf(c14nMethod, 'Algorithm') !== ALGO_EXC_C14N) {
    return fail('bad-signature', 'unexpected canonicalization method');
  }
  const signatureMethod = firstByLocalName(signedInfo, DS_NS, 'SignatureMethod');
  if (attrOf(signatureMethod, 'Algorithm') !== ALGO_RSA_SHA256) {
    return fail('bad-signature', 'unexpected signature method');
  }

  const inclusivePrefixes = inclusivePrefixList(c14nMethod);
  materializeInclusiveNamespaces(signedInfo, inclusivePrefixes);
  const canonicalSignedInfo = inclusivePrefixes.length
    ? canonicalize(signedInfo, inclusivePrefixes)
    : canonicalize(signedInfo);

  const signatureValue = textOf(firstByLocalName(signature, DS_NS, 'SignatureValue'));
  if (!signatureValue) return fail('malformed', 'no SignatureValue');
  const signatureBytes = Buffer.from(signatureValue.trim(), 'base64');
  const signatureOk = cryptoVerify(
    'sha256',
    Buffer.from(canonicalSignedInfo, 'utf8'),
    { key: signer.publicKey, padding: constants.RSA_PKCS1_PADDING },
    signatureBytes,
  );
  if (!signatureOk) return fail('bad-signature', 'SignatureValue does not verify over SignedInfo');

  const references = verifyReferences(doc, signedInfo);
  if (!references.ok) return references;
  if (references.coveredElements.length === 0) {
    return fail('malformed', 'no verifiable in-envelope references');
  }

  return {
    ok: true,
    signature: {
      signerCertificatePem: signerPem,
      signerCertificate: signer,
      references: references.references,
      coveredElements: references.coveredElements,
    },
  };
}

const fail = (reason: SignatureFailureReason, detail: string): SignatureVerificationFailure => ({
  ok: false,
  reason,
  detail,
});

type ReferencesVerification =
  | { readonly ok: true; readonly references: readonly SignedReference[]; readonly coveredElements: readonly Element[] }
  | SignatureVerificationFailure;

/**
 * Verify the digests of the SignedInfo references and report which in-envelope
 * elements they cover. `cid:` references target the original message's
 * attachment, which is not part of the signed XML; they are returned with their
 * declared digest but never resolved against the document.
 */
function verifyReferences(doc: Document, signedInfo: Element): ReferencesVerification {
  const references = elementsByLocalName(signedInfo, DS_NS, 'Reference');
  if (references.length === 0) return fail('malformed', 'SignedInfo has no references');

  const declared: SignedReference[] = [];
  const coveredElements: Element[] = [];
  for (const reference of references) {
    const uri = attrOf(reference, 'URI') ?? '';
    const digest = textOf(firstByLocalName(reference, DS_NS, 'DigestValue'))?.trim();
    if (!digest) return fail('malformed', 'missing DigestValue');
    declared.push({ uri, digest });

    if (uri.startsWith('cid:')) continue; // attachment; not resolvable here
    if (!uri.startsWith('#')) return fail('malformed', `unsupported reference ${uri}`);

    const resolved = resolveIdUnique(doc, uri.slice(1));
    if (resolved.matches > 1) return fail('malformed', `duplicate id ${uri}`);
    if (!resolved.element) return fail('malformed', `unresolved reference ${uri}`);

    const digestMethod = firstByLocalName(reference, DS_NS, 'DigestMethod');
    if (attrOf(digestMethod, 'Algorithm') !== ALGO_SHA256) {
      return fail('bad-signature', 'unexpected digest method');
    }

    const prefixes = referenceInclusivePrefixes(reference);
    materializeInclusiveNamespaces(resolved.element, prefixes);
    const actual = prefixes.length
      ? createHash('sha256').update(canonicalize(resolved.element, prefixes), 'utf8').digest('base64')
      : canonicalizeDigest(resolved.element);
    if (actual !== digest) return fail('digest-mismatch', `digest mismatch for ${uri}`);
    coveredElements.push(resolved.element);
  }
  return { ok: true, references: declared, coveredElements };
}

function findSignature(doc: Document): Element | null {
  for (const security of elementsByLocalName(doc, WSSE_NS, 'Security')) {
    const signature = firstByLocalName(security, DS_NS, 'Signature');
    if (signature) return signature;
  }
  return elementsByLocalName(doc, DS_NS, 'Signature')[0] ?? null;
}

function extractSignerCertificate(doc: Document, signature: Element): string | null {
  const keyInfo = firstByLocalName(signature, DS_NS, 'KeyInfo');
  if (!keyInfo) return null;

  const str = firstByLocalName(keyInfo, WSSE_NS, 'SecurityTokenReference');
  if (str) {
    const reference = firstByLocalName(str, WSSE_NS, 'Reference');
    const uri = attrOf(reference, 'URI');
    const id = uri?.startsWith('#') ? uri.slice(1) : null;
    if (id) {
      const resolved = resolveIdUnique(doc, id);
      const token = resolved.element;
      const b64 = token ? textOf(token)?.replace(/\s+/g, '') : null;
      if (b64) return derBase64ToPem(b64);
    }
  }

  const inline = firstByLocalName(keyInfo, DS_NS, 'X509Certificate');
  const b64 = inline ? textOf(inline)?.replace(/\s+/g, '') : null;
  return b64 ? derBase64ToPem(b64) : null;
}

interface ResolveResult {
  readonly element: Element | null;
  readonly matches: number;
}

/** Resolve an XML id, and report how many elements carry it (duplicates are fatal). */
export function resolveIdUnique(doc: Document, id: string): ResolveResult {
  const all = doc.getElementsByTagName('*');
  const matches: Element[] = [];
  for (let i = 0; i < all.length; i += 1) {
    const element = all.item(i);
    if (!element) continue;
    if (
      element.getAttributeNS(WSU_NS, 'Id') === id ||
      element.getAttribute('Id') === id ||
      element.getAttribute('id') === id
    ) {
      matches.push(element);
    }
  }
  return { element: matches.length === 1 ? matches[0]! : null, matches: matches.length };
}

function inclusivePrefixList(c14nMethod: Element | null): string[] {
  if (!c14nMethod) return [];
  const inc = firstByLocalName(c14nMethod, ALGO_EXC_C14N, 'InclusiveNamespaces');
  const list = attrOf(inc, 'PrefixList');
  return list ? list.split(/\s+/).filter(Boolean) : [];
}

function referenceInclusivePrefixes(reference: Element): string[] {
  const transform = elementsByLocalName(reference, DS_NS, 'Transform')[0];
  if (!transform) return [];
  const inc = firstByLocalName(transform, ALGO_EXC_C14N, 'InclusiveNamespaces');
  const list = attrOf(inc, 'PrefixList');
  return list ? list.split(/\s+/).filter(Boolean) : [];
}

function derBase64ToPem(base64: string): string {
  return normalizePem(`-----BEGIN CERTIFICATE-----\n${base64}\n-----END CERTIFICATE-----`);
}
