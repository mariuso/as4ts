import { constants, createHash, verify as cryptoVerify } from 'node:crypto';
import { C14nCanonicalization } from 'xml-crypto';
import { DS_NS } from '../constants.js';
import { normalizePem, parseCertificate } from '../util.js';
import { attrOf, elementsByLocalName, firstByLocalName, textOf } from '../xml/nodes.js';
import { resolveIdUnique } from '../xml/ws-security.js';
import { ALGO_ENVELOPED_SIGNATURE, ALGO_INCLUSIVE_C14N, ALGO_RSA_SHA256, ALGO_SHA256 } from './constants.js';

/**
 * Inclusive C14N 1.0, which the SMP specification mandates (SMP v1.4.0 §5.5.1,
 * `http://www.w3.org/TR/2001/REC-xml-c14n-20010315`). This differs from the
 * AS4 messages, whose signatures use exclusive C14N; the AS4 canonicaliser is
 * deliberately not bent to fit.
 *
 * As in `xml/c14n.ts`, replace xml-crypto's locale-aware namespace comparator
 * with the codepoint one Canonical XML requires.
 */
const canonicalizer = new C14nCanonicalization();
(canonicalizer as unknown as { nsCompare: (a: { prefix?: string }, b: { prefix?: string }) => number }).nsCompare = (
  a,
  b,
) => {
  const pa = a.prefix ?? '';
  const pb = b.prefix ?? '';
  return pa === pb ? 0 : pa < pb ? -1 : 1;
};

/** Inclusive C14N 1.0, as the SMP specification mandates. Exported for the fixture signer. */
export function inclusiveCanonicalize(node: Node): string {
  return canonicalizer.process(node, {});
}

export type SmpSignatureVerification =
  { readonly ok: true; readonly signerCertificatePem: string } | { readonly ok: false; readonly reason: string };

/**
 * Verify the enveloped XML signature on a Peppol SMP `SignedServiceMetadata`
 * response, per SMP v1.4.0 §5.5.1:
 *
 *  - `ds:Signature` with exactly one `enveloped-signature` transform;
 *  - inclusive C14N, RSA-SHA256 and SHA-256 only; anything else is rejected;
 *  - the signer certificate in `ds:KeyInfo/ds:X509Data/ds:X509Certificate`.
 *
 * The certificate is only extracted here; the caller validates it. Nothing is
 * thrown.
 */
export function verifySmpSignature(document: Document): SmpSignatureVerification {
  const signature = elementsByLocalName(document, DS_NS, 'Signature')[0] ?? null;
  if (!signature) return fail('no ds:Signature found');

  const signerPem = extractSignerCertificate(signature);
  if (!signerPem) return fail('no ds:X509Certificate in ds:KeyInfo');

  const signedInfo = firstByLocalName(signature, DS_NS, 'SignedInfo');
  if (!signedInfo) return fail('no ds:SignedInfo');

  const c14nMethod = firstByLocalName(signedInfo, DS_NS, 'CanonicalizationMethod');
  if (attrOf(c14nMethod, 'Algorithm') !== ALGO_INCLUSIVE_C14N) {
    return fail('SMP signatures must use inclusive C14N (SMP v1.4.0 §5.5.1)');
  }
  const signatureMethod = firstByLocalName(signedInfo, DS_NS, 'SignatureMethod');
  if (attrOf(signatureMethod, 'Algorithm') !== ALGO_RSA_SHA256) {
    return fail('SMP signatures must use rsa-sha256 (SMP v1.4.0 §5.5.1)');
  }

  const references = elementsByLocalName(signedInfo, DS_NS, 'Reference');
  if (references.length === 0) return fail('ds:SignedInfo has no references');
  for (const reference of references) {
    const transforms = elementsByLocalName(reference, DS_NS, 'Transform');
    if (transforms.length !== 1 || attrOf(transforms[0] ?? null, 'Algorithm') !== ALGO_ENVELOPED_SIGNATURE) {
      return fail('every SMP reference must use exactly the enveloped-signature transform');
    }
    const digestMethod = firstByLocalName(reference, DS_NS, 'DigestMethod');
    if (attrOf(digestMethod, 'Algorithm') !== ALGO_SHA256) {
      return fail('SMP references must use SHA-256 (SMP v1.4.0 §5.5.1)');
    }
    const expected = textOf(firstByLocalName(reference, DS_NS, 'DigestValue'))?.trim();
    if (!expected) return fail('missing ds:DigestValue');

    const uri = attrOf(reference, 'URI') ?? '';
    const target = resolveReferenceTarget(document, uri);
    if (!target.ok) return fail(target.reason);
    const actual = createHash('sha256').update(inclusiveCanonicalize(target.node), 'utf8').digest('base64');
    if (actual !== expected) return fail(`digest mismatch for reference ${uri || '(document)'}`);
  }

  const signatureValue = textOf(firstByLocalName(signature, DS_NS, 'SignatureValue'))?.trim();
  if (!signatureValue) return fail('no ds:SignatureValue');

  let signer;
  try {
    signer = parseCertificate(signerPem);
  } catch {
    return fail('the ds:X509Certificate is not readable');
  }
  let verified = false;
  try {
    verified = cryptoVerify(
      'sha256',
      Buffer.from(inclusiveCanonicalize(signedInfo), 'utf8'),
      { key: signer.publicKey, padding: constants.RSA_PKCS1_PADDING },
      Buffer.from(signatureValue, 'base64'),
    );
  } catch {
    verified = false;
  }
  if (!verified) return fail('ds:SignatureValue does not verify over ds:SignedInfo');

  return { ok: true, signerCertificatePem: signerPem };
}

function fail(reason: string): SmpSignatureVerification {
  return { ok: false, reason };
}

type TargetResolution = { readonly ok: true; readonly node: Node } | { readonly ok: false; readonly reason: string };

/**
 * The enveloped-signature transform: the referenced node-set is the document
 * with the signature removed. Work on a clone so the original document (whose
 * SignedInfo we still need) is untouched.
 */
function resolveReferenceTarget(document: Document, uri: string): TargetResolution {
  const clone = document.cloneNode(true) as Document;
  const signature = elementsByLocalName(clone, DS_NS, 'Signature')[0] ?? null;
  if (signature?.parentNode) signature.parentNode.removeChild(signature);

  if (uri === '') {
    const root = clone.documentElement;
    return root ? { ok: true, node: root } : { ok: false, reason: 'the response has no document element' };
  }
  if (!uri.startsWith('#')) return { ok: false, reason: `unsupported reference URI ${uri}` };
  const resolved = resolveIdUnique(clone, uri.slice(1));
  if (resolved.matches > 1) return { ok: false, reason: `duplicate id ${uri}` };
  if (!resolved.element) return { ok: false, reason: `unresolved reference ${uri}` };
  return { ok: true, node: resolved.element };
}

function extractSignerCertificate(signature: Element): string | null {
  const keyInfo = firstByLocalName(signature, DS_NS, 'KeyInfo');
  if (!keyInfo) return null;
  const x509Data = firstByLocalName(keyInfo, DS_NS, 'X509Data');
  const certificate = firstByLocalName(x509Data, DS_NS, 'X509Certificate');
  const base64 = certificate ? textOf(certificate)?.replace(/\s+/g, '') : null;
  return base64 ? normalizePem(`-----BEGIN CERTIFICATE-----\n${base64}\n-----END CERTIFICATE-----`) : null;
}
