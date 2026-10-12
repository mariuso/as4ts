import { constants, createHash, verify as cryptoVerify } from 'node:crypto';
import { ALGO_EXC_C14N, ALGO_RSA_SHA256, ALGO_SHA256, DS_NS, EBBP_SIGNALS_NS, WSSE_NS, WSU_NS } from '../constants.js';
import type { ReceiptEvidence, ReceiptFailureReason, ValidateCertificate } from '../types.js';
import { commonNameOf, normalizePem, parseCertificate, sameCertificate } from '../util.js';
import { canonicalize, canonicalizeDigest, materializeInclusiveNamespaces } from '../xml/c14n.js';
import { attrOf, elementsByLocalName, firstByLocalName, textOf } from '../xml/nodes.js';
import type { ParsedSignal } from '../xml/signal.js';

export interface SignedReference {
  readonly uri: string;
  readonly digest: string;
}

export interface ReceiptCheckInput {
  readonly signal: ParsedSignal;
  readonly as4MessageId: string;
  readonly receiverCertificatePem: string;
  /** The references we put in our own SignedInfo (Body, Messaging, attachment). */
  readonly signedReferences: readonly SignedReference[];
  /** Required. Validates the receipt signer before the receipt is accepted. */
  readonly validateCertificate: ValidateCertificate;
  readonly now: () => Date;
  /** Caller abort signal; aborts a revocation check during receipt verification. */
  readonly abort?: AbortSignal;
}

export type ReceiptCheck =
  | { readonly ok: true; readonly receipt: ReceiptEvidence; readonly signerCertificatePem: string }
  | { readonly ok: false; readonly reason: ReceiptFailureReason; readonly detail: string };

const fail = (reason: ReceiptFailureReason, detail: string): ReceiptCheck => ({ ok: false, reason, detail });

/**
 * Verify an AS4 receipt fully. Acceptance requires all of:
 *  - a valid XML signature over SignedInfo, made with RSA-SHA256 and exclusive C14N;
 *  - the signature actually covers the eb:Messaging/SignalMessage we read
 *    (otherwise a forged unsigned receipt could be prepended to a genuine one);
 *  - the signer certificate chains to a Peppol trust anchor, is in date, is not
 *    revoked, and its common name equals the receiver's;
 *  - RefToMessageId equals the message id we sent;
 *  - every NonRepudiationInformation reference inside the signed signal carries a
 *    digest we signed.
 *
 * Any failure is reported as a value with a reason; the raw bytes are preserved
 * by the caller either way.
 */
export async function verifyReceipt(input: ReceiptCheckInput): Promise<ReceiptCheck> {
  const signal = input.signal;
  const doc = signal.document;
  const signature = findReceiptSignature(doc);
  if (!signature) return fail('receipt.malformed', 'no WS-Security signature found');

  const signerPem = extractSignerCertificate(doc, signature);
  if (!signerPem) return fail('receipt.malformed', 'no signer certificate found');
  const signer = parseCertificate(signerPem);

  const signedInfo = firstByLocalName(signature, DS_NS, 'SignedInfo');
  if (!signedInfo) return fail('receipt.malformed', 'no SignedInfo');

  const c14nMethod = firstByLocalName(signedInfo, DS_NS, 'CanonicalizationMethod');
  if (attrOf(c14nMethod, 'Algorithm') !== ALGO_EXC_C14N) {
    return fail('receipt.bad-signature', 'unexpected canonicalization method');
  }
  const signatureMethod = firstByLocalName(signedInfo, DS_NS, 'SignatureMethod');
  if (attrOf(signatureMethod, 'Algorithm') !== ALGO_RSA_SHA256) {
    return fail('receipt.bad-signature', 'unexpected signature method');
  }

  const inclusivePrefixes = inclusivePrefixList(c14nMethod);
  materializeInclusiveNamespaces(signedInfo, inclusivePrefixes);
  const canonicalSignedInfo = inclusivePrefixes.length
    ? canonicalize(signedInfo, inclusivePrefixes)
    : canonicalize(signedInfo);

  const signatureValue = textOf(firstByLocalName(signature, DS_NS, 'SignatureValue'));
  if (!signatureValue) return fail('receipt.malformed', 'no SignatureValue');
  const signatureBytes = Buffer.from(signatureValue.trim(), 'base64');
  const signatureOk = cryptoVerify(
    'sha256',
    Buffer.from(canonicalSignedInfo, 'utf8'),
    { key: signer.publicKey, padding: constants.RSA_PKCS1_PADDING },
    signatureBytes,
  );
  if (!signatureOk) return fail('receipt.bad-signature', 'SignatureValue does not verify over SignedInfo');

  const referenceCheck = verifySignedInfoReferences(doc, signedInfo, signal);
  if (referenceCheck.fail) return fail(referenceCheck.fail.reason, referenceCheck.fail.detail);

  const validation = await input.validateCertificate({
    certificatePem: signerPem,
    purpose: 'receipt-signer',
    now: input.now(),
    ...(input.abort ? { signal: input.abort } : {}),
  });
  if (!validation.ok) {
    if (validation.status === 'revoked') return fail('receipt.revoked-signer', validation.reason);
    return fail('receipt.untrusted-signer', validation.reason);
  }

  const receiverCert = parseCertificate(normalizePem(input.receiverCertificatePem));
  const signerCn = commonNameOf(signer);
  const receiverCn = commonNameOf(receiverCert);
  if (!signerCn || signerCn !== receiverCn) {
    return fail(
      'receipt.wrong-signer',
      `receipt signer CN ${signerCn || '(none)'} != receiver CN ${receiverCn || '(none)'}`,
    );
  }

  if (signal.refToMessageId !== input.as4MessageId) {
    return fail('receipt.ref-mismatch', `RefToMessageId ${signal.refToMessageId ?? '(none)'} != ${input.as4MessageId}`);
  }

  const nrrFail = verifyNonRepudiationInformation(signal, input.signedReferences);
  if (nrrFail) return fail(nrrFail.reason, nrrFail.detail);

  const receipt: ReceiptEvidence = {
    timestamp: signal.timestamp ?? '',
    raw: signal.raw,
    signerCertificate: signerPem,
    signerMatchesSmPCertificate: sameCertificate(signer, receiverCert),
    refToMessageId: signal.refToMessageId ?? '',
  };
  return { ok: true, receipt, signerCertificatePem: signerPem };
}

function findReceiptSignature(doc: Document): Element | null {
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
function resolveIdUnique(doc: Document, id: string): ResolveResult {
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

interface ReferenceOutcome {
  readonly fail: { reason: ReceiptFailureReason; detail: string } | null;
}

/**
 * Verify the digests of the receipt's own SignedInfo references, and require
 * that the signature covers the exact eb:Messaging / SignalMessage we parsed.
 */
function verifySignedInfoReferences(doc: Document, signedInfo: Element, signal: ParsedSignal): ReferenceOutcome {
  if (!signal.messagingId) {
    return { fail: { reason: 'receipt.malformed', detail: 'the signed eb:Messaging has no id' } };
  }
  const references = elementsByLocalName(signedInfo, DS_NS, 'Reference');
  if (references.length === 0) return { fail: { reason: 'receipt.malformed', detail: 'SignedInfo has no references' } };

  let verified = 0;
  let boundToSignal = false;
  for (const reference of references) {
    const uri = attrOf(reference, 'URI') ?? '';
    if (uri.startsWith('cid:')) continue; // attachment of the original message; not in a signal
    if (!uri.startsWith('#')) return { fail: { reason: 'receipt.malformed', detail: `unsupported reference ${uri}` } };

    const resolved = resolveIdUnique(doc, uri.slice(1));
    if (resolved.matches > 1) {
      return { fail: { reason: 'receipt.malformed', detail: `duplicate id ${uri}` } };
    }
    if (!resolved.element) return { fail: { reason: 'receipt.malformed', detail: `unresolved reference ${uri}` } };

    const digestMethod = firstByLocalName(reference, DS_NS, 'DigestMethod');
    if (attrOf(digestMethod, 'Algorithm') !== ALGO_SHA256) {
      return { fail: { reason: 'receipt.bad-signature', detail: 'unexpected digest method' } };
    }
    const expected = textOf(firstByLocalName(reference, DS_NS, 'DigestValue'))?.trim();
    if (!expected) return { fail: { reason: 'receipt.malformed', detail: 'missing DigestValue' } };

    const prefixes = referenceInclusivePrefixes(reference);
    materializeInclusiveNamespaces(resolved.element, prefixes);
    const actual = prefixes.length
      ? createHash('sha256').update(canonicalize(resolved.element, prefixes), 'utf8').digest('base64')
      : canonicalizeDigest(resolved.element);
    if (actual !== expected)
      return { fail: { reason: 'receipt.digest-mismatch', detail: `digest mismatch for ${uri}` } };
    verified += 1;

    if (resolved.element === signal.messagingElement || resolved.element === signal.signalElement) {
      boundToSignal = true;
    }
  }
  if (verified === 0) return { fail: { reason: 'receipt.malformed', detail: 'no verifiable references' } };
  if (!boundToSignal) {
    return {
      fail: { reason: 'receipt.bad-signature', detail: 'signature does not cover the signal message we read' },
    };
  }
  return { fail: null };
}

function verifyNonRepudiationInformation(
  signal: ParsedSignal,
  signedReferences: readonly SignedReference[],
): { reason: ReceiptFailureReason; detail: string } | null {
  const nri = firstByLocalName(signal.signalElement, EBBP_SIGNALS_NS, 'NonRepudiationInformation');
  if (!nri) return { reason: 'receipt.malformed', detail: 'no NonRepudiationInformation in the signed signal' };

  const expected = new Map(signedReferences.map((r) => [r.uri, r.digest]));
  const partInfos = elementsByLocalName(nri, EBBP_SIGNALS_NS, 'MessagePartNRInformation');
  if (partInfos.length === 0) return { reason: 'receipt.malformed', detail: 'no MessagePartNRInformation' };

  const seen = new Set<string>();
  for (const partInfo of partInfos) {
    for (const reference of elementsByLocalName(partInfo, DS_NS, 'Reference')) {
      const uri = attrOf(reference, 'URI') ?? '';
      const digest = textOf(firstByLocalName(reference, DS_NS, 'DigestValue'))?.trim();
      const want = expected.get(uri);
      if (!want || !digest || want !== digest) {
        return { reason: 'receipt.digest-mismatch', detail: `NonRepudiationInformation mismatch for ${uri}` };
      }
      seen.add(uri);
    }
  }
  if (seen.size === 0) return { reason: 'receipt.malformed', detail: 'NonRepudiationInformation has no references' };
  // Every part we signed must be acknowledged, not just a subset: a receipt for
  // only the (empty) body must not count as accepting the whole message.
  for (const { uri } of signedReferences) {
    if (!seen.has(uri)) {
      return { reason: 'receipt.malformed', detail: `NonRepudiationInformation does not acknowledge ${uri}` };
    }
  }
  return null;
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
