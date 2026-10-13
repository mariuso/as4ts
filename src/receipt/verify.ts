import { ALGO_EXC_C14N, ALGO_SHA256, DS_NS, EBBP_SIGNALS_NS, SWA_TRANSFORM_SIGNATURE } from '../constants.js';
import type { ReceiptEvidence, ReceiptFailureReason, ValidateCertificate } from '../types.js';
import { commonNameOf, normalizePem, parseCertificate, sameCertificate } from '../util.js';
import { elementsByLocalName, firstByLocalName, attrOf, textOf } from '../xml/nodes.js';
import type { ParsedSignal } from '../xml/signal.js';
import { verifyWsSecuritySignature, type SignedReference, type VerifiedReference } from '../xml/ws-security.js';

export type { SignedReference } from '../xml/ws-security.js';

export interface ReceiptCheckInput {
  readonly signal: ParsedSignal;
  readonly as4MessageId: string;
  readonly receiverCertificatePem: string;
  /**
   * The references to expect in the receipt. The sender's own outbound artifact
   * passes URI/digest pairs, for which the fixed profile semantics apply; the
   * receiving path passes fully verified references, whose recorded digest
   * method, ordered transforms and inclusive-prefix parameters are compared
   * directly.
   */
  readonly signedReferences: readonly (SignedReference | VerifiedReference)[];
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
 * Verify an AS4 receipt fully. The WS-Security signature itself is verified by
 * the direction-neutral {@link verifyWsSecuritySignature}; on top of that this
 * applies the receipt-specific rules. Acceptance requires all of:
 *  - a valid signature that actually covers the eb:Messaging/SignalMessage we
 *    read (otherwise a forged unsigned receipt could be prepended to a genuine
 *    one);
 *  - the signer certificate chains to a Peppol trust anchor, is in date, is not
 *    revoked, and its common name equals the receiver's;
 *  - RefToMessageId equals the message id we sent;
 *  - every NonRepudiationInformation reference inside the signed signal
 *    acknowledges one of our references with the same digest method, ordered
 *    transforms and parameters as well as the same digest value, exactly once.
 *
 * Any failure is reported as a value with a reason; the raw bytes are preserved
 * by the caller either way.
 */
export async function verifyReceipt(input: ReceiptCheckInput): Promise<ReceiptCheck> {
  const signal = input.signal;

  const signature = verifyWsSecuritySignature(signal.document);
  if (!signature.ok) {
    return fail(`receipt.${signature.reason}` as ReceiptFailureReason, signature.detail);
  }

  // The signature must cover the exact eb:Messaging / SignalMessage we parsed.
  if (!signal.messagingId) {
    return fail('receipt.malformed', 'the signed eb:Messaging has no id');
  }
  const coversSignal =
    covers(signature.signature.coveredElements, signal.messagingElement) ||
    covers(signature.signature.coveredElements, signal.signalElement);
  if (!coversSignal) {
    return fail('receipt.bad-signature', 'signature does not cover the signal message we read');
  }

  const signerPem = signature.signature.signerCertificatePem;
  const signer = signature.signature.signerCertificate;

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

function covers(elements: readonly Element[], target: Element): boolean {
  return elements.includes(target);
}

function verifyNonRepudiationInformation(
  signal: ParsedSignal,
  signedReferences: readonly (SignedReference | VerifiedReference)[],
): { reason: ReceiptFailureReason; detail: string } | null {
  const nri = firstByLocalName(signal.signalElement, EBBP_SIGNALS_NS, 'NonRepudiationInformation');
  if (!nri) return { reason: 'receipt.malformed', detail: 'no NonRepudiationInformation in the signed signal' };

  const expectedByUri = new Map(signedReferences.map((reference) => [reference.uri, reference]));
  const partInfos = elementsByLocalName(nri, EBBP_SIGNALS_NS, 'MessagePartNRInformation');
  if (partInfos.length === 0) return { reason: 'receipt.malformed', detail: 'no MessagePartNRInformation' };

  const seen = new Set<string>();
  for (const partInfo of partInfos) {
    for (const reference of elementsByLocalName(partInfo, DS_NS, 'Reference')) {
      const uri = attrOf(reference, 'URI') ?? '';
      const want = expectedByUri.get(uri);
      if (!want) {
        return {
          reason: 'receipt.malformed',
          detail: `NonRepudiationInformation acknowledges an unrequested reference ${uri}`,
        };
      }
      if (seen.has(uri)) {
        return { reason: 'receipt.malformed', detail: `duplicate acknowledgement reference ${uri}` };
      }
      seen.add(uri);

      // AS4 receipts echo the original reference structure as evidence, so the
      // acknowledgement must carry the same processing semantics (digest method,
      // ordered transforms and their parameters), not only the same digest text.
      if (!sameSemantics(actualSemantics(reference), expectedSemantics(want, uri))) {
        return {
          reason: 'receipt.digest-mismatch',
          detail: `NonRepudiationInformation reference semantics mismatch for ${uri}`,
        };
      }

      const digest = textOf(firstByLocalName(reference, DS_NS, 'DigestValue'))?.trim();
      if (!digest || digest !== want.digest) {
        return { reason: 'receipt.digest-mismatch', detail: `NonRepudiationInformation digest mismatch for ${uri}` };
      }
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

interface TransformSemantics {
  readonly algorithm: string;
  readonly inclusivePrefixes: readonly string[];
}

interface ReferenceSemantics {
  readonly digestMethod: string | null;
  readonly transforms: readonly TransformSemantics[];
}

/**
 * The reference semantics a receipt must echo for one acknowledgement.
 *
 * When the caller supplies the full verified semantics (the receiving path), the
 * recorded digest method, ordered transforms and inclusive-prefix parameters are
 * compared directly, so a peer that used supported canonicalisation parameters is
 * not rejected for using them. When the caller supplies only URI/digest pairs
 * (the sender's own outbound artifact), the fixed profile expectations apply: SOAP
 * parts are signed with SHA-256 over exclusive C14N, attachments with SHA-256 over
 * the SwA content-signature transform, and neither declares namespace parameters.
 * A receipt that acknowledges such a reference with anything else is not
 * acknowledging what we signed.
 */
function expectedSemantics(reference: SignedReference | VerifiedReference, uri: string): ReferenceSemantics {
  if (isVerifiedReference(reference)) {
    return {
      digestMethod: reference.digestMethod,
      transforms: reference.transforms.map((transform) => ({
        algorithm: transform.algorithm,
        inclusivePrefixes: [...transform.inclusivePrefixes].sort(),
      })),
    };
  }
  return {
    digestMethod: ALGO_SHA256,
    transforms: [
      {
        algorithm: uri.startsWith('cid:') ? SWA_TRANSFORM_SIGNATURE : ALGO_EXC_C14N,
        inclusivePrefixes: [],
      },
    ],
  };
}

function isVerifiedReference(reference: SignedReference | VerifiedReference): reference is VerifiedReference {
  const candidate = reference as VerifiedReference;
  return typeof candidate.digestMethod === 'string' && Array.isArray(candidate.transforms);
}

function actualSemantics(reference: Element): ReferenceSemantics {
  const digestMethod = attrOf(firstByLocalName(reference, DS_NS, 'DigestMethod'), 'Algorithm');
  const transforms = elementsByLocalName(reference, DS_NS, 'Transform').map((transform) => ({
    algorithm: attrOf(transform, 'Algorithm') ?? '',
    inclusivePrefixes: inclusivePrefixesOf(transform),
  }));
  return { digestMethod, transforms };
}

function inclusivePrefixesOf(transform: Element): string[] {
  const inc = firstByLocalName(transform, ALGO_EXC_C14N, 'InclusiveNamespaces');
  const list = attrOf(inc, 'PrefixList');
  return list ? list.split(/\s+/).filter(Boolean).sort() : [];
}

function sameSemantics(a: ReferenceSemantics, b: ReferenceSemantics): boolean {
  if (a.digestMethod !== b.digestMethod) return false;
  if (a.transforms.length !== b.transforms.length) return false;
  return a.transforms.every((transform, index) => {
    const other = b.transforms[index]!;
    return (
      transform.algorithm === other.algorithm &&
      transform.inclusivePrefixes.join(' ') === other.inclusivePrefixes.join(' ')
    );
  });
}
