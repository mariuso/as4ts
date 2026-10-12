import { DS_NS, EBBP_SIGNALS_NS } from '../constants.js';
import type { ReceiptEvidence, ReceiptFailureReason, ValidateCertificate } from '../types.js';
import { commonNameOf, normalizePem, parseCertificate, sameCertificate } from '../util.js';
import { elementsByLocalName, firstByLocalName, attrOf, textOf } from '../xml/nodes.js';
import type { ParsedSignal } from '../xml/signal.js';
import { verifyWsSecuritySignature, type SignedReference } from '../xml/ws-security.js';

export type { SignedReference } from '../xml/ws-security.js';

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
 * Verify an AS4 receipt fully. The WS-Security signature itself is verified by
 * the direction-neutral {@link verifyWsSecuritySignature}; on top of that this
 * applies the receipt-specific rules. Acceptance requires all of:
 *  - a valid signature that actually covers the eb:Messaging/SignalMessage we
 *    read (otherwise a forged unsigned receipt could be prepended to a genuine
 *    one);
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
