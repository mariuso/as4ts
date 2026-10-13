import { AS4_COMPRESSION_TYPE, EBMS_NS, SOAP_11_NS, SOAP_ENV_NS } from '../constants.js';
import { peppolProfile } from '../profile.js';
import { commonNameOf, parseCertificate, safeMessage } from '../util.js';
import { MessageBudget } from './budget.js';
import { EncryptionFault, parseInboundEncryption } from './encryption.js';
import { MimeFault, parseMultipartRelated, selectSoapPart } from './mime.js';
import { recoverInboundPayload } from './payload.js';
import { payloadHooks } from './payload-hooks.js';
import { checkSbdh, documentTypeFromAction } from './sbdh.js';
import { abortableStream, isAbortError } from './streams.js';
import { AddressingFault, isSupportedCompression, readUserMessage } from './user-message.js';
import { defaultXmlLimits, parseStrictXml, XmlFault } from './xml.js';
import { verifyWsSecuritySignature } from '../xml/ws-security.js';
import type {
  EvidenceHandle,
  InboundCorrelation,
  InboundEvent,
  InboundFailure,
  InboundFailureReason,
  InboundStage,
  OnInboundEvent,
  OpenAs4MessageInput,
  OpenResult,
  PayloadHandle,
  ReceiptContext,
  SbdhConsistency,
} from './types.js';
import { defaultInboundLimits } from './types.js';

/**
 * Verify and unpack one inbound AS4 `UserMessage` (Phase 3). It performs no
 * acknowledgement and no storage: success means the message verified and the
 * payload was fully processed, and it returns verified facts plus owned handles
 * and an immutable receipt context. Every failure is a value with a stage, a
 * reason and — only once the AP identity is bound — the correlation needed to
 * build an ebMS error.
 */
function emit(onEvent: OnInboundEvent | undefined, event: InboundEvent): void {
  if (!onEvent) return;
  try {
    onEvent(event);
  } catch {
    // observe only
  }
}

async function timed<T>(
  onEvent: OnInboundEvent | undefined,
  phase: InboundEvent['phase'],
  fn: () => Promise<T>,
): Promise<T> {
  const start = performance.now();
  try {
    return await fn();
  } finally {
    emit(onEvent, { phase, durationMs: performance.now() - start });
  }
}

function directChild(node: Element | null, ns: string, localName: string): Element | null {
  const children = node?.childNodes;
  if (!children) return null;
  for (let i = 0; i < children.length; i += 1) {
    const child = children.item(i);
    if (!child || child.nodeType !== 1) continue;
    const element = child as Element;
    if (element.namespaceURI === ns && element.localName === localName) return element;
  }
  return null;
}

function mapSignatureReason(reason: 'malformed' | 'bad-signature' | 'digest-mismatch'): InboundFailureReason {
  if (reason === 'bad-signature') return 'signature.bad-signature';
  if (reason === 'digest-mismatch') return 'signature.digest-mismatch';
  return 'signature.malformed';
}

function certReason(status: 'invalid' | 'revoked' | 'unavailable'): InboundFailureReason {
  if (status === 'revoked') return 'certificate.revoked';
  if (status === 'unavailable') return 'certificate.unavailable';
  return 'certificate.untrusted';
}

function isFileSystemError(err: unknown): boolean {
  const code = (err as NodeJS.ErrnoException | undefined)?.code;
  return typeof code === 'string' && /^E[A-Z]+$/.test(code);
}

/** Read a payload up to `maxBytes`, cancelling on the signal and detecting overflow. */
async function readPayload(
  handle: PayloadHandle,
  maxBytes: number,
  signal: AbortSignal | undefined,
): Promise<{ bytes: Buffer; tooLarge: boolean }> {
  payloadHooks.onReadPayload?.();
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of abortableStream(handle.read(), signal)) {
    total += chunk.byteLength;
    if (total > maxBytes) return { bytes: Buffer.alloc(0), tooLarge: true };
    chunks.push(Buffer.from(chunk));
  }
  return { bytes: Buffer.concat(chunks), tooLarge: false };
}

export async function openAs4Message(input: OpenAs4MessageInput): Promise<OpenResult> {
  const limits = input.limits ?? defaultInboundLimits;
  const profile = input.profile ?? peppolProfile;
  const holders = Array.isArray(input.keyHolder) ? input.keyHolder : [input.keyHolder];
  const abort = input.signal;
  const onEvent = input.onEvent;
  let correlation: InboundCorrelation | undefined;

  const fail = (stage: InboundStage, reason: InboundFailureReason, detail?: string): InboundFailure => ({
    ok: false,
    stage,
    reason,
    answerable: correlation !== undefined,
    ...(correlation ? { correlation } : {}),
    ...(detail ? { detail } : {}),
  });

  try {
    const parsed = await timed(onEvent, 'parse-mime', () =>
      parseMultipartRelated({
        contentType: input.contentType,
        body: input.body,
        limits: {
          maxRequestBytes: limits.maxRequestBytes,
          maxParts: limits.maxParts,
          maxHeaderBytes: limits.maxHeaderBytes,
          maxPartBytes: limits.maxPartBytes,
          maxBoundaryLength: limits.maxBoundaryLength,
        },
        ...(abort ? { signal: abort } : {}),
      }),
    );
    const soap = selectSoapPart(parsed);

    const document = await timed(onEvent, 'parse-xml', () =>
      Promise.resolve(parseStrictXml(soap.body, { ...defaultXmlLimits, maxBytes: limits.maxEnvelopeBytes })),
    );

    const envelope = document.documentElement;
    if (
      envelope.localName !== 'Envelope' ||
      (envelope.namespaceURI !== SOAP_ENV_NS && envelope.namespaceURI !== SOAP_11_NS)
    ) {
      return fail('xml', 'xml.malformed', 'the document is not a SOAP envelope');
    }

    const verification = verifyWsSecuritySignature(document);
    if (!verification.ok) return fail('signature', mapSignatureReason(verification.reason), verification.detail);
    const signature = verification.signature;
    const signerPem = signature.signerCertificatePem;

    // Coverage: eb:Messaging and the SOAP Body must both be signed.
    const soapNamespace = envelope.namespaceURI ?? '';
    const header = directChild(envelope, soapNamespace, 'Header');
    const soapBody = directChild(envelope, soapNamespace, 'Body');
    const messaging = directChild(header, EBMS_NS, 'Messaging');
    if (
      !messaging ||
      !soapBody ||
      !signature.coveredElements.includes(messaging) ||
      !signature.coveredElements.includes(soapBody)
    ) {
      return fail('signature', 'signature.coverage', 'the signature does not cover eb:Messaging and the SOAP Body');
    }

    // Every reference must be unique, and there must be exactly one attachment
    // reference. Until multiple attachments are supported, extra parts or
    // references are rejected rather than acknowledged.
    const seenUris = new Set<string>();
    for (const reference of signature.references) {
      if (seenUris.has(reference.uri))
        return fail('signature', 'signature.coverage', `duplicate reference ${reference.uri}`);
      seenUris.add(reference.uri);
    }
    const attachmentReferences = signature.references.filter((reference) => reference.uri.startsWith('cid:'));
    if (attachmentReferences.length !== 1) {
      return fail(
        'signature',
        'signature.coverage',
        `expected exactly one attachment reference, got ${attachmentReferences.length}`,
      );
    }
    if (parsed.parts.length !== 2) {
      return fail('mime', 'mime.malformed', `expected exactly two MIME parts, got ${parsed.parts.length}`);
    }

    const validation = await timed(onEvent, 'validate-certificate', () =>
      input.validateCertificate({
        certificatePem: signerPem,
        purpose: 'message-signer',
        now: input.now(),
        ...(abort ? { signal: abort } : {}),
      }),
    );
    if (!validation.ok) return fail('certificate', certReason(validation.status), validation.reason);

    const headers = readUserMessage(document, profile);

    // AP identity binding. Correlation is only trusted once this succeeds.
    const signerCn = commonNameOf(parseCertificate(signerPem));
    if (headers.fromPartyId !== signerCn) {
      return fail(
        'addressing',
        'addressing.party-mismatch',
        `From/PartyId ${headers.fromPartyId} != signer CN ${signerCn}`,
      );
    }
    if (headers.toPartyId !== input.receiverIdentity.value) {
      return fail(
        'addressing',
        'addressing.party-mismatch',
        `To/PartyId ${headers.toPartyId} != receiver identity ${input.receiverIdentity.value}`,
      );
    }
    correlation = { messageId: headers.messageId, senderId: headers.fromPartyId, receiverId: headers.toPartyId };
    if (!isSupportedCompression(headers.compressionType)) {
      return fail('addressing', 'addressing.unsupported', `unsupported compression ${headers.compressionType}`);
    }

    const encryption = parseInboundEncryption(document);
    const contentId = encryption.attachmentHref.startsWith('cid:') ? encryption.attachmentHref.slice(4) : '';
    const attachmentReference = attachmentReferences[0]!;
    if (attachmentReference.uri !== encryption.attachmentHref || headers.partHref !== encryption.attachmentHref) {
      return fail('signature', 'signature.coverage', 'the reference, PartInfo href and encryption descriptor differ');
    }
    const part = parsed.parts.find((candidate) => candidate !== soap);
    if (!part || part.contentId !== contentId) {
      return fail('mime', 'mime.malformed', 'the attachment Content-ID does not match the encryption reference');
    }

    const compression =
      headers.compressionType === AS4_COMPRESSION_TYPE
        ? ({ kind: 'gzip', declaredBy: 'CompressionType' } as const)
        : ({ kind: 'none' } as const);

    const recovered = await recoverInboundPayload({
      encryption,
      attachment: {
        contentId,
        source: (async function* () {
          yield part.body;
        })(),
        byteLength: part.body.length,
      },
      reference: attachmentReference,
      compression,
      keyHolder: holders,
      limits,
      budget: new MessageBudget(limits.maxAggregateOutputBytes),
      ...(input.spoolDirectory ? { spoolDirectory: input.spoolDirectory } : {}),
      ...(abort ? { signal: abort } : {}),
      ...(onEvent ? { onEvent } : {}),
    });
    if (!recovered.ok) {
      return { ...recovered, answerable: correlation !== undefined, ...(correlation ? { correlation } : {}) };
    }

    // From here the recovered bundle is owned: any later failure must dispose it.
    let sbdh: SbdhConsistency;
    try {
      const payload = await readPayload(recovered.payload, limits.maxXmlBytes, abort);
      sbdh = payload.tooLarge
        ? { status: 'too-large' }
        : checkSbdh(
            payload.bytes,
            { ...defaultXmlLimits, maxBytes: limits.maxXmlBytes },
            {
              originalSender: headers.originalSender,
              finalRecipient: headers.finalRecipient,
              process: headers.service,
              documentType: documentTypeFromAction(headers.action),
            },
          );
    } catch (err) {
      await recovered.dispose();
      if (isAbortError(err)) return fail('transport', 'aborted', 'aborted while reading the payload');
      if (isFileSystemError(err)) return fail('payload', 'payload.spool-failed', safeMessage(err));
      return fail('internal', 'internal.error', safeMessage(err));
    }
    if (abort?.aborted) {
      await recovered.dispose();
      return fail('transport', 'aborted');
    }

    const receipt: ReceiptContext = {
      messageId: headers.messageId,
      senderId: headers.fromPartyId,
      receiverId: headers.toPartyId,
      timestamp: headers.timestamp,
      signedReferences: signature.references,
    };
    const evidence: EvidenceHandle = {
      envelopeBytes: new Uint8Array(soap.body),
      signedReferences: signature.references,
      signerCertificate: signerPem,
      dispose: async () => {},
    };

    return {
      ok: true,
      messageId: headers.messageId,
      timestamp: headers.timestamp,
      senderId: headers.fromPartyId,
      receiverId: headers.toPartyId,
      originalSender: headers.originalSender,
      finalRecipient: headers.finalRecipient,
      service: headers.service,
      action: headers.action,
      ...(headers.agreement ? { agreement: headers.agreement } : {}),
      ...(headers.conversationId ? { conversationId: headers.conversationId } : {}),
      ...(headers.mpc ? { mpc: headers.mpc } : {}),
      ...(headers.compressionType ? { compressionType: headers.compressionType } : {}),
      signerCertificate: signerPem,
      credentialCertificate: recovered.credential.certificate,
      payload: recovered.payload,
      representation: recovered.representation,
      evidence,
      receipt,
      sbdh,
      dispose: () => recovered.dispose(),
    };
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    if (err instanceof MimeFault) return fail('mime', err.reason, detail);
    if (err instanceof XmlFault) return fail('xml', err.reason, detail);
    if (err instanceof EncryptionFault) return fail('decrypt', err.reason, detail);
    if (err instanceof AddressingFault) return fail('addressing', err.reason, detail);
    return fail('internal', 'internal.error', detail);
  }
}
