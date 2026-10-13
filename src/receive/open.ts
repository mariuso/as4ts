import { AS4_COMPRESSION_TYPE, EBMS_NS, SOAP_11_NS, SOAP_ENV_NS, WSSE_NS } from '../constants.js';
import { elementsByLocalName } from '../xml/nodes.js';
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

function directChildren(node: Element | null, ns: string, localName: string): Element[] {
  const out: Element[] = [];
  const children = node?.childNodes;
  if (!children) return out;
  for (let i = 0; i < children.length; i += 1) {
    const child = children.item(i);
    if (!child || child.nodeType !== 1) continue;
    const element = child as Element;
    if (element.namespaceURI === ns && element.localName === localName) out.push(element);
  }
  return out;
}

interface SoapStructure {
  readonly header: Element;
  readonly body: Element;
  readonly messaging: Element;
  readonly security: Element;
}

/**
 * Validate the whole SOAP structure *before* verification, so the elements used
 * later are unambiguous: exactly one SOAP Header and Body, one eb:Messaging and
 * one wsse:Security, each in its required position, and no wsse:Security
 * anywhere outside the Header. Returns a detail string when the structure is
 * not acceptable.
 */
function validateSoapStructure(document: Document): SoapStructure | { readonly detail: string } {
  const envelope = document.documentElement;
  if (
    !envelope ||
    envelope.localName !== 'Envelope' ||
    (envelope.namespaceURI !== SOAP_ENV_NS && envelope.namespaceURI !== SOAP_11_NS)
  ) {
    return { detail: 'the document is not a SOAP envelope' };
  }
  const soapNamespace = envelope.namespaceURI ?? '';
  const headers = directChildren(envelope, soapNamespace, 'Header');
  if (headers.length !== 1) return { detail: `expected exactly one SOAP Header, got ${headers.length}` };
  const bodies = directChildren(envelope, soapNamespace, 'Body');
  if (bodies.length !== 1) return { detail: `expected exactly one SOAP Body, got ${bodies.length}` };
  const header = headers[0]!;
  const messaging = directChildren(header, EBMS_NS, 'Messaging');
  if (messaging.length !== 1) {
    return { detail: `expected exactly one eb:Messaging in the Header, got ${messaging.length}` };
  }
  const securities = directChildren(header, WSSE_NS, 'Security');
  if (securities.length !== 1) {
    return { detail: `expected exactly one wsse:Security in the Header, got ${securities.length}` };
  }
  if (elementsByLocalName(document, WSSE_NS, 'Security').length !== 1) {
    return { detail: 'wsse:Security must appear only in the SOAP Header' };
  }
  return { header, body: bodies[0]!, messaging: messaging[0]!, security: securities[0]! };
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

    const structure = validateSoapStructure(document);
    if ('detail' in structure) return fail('xml', 'xml.malformed', structure.detail);
    const { messaging, body: soapBody } = structure;

    const verification = verifyWsSecuritySignature(document);
    if (!verification.ok) return fail('signature', mapSignatureReason(verification.reason), verification.detail);
    const signature = verification.signature;
    const signerPem = signature.signerCertificatePem;

    // Coverage: eb:Messaging and the SOAP Body must both be signed.
    if (!signature.coveredElements.includes(messaging) || !signature.coveredElements.includes(soapBody)) {
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
