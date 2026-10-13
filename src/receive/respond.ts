import { ALGO_EXC_C14N, DS_NS, EBBP_SIGNALS_NS } from '../constants.js';
import { defaultEntropy, hexToken, type Entropy } from '../entropy.js';
import type { Signer } from '../types.js';
import { canonicalizeDigest } from '../xml/c14n.js';
import {
  append,
  element,
  elementsByLocalName,
  firstByLocalName,
  parseXml,
  serializeXml,
  textOf,
} from '../xml/nodes.js';
import { addSignature, createSecurityHeader, type SignedPart } from '../xml/security.js';
import { parseSignal, type ParsedSignal } from '../xml/signal.js';
import { verifyWsSecuritySignature } from '../xml/ws-security.js';
import type { ReceiptContext, RespondAs4MessageInput, RespondResult, RespondSuccess } from './types.js';

/**
 * Build the signed response to an inbound AS4 message (Phase 4). An accepted
 * message gets a signed `eb:Receipt` whose NonRepudiationInformation echoes the
 * verified references exactly; a rejected one gets a signed `eb:Error` signal
 * built only from the recovered correlation. The serialised output is verified
 * before it is returned, so a caller can persist and replay exactly these bytes.
 */
const SKELETON =
  '<env:Envelope ' +
  'xmlns:env="http://www.w3.org/2003/05/soap-envelope" ' +
  'xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/" ' +
  'xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" ' +
  'xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" ' +
  'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ' +
  'xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" ' +
  'xmlns:ebbp="http://docs.oasis-open.org/ebxml-bp/ebbp-signals-2.0"/>';

const RESPONSE_CONTENT_TYPE = 'application/soap+xml; charset=UTF-8';

interface SignalParts {
  readonly doc: Document;
  readonly header: Element;
  readonly body: Element;
  readonly messaging: Element;
  readonly signalMessage: Element;
  readonly messagingId: string;
  readonly bodyId: string;
}

function buildSignalEnvelope(entropy: Entropy): SignalParts {
  const doc = parseXml(SKELETON);
  const envelope = doc.documentElement;
  if (!envelope) throw new Error('response skeleton failed to parse');
  const messagingId = `_${hexToken(entropy, 16)}`;
  const bodyId = `_${hexToken(entropy, 16)}`;
  const signalId = `_${hexToken(entropy, 8)}`;

  const header = element(doc, 'env', 'Header');
  const body = element(doc, 'env', 'Body', { 'wsu:Id': bodyId });
  const messaging = element(doc, 'eb', 'Messaging', { 'env:mustUnderstand': 'true', 'wsu:Id': messagingId });
  const signalMessage = element(doc, 'eb', 'SignalMessage', { Id: signalId });
  append(messaging, signalMessage);
  append(header, messaging);
  append(envelope, header, body);
  return { doc, header, body, messaging, signalMessage, messagingId, bodyId };
}

function messageInfo(doc: Document, timestamp: string, messageId: string, refToMessageId: string): Element {
  const info = element(doc, 'eb', 'MessageInfo');
  append(
    info,
    element(doc, 'eb', 'Timestamp', {}, timestamp),
    element(doc, 'eb', 'MessageId', {}, messageId),
    element(doc, 'eb', 'RefToMessageId', {}, refToMessageId),
  );
  return info;
}

/** Echo one verified reference into a `ebbp:MessagePartNRInformation`. */
function acknowledge(doc: Document, reference: ReceiptContext['signedReferences'][number]): Element {
  const dsReference = element(doc, 'ds', 'Reference', { URI: reference.uri });
  const transforms = element(doc, 'ds', 'Transforms');
  for (const transform of reference.transforms) {
    const node = element(doc, 'ds', 'Transform', { Algorithm: transform.algorithm });
    if (transform.inclusivePrefixes.length > 0) {
      append(node, element(doc, 'ec', 'InclusiveNamespaces', { PrefixList: transform.inclusivePrefixes.join(' ') }));
    }
    append(transforms, node);
  }
  append(
    dsReference,
    transforms,
    element(doc, 'ds', 'DigestMethod', { Algorithm: reference.digestMethod }),
    element(doc, 'ds', 'DigestValue', {}, reference.digest),
  );
  const partInfo = element(doc, 'ebbp', 'MessagePartNRInformation');
  append(partInfo, dsReference);
  return partInfo;
}

/** Build the eb:Receipt signal message from the verified receipt context. */
function buildReceiptSignal(parts: SignalParts, ctx: ReceiptContext, timestamp: string, messageId: string): void {
  const { doc, signalMessage } = parts;
  append(signalMessage, messageInfo(doc, timestamp, messageId, ctx.messageId));
  const receipt = element(doc, 'eb', 'Receipt');
  const nri = element(doc, 'ebbp', 'NonRepudiationInformation');
  for (const reference of ctx.signedReferences) append(nri, acknowledge(doc, reference));
  append(receipt, nri);
  append(signalMessage, receipt);
}

/** Build the eb:Error signal message from the recovered correlation. */
function buildErrorSignal(
  parts: SignalParts,
  correlation: { readonly messageId: string },
  error: {
    readonly code: string;
    readonly severity: string;
    readonly shortDescription?: string;
    readonly detail?: string;
  },
  timestamp: string,
  messageId: string,
): void {
  const { doc, signalMessage } = parts;
  append(signalMessage, messageInfo(doc, timestamp, messageId, correlation.messageId));
  const attrs: Record<string, string> = { errorCode: error.code, severity: error.severity };
  if (error.shortDescription) attrs['shortDescription'] = error.shortDescription;
  const node = element(doc, 'eb', 'Error', attrs);
  if (error.detail) append(node, element(doc, 'eb', 'ErrorDetail', {}, error.detail));
  append(signalMessage, node);
}

/** Sign the SOAP Body and eb:Messaging of a response, then serialise it. */
async function signSignal(
  parts: SignalParts,
  signer: Signer,
  signal: AbortSignal | undefined,
  entropy: Entropy,
): Promise<string> {
  const { doc, header, body, messaging, messagingId, bodyId } = parts;
  const security = createSecurityHeader(doc);
  const references: SignedPart[] = [
    { uri: `#${bodyId}`, transform: ALGO_EXC_C14N, digest: canonicalizeDigest(body) },
    { uri: `#${messagingId}`, transform: ALGO_EXC_C14N, digest: canonicalizeDigest(messaging) },
  ];
  await addSignature(
    doc,
    security,
    { signingTokenId: `X509-SIG-${hexToken(entropy, 16)}`, signatureId: `SIG-${hexToken(entropy, 16)}`, references },
    signer,
    signal,
  );
  append(header, security);
  return `<?xml version="1.0" encoding="UTF-8"?>${serializeXml(doc)}`;
}

function coversMessaging(signal: ParsedSignal): boolean {
  const verification = verifyWsSecuritySignature(signal.document);
  if (!verification.ok) return false;
  return verification.signature.coveredElements.includes(signal.messagingElement);
}

/** Every expected reference must be echoed once, with the same semantics. */
function acknowledgesExactly(signal: ParsedSignal, ctx: ReceiptContext): boolean {
  const nri = firstByLocalName(signal.signalElement, EBBP_SIGNALS_NS, 'NonRepudiationInformation');
  if (!nri) return false;
  const references = elementsByLocalName(nri, DS_NS, 'Reference');
  if (references.length !== ctx.signedReferences.length) return false;
  const byUri = new Map(references.map((reference) => [reference.getAttribute('URI') ?? '', reference]));
  if (byUri.size !== references.length) return false;
  return ctx.signedReferences.every((expected) => {
    const reference = byUri.get(expected.uri);
    if (!reference) return false;
    if (firstByLocalName(reference, DS_NS, 'DigestMethod')?.getAttribute('Algorithm') !== expected.digestMethod)
      return false;
    if (textOf(firstByLocalName(reference, DS_NS, 'DigestValue')) !== expected.digest) return false;
    const transforms = elementsByLocalName(reference, DS_NS, 'Transform');
    return (
      transforms.length === expected.transforms.length &&
      expected.transforms.every((transform, index) => {
        const node = transforms[index]!;
        if (node.getAttribute('Algorithm') !== transform.algorithm) return false;
        const list = firstByLocalName(node, ALGO_EXC_C14N, 'InclusiveNamespaces')?.getAttribute('PrefixList');
        const actual = list ? list.split(/\s+/).filter(Boolean).sort() : [];
        return actual.join(' ') === [...transform.inclusivePrefixes].sort().join(' ');
      })
    );
  });
}

const failure = (reason: string): RespondResult => ({ ok: false, reason });

/** Wrap a serialised signal into the response the caller persists and replays. */
function response(xml: string): RespondSuccess {
  return { ok: true, status: 200, contentType: RESPONSE_CONTENT_TYPE, headers: {}, body: Buffer.from(xml, 'utf8') };
}

export async function respondAs4Message(input: RespondAs4MessageInput): Promise<RespondResult> {
  const entropy = defaultEntropy();
  const timestamp = input.now().toISOString();
  try {
    if (input.kind === 'accepted') {
      const parts = buildSignalEnvelope(entropy);
      buildReceiptSignal(parts, input.receipt, timestamp, `_${hexToken(entropy, 16)}@as4ts`);
      const xml = await signSignal(parts, input.signer, input.signal, entropy);
      const signal = parseSignal(Buffer.from(xml, 'utf8'));
      if (!signal || signal.kind !== 'receipt' || signal.refToMessageId !== input.receipt.messageId) {
        return failure('internal.self-check-failed');
      }
      if (!coversMessaging(signal) || !acknowledgesExactly(signal, input.receipt)) {
        return failure('internal.self-check-failed');
      }
      return response(xml);
    }

    const parts = buildSignalEnvelope(entropy);
    buildErrorSignal(
      parts,
      input.correlation,
      {
        code: input.error.code,
        severity: input.error.severity,
        ...(input.error.shortDescription ? { shortDescription: input.error.shortDescription } : {}),
        ...(input.error.detail ? { detail: input.error.detail } : {}),
      },
      timestamp,
      `_${hexToken(entropy, 16)}@as4ts`,
    );
    const xml = await signSignal(parts, input.signer, input.signal, entropy);
    const signal = parseSignal(Buffer.from(xml, 'utf8'));
    if (!signal || signal.kind !== 'error' || signal.refToMessageId !== input.correlation.messageId) {
      return failure('internal.self-check-failed');
    }
    if (!coversMessaging(signal)) return failure('internal.self-check-failed');
    return response(xml);
  } catch (err) {
    if (err instanceof Error && (err.name === 'AbortError' || (err as NodeJS.ErrnoException).code === 'ABORT_ERR')) {
      return failure('aborted');
    }
    throw err;
  }
}
