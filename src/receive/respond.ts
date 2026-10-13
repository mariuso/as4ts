import { ALGO_EXC_C14N, ALGO_SHA256, DS_NS, EBBP_SIGNALS_NS, SWA_TRANSFORM_SIGNATURE } from '../constants.js';
import { defaultEntropy, hexToken, type Entropy } from '../entropy.js';
import type { Signer } from '../types.js';
import { safeMessage } from '../util.js';
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
import { abortError, isAbortError } from './streams.js';
import type { ReceiptContext, RespondAs4MessageInput, RespondFailure, RespondResult, RespondSuccess } from './types.js';

/**
 * Build the signed response to an inbound AS4 message (Phase 4). An accepted
 * message gets a signed `eb:Receipt` whose NonRepudiationInformation echoes the
 * verified references exactly; a rejected one gets a signed `eb:Error` signal
 * built only from the recovered correlation. The serialised output is verified
 * before it is returned, so a caller can persist and replay exactly these bytes.
 *
 * Both signals use HTTP 200 and plain `application/soap+xml; charset=UTF-8`: an
 * ebMS Error is carried in a normal SOAP response (SOAP Faults have separate
 * HTTP mappings), and payload-free ebMS messages may use plain SOAP. The HTTP
 * adapter must set `Content-Type` from `contentType` and transmit `body`
 * unchanged.
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

const refuse = (reason: string, detail?: string): RespondFailure => ({
  ok: false,
  reason,
  ...(detail ? { detail } : {}),
});

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

/**
 * Await `operation`, but stop waiting as soon as `signal` aborts. The operation
 * itself is not cancelled here (that is the signer's concern). A rejection
 * handler is attached to the started operation **before** any early return, so a
 * late rejection — including one racing an already-aborted signal — can never
 * become an unhandled rejection.
 */
async function abortableAwait<T>(operation: Promise<T>, signal: AbortSignal | undefined): Promise<T> {
  // Observe the operation unconditionally, ahead of every exit path.
  operation.catch(() => {});
  if (!signal) return operation;
  if (signal.aborted) throw abortError();
  return new Promise<T>((resolve, reject) => {
    const onAbort = (): void => reject(abortError());
    signal.addEventListener('abort', onAbort, { once: true });
    operation.then(
      (value) => {
        signal.removeEventListener('abort', onAbort);
        resolve(value);
      },
      (err) => {
        signal.removeEventListener('abort', onAbort);
        reject(err);
      },
    );
  });
}

type SignOutcome = { readonly ok: true; readonly xml: string } | RespondFailure;

/** Sign the SOAP Body and eb:Messaging of a response, then serialise it. */
async function signSignal(
  parts: SignalParts,
  signer: Signer,
  signal: AbortSignal | undefined,
  entropy: Entropy,
): Promise<SignOutcome> {
  const { doc, header, body, messaging, messagingId, bodyId } = parts;
  const security = createSecurityHeader(doc);
  const references: SignedPart[] = [
    { uri: `#${bodyId}`, transform: ALGO_EXC_C14N, digest: canonicalizeDigest(body) },
    { uri: `#${messagingId}`, transform: ALGO_EXC_C14N, digest: canonicalizeDigest(messaging) },
  ];
  try {
    await abortableAwait(
      addSignature(
        doc,
        security,
        {
          signingTokenId: `X509-SIG-${hexToken(entropy, 16)}`,
          signatureId: `SIG-${hexToken(entropy, 16)}`,
          references,
        },
        signer,
        signal,
      ),
      signal,
    );
  } catch (err) {
    if (isAbortError(err) || signal?.aborted) return refuse('aborted');
    return refuse('respond.signing-failed', safeMessage(err));
  }
  append(header, security);
  return { ok: true, xml: `<?xml version="1.0" encoding="UTF-8"?>${serializeXml(doc)}` };
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

/** Wrap a serialised signal into the response the caller persists and replays. */
function response(xml: string): RespondSuccess {
  return { ok: true, status: 200, contentType: RESPONSE_CONTENT_TYPE, headers: {}, body: Buffer.from(xml, 'utf8') };
}

function isSha256Base64(value: string): boolean {
  const bytes = Buffer.from(value, 'base64');
  return bytes.length === 32 && bytes.toString('base64') === value;
}

/** The single transform the profile allows for a reference of this kind. */
function supportedTransformAlgorithm(uri: string): string {
  return uri.startsWith('cid:') ? SWA_TRANSFORM_SIGNATURE : ALGO_EXC_C14N;
}

/**
 * A reference is either an in-envelope `#<fragment>` or an attachment
 * `cid:<identifier>`. Anything else — an external URL, arbitrary text, or a
 * `#`/`cid:` with no value — is not a reference this profile can acknowledge.
 */
function isSupportedReference(uri: string): boolean {
  if (uri.startsWith('#')) return uri.length > 1;
  if (uri.startsWith('cid:')) return uri.length > 'cid:'.length;
  return false;
}

/**
 * Reject an unusable persisted receipt context before any signing: a receipt is
 * only produced for a non-empty, unique set of references whose semantics the
 * profile supports — SHA-256 over exclusive C14N for SOAP parts, the SwA content
 * signature transform for attachments — so a persisted context cannot make us
 * acknowledge something we would not have produced.
 */
function validateReceipt(receipt: ReceiptContext): RespondFailure | null {
  if (!receipt || typeof receipt.messageId !== 'string' || receipt.messageId.length === 0) {
    return refuse('respond.invalid-receipt', 'the receipt context has no message id');
  }
  const references = receipt.signedReferences;
  if (!Array.isArray(references) || references.length === 0) {
    return refuse('respond.invalid-receipt', 'the receipt context has no signed references');
  }
  const seen = new Set<string>();
  for (const reference of references) {
    if (!reference || typeof reference.uri !== 'string' || reference.uri.length === 0) {
      return refuse('respond.invalid-receipt', 'a reference has no URI');
    }
    if (!isSupportedReference(reference.uri)) {
      return refuse('respond.invalid-receipt', `reference ${reference.uri} is not a supported reference URI`);
    }
    if (typeof reference.digest !== 'string' || !isSha256Base64(reference.digest)) {
      return refuse('respond.invalid-receipt', `reference ${reference.uri} has a malformed digest`);
    }
    if (reference.digestMethod !== ALGO_SHA256) {
      return refuse('respond.invalid-receipt', `reference ${reference.uri} has an unsupported digest method`);
    }
    if (!Array.isArray(reference.transforms) || reference.transforms.length !== 1) {
      return refuse('respond.invalid-receipt', `reference ${reference.uri} must have exactly one transform`);
    }
    const expectedTransform = supportedTransformAlgorithm(reference.uri);
    for (const transform of reference.transforms) {
      if (!transform || typeof transform.algorithm !== 'string' || transform.algorithm !== expectedTransform) {
        return refuse('respond.invalid-receipt', `reference ${reference.uri} has an unsupported transform`);
      }
      if (
        !Array.isArray(transform.inclusivePrefixes) ||
        transform.inclusivePrefixes.some((prefix: string) => typeof prefix !== 'string')
      ) {
        return refuse('respond.invalid-receipt', `reference ${reference.uri} has non-string transform parameters`);
      }
    }
    if (seen.has(reference.uri)) {
      return refuse('respond.invalid-receipt', `duplicate reference ${reference.uri}`);
    }
    seen.add(reference.uri);
  }
  return null;
}

/** Validate the request before doing any work, so bad input is a value. */
function validateInput(input: RespondAs4MessageInput): RespondFailure | null {
  if (!input || typeof input !== 'object') {
    return refuse('respond.invalid-input', 'a response input is required');
  }
  if (input.kind !== 'accepted' && input.kind !== 'rejected') {
    return refuse('respond.invalid-input', 'kind must be accepted or rejected');
  }
  if (typeof input.now !== 'function') return refuse('respond.invalid-input', 'now must be a function');
  if (!input.signer || typeof input.signer.sign !== 'function') {
    return refuse('respond.invalid-input', 'a signer is required');
  }
  if (input.kind === 'accepted') {
    if (input.decision !== 'committed' && input.decision !== 'already-committed') {
      return refuse('respond.decision-required', 'an explicit acceptance decision is required');
    }
    return validateReceipt(input.receipt);
  }
  if (
    !input.correlation ||
    typeof input.correlation.messageId !== 'string' ||
    input.correlation.messageId.length === 0
  ) {
    return refuse('respond.invalid-input', 'a correlation message id is required');
  }
  if (!input.error || typeof input.error.code !== 'string' || input.error.code.length === 0) {
    return refuse('respond.invalid-input', 'an ebMS error code is required');
  }
  if (input.error.severity !== 'failure' && input.error.severity !== 'warning') {
    return refuse('respond.invalid-input', 'error severity must be failure or warning');
  }
  return null;
}

export async function respondAs4Message(input: RespondAs4MessageInput): Promise<RespondResult> {
  // `started` marks the point past validation, so a throw before it is treated
  // as malformed input and a throw after it as a build/self-check failure.
  let started = false;
  let timestamp = '';
  try {
    const invalid = validateInput(input);
    if (invalid) return invalid;
    timestamp = input.now().toISOString();
    const entropy = defaultEntropy();
    if (input.signal?.aborted) return refuse('aborted');
    started = true;

    const parts = buildSignalEnvelope(entropy);
    if (input.kind === 'accepted') {
      buildReceiptSignal(parts, input.receipt, timestamp, `_${hexToken(entropy, 16)}@as4ts`);
    } else {
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
    }

    const signed = await signSignal(parts, input.signer, input.signal, entropy);
    if (!signed.ok) return signed;
    if (input.signal?.aborted) return refuse('aborted');

    const signal = parseSignal(Buffer.from(signed.xml, 'utf8'));
    if (!signal || signal.kind !== (input.kind === 'accepted' ? 'receipt' : 'error')) {
      return refuse('respond.self-check-failed', 'the response signal did not parse as expected');
    }
    const expectedRef = input.kind === 'accepted' ? input.receipt.messageId : input.correlation.messageId;
    if (signal.refToMessageId !== expectedRef) {
      return refuse('respond.self-check-failed', 'RefToMessageId does not match');
    }
    if (!coversMessaging(signal)) {
      return refuse('respond.self-check-failed', 'the signature does not cover eb:Messaging');
    }
    if (input.kind === 'accepted' && !acknowledgesExactly(signal, input.receipt)) {
      return refuse('respond.self-check-failed', 'the receipt does not echo the signed references');
    }
    if (input.signal?.aborted) return refuse('aborted');
    return response(signed.xml);
  } catch (err) {
    if (isAbortError(err)) return refuse('aborted');
    return refuse(started ? 'respond.self-check-failed' : 'respond.invalid-input', safeMessage(err));
  }
}
