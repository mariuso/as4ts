import { randomBytes, sign as cryptoSign, constants } from 'node:crypto';
import {
  ALGO_EXC_C14N,
  ALGO_RSA_SHA256,
  ALGO_SHA256,
  DS_NS,
  EBBP_SIGNALS_NS,
  EBMS_NS,
  SOAP_ENV_NS,
  WSSE_NS,
  WSU_NS,
  XMLNS_NS,
} from '../../src/constants.js';
import { canonicalize, canonicalizeDigest } from '../../src/xml/c14n.js';
import { parseXml, serializeXml } from '../../src/xml/nodes.js';
import { parseSignal, type ParsedSignal } from '../../src/xml/signal.js';
import { createSelfSignedCert, type TestCert } from './pki.js';

/**
 * A reference echoed in NonRepudiationInformation, or placed directly in the
 * receipt's SignedInfo (negative tests). Optional fields let a test construct an
 * acknowledgement whose processing semantics differ from the outbound artifact.
 */
export interface SignedInfoReference {
  readonly uri: string;
  readonly transform: string;
  readonly digest: string;
  readonly digestMethod?: string;
  /** Override the transform sequence; defaults to `[transform]`. */
  readonly transforms?: readonly string[];
  /** Attach an InclusiveNamespaces PrefixList to the transform (altered parameters). */
  readonly inclusivePrefixes?: readonly string[];
}

export type ReceiptReference = SignedInfoReference;

export interface ReceiptBuildOptions {
  /** Certificate and key that produce the signature. */
  readonly signer: TestCert;
  /** Certificate embedded in the receipt, when different from `signer` (untrusted signer test). */
  readonly embeddedCertPem?: string;
  readonly refToMessageId: string | null;
  /** References echoed in NonRepudiationInformation (normally what the sender signed). */
  readonly references: readonly ReceiptReference[];
  /** Corrupt the signature bytes. */
  readonly breakSignature?: boolean;
  /** Replace the NonRepudiationInformation digests with these. */
  readonly tamperedDigests?: Readonly<Record<string, string>>;
  readonly signalMessageId?: string;
  /** Sign a different element than the eb:Messaging (binding test). */
  readonly referenceTarget?: 'messaging' | 'body';
  /** SOAP version of the receipt envelope (default 1.2). */
  readonly soapVersion?: '1.1' | '1.2';
  /** Prefix bound to the SOAP namespace; also the InclusiveNamespaces prefix. */
  readonly soapPrefix?: string;
  /** Override the declared SignatureMethod algorithm (negative tests). */
  readonly signatureMethodAlgorithm?: string;
  /** Override the declared DigestMethod algorithm (negative tests). */
  readonly digestMethodAlgorithm?: string;
  /** Override the declared CanonicalizationMethod algorithm (negative tests). */
  readonly canonicalizationAlgorithm?: string;
  /** Override the transform algorithm of the default signature reference (negative tests). */
  readonly referenceTransformAlgorithm?: string;
  /** Extra references to place in SignedInfo after the default one (negative tests). */
  readonly extraSignedInfoReferences?: readonly SignedInfoReference[];
}

const SOAP_11_NS = 'http://schemas.xmlsoap.org/soap/envelope/';

export function buildSignedReceipt(options: ReceiptBuildOptions): { xml: string; raw: Buffer; signal: ParsedSignal } {
  const soapNs = options.soapVersion === '1.1' ? SOAP_11_NS : SOAP_ENV_NS;
  const prefix = options.soapPrefix ?? 'env';
  const signalId = options.signalMessageId ?? `_${randomBytes(16).toString('hex')}`;
  const signalingId = `_msg_${randomBytes(8).toString('hex')}`;
  const bodyId = `_body_${randomBytes(8).toString('hex')}`;
  const doc = parseXml(
    `<${prefix}:Envelope ` +
      `xmlns:${prefix}="${soapNs}" ` +
      `xmlns:eb="${EBMS_NS}" ` +
      `xmlns:ds="${DS_NS}" ` +
      `xmlns:ebbp="${EBBP_SIGNALS_NS}" ` +
      `xmlns:ec="${ALGO_EXC_C14N}" ` +
      `xmlns:wsu="${WSU_NS}" ` +
      `xmlns:wsse="${WSSE_NS}"/>`,
  );
  const envelope = doc.documentElement!;
  const mk = (ns: string, qname: string, attrs: Record<string, string> = {}, text?: string): Element => {
    const node = doc.createElementNS(ns, qname);
    for (const [k, v] of Object.entries(attrs)) {
      if (k.startsWith('wsu:')) node.setAttributeNS(WSU_NS, k, v);
      else if (k.startsWith(`${prefix}:`)) node.setAttributeNS(soapNs, k, v);
      else node.setAttribute(k, v);
    }
    if (text !== undefined) node.appendChild(doc.createTextNode(text));
    return node;
  };

  const signalMessage = mk(EBMS_NS, 'eb:SignalMessage', { Id: signalId });
  const messageInfo = mk(EBMS_NS, 'eb:MessageInfo');
  messageInfo.appendChild(mk(EBMS_NS, 'eb:Timestamp', {}, '2026-10-12T09:07:36.000Z'));
  messageInfo.appendChild(mk(EBMS_NS, 'eb:MessageId', {}, `${randomBytes(16).toString('hex')}@receiver.test`));
  if (options.refToMessageId !== null) {
    messageInfo.appendChild(mk(EBMS_NS, 'eb:RefToMessageId', {}, options.refToMessageId));
  }
  signalMessage.appendChild(messageInfo);

  const receipt = mk(EBMS_NS, 'eb:Receipt');
  const nri = mk(EBBP_SIGNALS_NS, 'ebbp:NonRepudiationInformation');
  for (const ref of options.references) {
    const partInfo = mk(EBBP_SIGNALS_NS, 'ebbp:MessagePartNRInformation');
    const reference = mk(DS_NS, 'ds:Reference', { URI: ref.uri });
    const transforms = mk(DS_NS, 'ds:Transforms');
    for (const algorithm of ref.transforms ?? [ref.transform]) {
      const transform = mk(DS_NS, 'ds:Transform', { Algorithm: algorithm });
      if (ref.inclusivePrefixes && ref.inclusivePrefixes.length > 0) {
        transform.appendChild(
          mk(ALGO_EXC_C14N, 'ec:InclusiveNamespaces', { PrefixList: ref.inclusivePrefixes.join(' ') }),
        );
      }
      transforms.appendChild(transform);
    }
    reference.appendChild(transforms);
    reference.appendChild(mk(DS_NS, 'ds:DigestMethod', { Algorithm: ref.digestMethod ?? ALGO_SHA256 }));
    const digest = options.tamperedDigests?.[ref.uri] ?? ref.digest;
    reference.appendChild(mk(DS_NS, 'ds:DigestValue', {}, digest));
    partInfo.appendChild(reference);
    nri.appendChild(partInfo);
  }
  receipt.appendChild(nri);
  signalMessage.appendChild(receipt);

  const signaling = mk(EBMS_NS, 'eb:Messaging', { [`${prefix}:mustUnderstand`]: 'true', 'wsu:Id': signalingId });
  signaling.appendChild(signalMessage);

  const security = mk(WSSE_NS, 'wsse:Security');
  const embeddedCert = options.embeddedCertPem ?? options.signer.certPem;
  const bst = mk(
    WSSE_NS,
    'wsse:BinarySecurityToken',
    {
      'wsu:Id': 'X509-RECEIPT',
      ValueType: 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3',
    },
    embeddedCert.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, ''),
  );
  security.appendChild(bst);

  // Assemble the envelope before hashing, so the digest matches what a receiver
  // computes over the parsed (in-envelope) Messaging element.
  const header = mk(soapNs, `${prefix}:Header`);
  header.appendChild(signaling);
  header.appendChild(security);
  const body = mk(soapNs, `${prefix}:Body`, { 'wsu:Id': bodyId });
  envelope.appendChild(header);
  envelope.appendChild(body);

  const signedInfo = mk(DS_NS, 'ds:SignedInfo');
  signedInfo.setAttributeNS(XMLNS_NS, `xmlns:${prefix}`, soapNs);
  const c14nMethod = mk(DS_NS, 'ds:CanonicalizationMethod', {
    Algorithm: options.canonicalizationAlgorithm ?? ALGO_EXC_C14N,
  });
  const inc = mk(ALGO_EXC_C14N, 'ec:InclusiveNamespaces', { PrefixList: prefix });
  c14nMethod.appendChild(inc);
  signedInfo.appendChild(c14nMethod);
  signedInfo.appendChild(
    mk(DS_NS, 'ds:SignatureMethod', { Algorithm: options.signatureMethodAlgorithm ?? ALGO_RSA_SHA256 }),
  );
  const signTarget = options.referenceTarget === 'body' ? body : signaling;
  const signTargetId = options.referenceTarget === 'body' ? bodyId : signalingId;
  const defaultDigestMethod = options.digestMethodAlgorithm ?? ALGO_SHA256;
  const signedInfoReferences: SignedInfoReference[] = [
    {
      uri: `#${signTargetId}`,
      transform: options.referenceTransformAlgorithm ?? ALGO_EXC_C14N,
      digest: canonicalizeDigest(signTarget),
      digestMethod: defaultDigestMethod,
    },
    ...(options.extraSignedInfoReferences ?? []),
  ];
  for (const reference of signedInfoReferences) {
    const ref = mk(DS_NS, 'ds:Reference', { URI: reference.uri });
    const transforms = mk(DS_NS, 'ds:Transforms');
    transforms.appendChild(mk(DS_NS, 'ds:Transform', { Algorithm: reference.transform }));
    ref.appendChild(transforms);
    ref.appendChild(mk(DS_NS, 'ds:DigestMethod', { Algorithm: reference.digestMethod ?? defaultDigestMethod }));
    ref.appendChild(mk(DS_NS, 'ds:DigestValue', {}, reference.digest));
    signedInfo.appendChild(ref);
  }

  let signatureValue = cryptoSign('sha256', Buffer.from(canonicalize(signedInfo), 'utf8'), {
    key: options.signer.keyObject,
    padding: constants.RSA_PKCS1_PADDING,
  }).toString('base64');
  if (options.breakSignature) {
    const buf = Buffer.from(signatureValue, 'base64');
    buf[0] = buf[0]! ^ 0xff;
    signatureValue = buf.toString('base64');
  }

  const signature = mk(DS_NS, 'ds:Signature');
  signature.appendChild(signedInfo);
  signature.appendChild(mk(DS_NS, 'ds:SignatureValue', {}, signatureValue));
  const keyInfo = mk(DS_NS, 'ds:KeyInfo');
  const str = mk(WSSE_NS, 'wsse:SecurityTokenReference');
  str.appendChild(mk(WSSE_NS, 'wsse:Reference', { URI: '#X509-RECEIPT' }));
  keyInfo.appendChild(str);
  signature.appendChild(keyInfo);
  security.appendChild(signature);

  const xml = `<?xml version="1.0" encoding="UTF-8"?>${serializeXml(envelope)}`;
  const raw = Buffer.from(xml, 'utf8');
  const signal = parseSignal(raw);
  if (!signal) throw new Error('failed to parse generated receipt');
  return { xml, raw, signal };
}

/** A completely unrelated self-signed certificate, for the untrusted-signer test. */
export function unrelatedSelfSigned(): TestCert {
  return createSelfSignedCert('POP999999');
}
