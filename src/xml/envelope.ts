import { ALGO_EXC_C14N, SOAP_ENV_NS, SWA_TRANSFORM_SIGNATURE } from '../constants.js';
import { defaultEntropy, hexToken, type Entropy } from '../entropy.js';
import type { Signer } from '../types.js';
import { canonicalizeDigest } from './c14n.js';
import { element, append, parseXml, serializeXml } from './nodes.js';
import { addEncryption, addSignature, createSecurityHeader, type SignedPart } from './security.js';
import { buildUserMessage, type UserMessageParams } from './user-message.js';

export interface BuildEnvelopeParams {
  readonly userMessage: UserMessageParams;
  readonly signer: Signer;
  readonly receiverCertificatePem: string;
  readonly wrappedKey: Buffer;
  /** Base64 SHA-256 of the gzipped payload (SwA signed digest). */
  readonly attachmentDigestBase64: string;
  /** Test-only, pins every XML id. */
  readonly entropy?: Entropy;
}

export interface BuiltEnvelope {
  readonly xml: string;
  readonly messagingId: string;
  readonly bodyId: string;
  readonly encryptedDataId: string;
  readonly encryptedKeyId: string;
  readonly bodyDigest: string;
  readonly messagingDigest: string;
}

const SKELETON =
  '<env:Envelope ' +
  'xmlns:env="http://www.w3.org/2003/05/soap-envelope" ' +
  'xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/" ' +
  'xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" ' +
  'xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" ' +
  'xmlns:wsse11="http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd" ' +
  'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ' +
  'xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" ' +
  'xmlns:xenc11="http://www.w3.org/2009/xmlenc11#" ' +
  'xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>';

/**
 * Assemble and sign the full SOAP envelope. The signature references are the
 * SOAP Body and eb:Messaging header (exclusive C14N) then the encrypted
 * attachment (SwA content signature transform). Everything is built in memory
 * here because the envelope is small; the payload itself is streamed elsewhere.
 *
 * Async because the signer is injected and may be backed by a remote KMS.
 */
export async function buildEnvelope(p: BuildEnvelopeParams): Promise<BuiltEnvelope> {
  const entropy = p.entropy ?? defaultEntropy();
  const doc: Document = parseXml(SKELETON);
  const envelope = doc.documentElement;
  if (!envelope) throw new Error('envelope skeleton failed to parse');
  if (envelope.namespaceURI !== SOAP_ENV_NS) throw new Error('wrong envelope namespace');

  const header = element(doc, 'env', 'Header');
  const security = createSecurityHeader(doc);
  const { messaging, messagingId, body, bodyId } = buildUserMessage(doc, p.userMessage, entropy);

  append(header, messaging, security);
  append(envelope, header, body);

  const bodyDigest = canonicalizeDigest(body);
  const messagingDigest = canonicalizeDigest(messaging);

  const encryptedKeyId = `EK-${hexToken(entropy, 16)}`;
  const encryptedDataId = `ED-${hexToken(entropy, 16)}`;
  const encryptionTokenId = `X509-ENC-${hexToken(entropy, 16)}`;
  const signingTokenId = `X509-SIG-${hexToken(entropy, 16)}`;
  const signatureId = `SIG-${hexToken(entropy, 16)}`;

  addEncryption(doc, security, {
    receiverCertificatePem: p.receiverCertificatePem,
    wrappedKey: p.wrappedKey,
    encryptedKeyId,
    encryptedDataId,
    encryptionTokenId,
    attachmentHref: p.userMessage.payloadHref,
  });

  const references: SignedPart[] = [
    { uri: `#${bodyId}`, transform: ALGO_EXC_C14N, digest: bodyDigest },
    { uri: `#${messagingId}`, transform: ALGO_EXC_C14N, digest: messagingDigest },
    {
      uri: p.userMessage.payloadHref,
      transform: SWA_TRANSFORM_SIGNATURE,
      digest: p.attachmentDigestBase64,
    },
  ];

  await addSignature(
    doc,
    security,
    {
      signingTokenId,
      signatureId,
      references,
    },
    p.signer,
  );

  return { xml: serializeXml(doc), messagingId, bodyId, encryptedDataId, encryptedKeyId, bodyDigest, messagingDigest };
}
