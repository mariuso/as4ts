import {
  createDecipheriv,
  createHash,
  privateDecrypt,
  randomBytes,
  sign as cryptoSign,
  verify as cryptoVerify,
  constants,
  X509Certificate,
} from 'node:crypto';
import { gunzipSync } from 'node:zlib';
import { createServer, type Server } from 'node:https';
import type { AddressInfo } from 'node:net';
import {
  ALGO_EXC_C14N,
  ALGO_RSA_SHA256,
  ALGO_SHA256,
  DS_NS,
  EBBP_SIGNALS_NS,
  EBMS_NS,
  SWA_TRANSFORM_SIGNATURE,
  WSSE_NS,
  WSU_NS,
  XMLNS_NS,
  SOAP_ENV_NS,
  XENC_NS,
} from '../../src/constants.js';
import { canonicalize, canonicalizeDigest } from '../../src/xml/c14n.js';
import { attrOf, elementsByLocalName, firstByLocalName, parseXml, serializeXml, textOf } from '../../src/xml/nodes.js';
import type { TestCert } from './pki.js';

export interface SignedReferenceView {
  readonly uri: string;
  readonly transform: string;
  readonly digest: string;
}

export interface ReceivedMessage {
  readonly envelope: Document;
  readonly rawBody: Buffer;
  readonly messageId: string;
  readonly attachment: Buffer;
  readonly decryptedCompressed: Buffer;
  readonly payload: Buffer;
  readonly signedReferences: readonly SignedReferenceView[];
  readonly signatureValid: boolean;
}

export interface FakeReceiver {
  readonly url: string;
  readonly received: ReceivedMessage[];
  close(): Promise<void>;
}

export interface FakeReceiverOptions {
  readonly receiver: TestCert;
  readonly tlsCertPem: string;
  readonly tlsKeyPem: string;
  readonly mode?:
    | { kind: 'receipt' }
    | { kind: 'status'; status: number; body?: string }
    | {
        kind: 'error';
        status: number;
        code: string;
        severity?: string;
        detail?: string;
        extraCodes?: readonly string[];
      }
    | { kind: 'receipt-tampered' }
    | { kind: 'drop' }
    | { kind: 'hang' };
}

export async function startFakeReceiver(options: FakeReceiverOptions): Promise<FakeReceiver> {
  const received: ReceivedMessage[] = [];
  const server: Server = createServer({ cert: options.tlsCertPem, key: options.tlsKeyPem }, (req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      if (options.mode?.kind === 'drop') {
        req.socket.destroy();
        return;
      }
      if (options.mode?.kind === 'hang') {
        // Never answer; the caller is expected to abort.
        return;
      }
      if (options.mode?.kind === 'status') {
        res.writeHead(options.mode.status, { 'Content-Type': 'text/plain' });
        res.end(options.mode.body ?? '');
        return;
      }
      if (options.mode?.kind === 'error') {
        res.writeHead(options.mode.status, { 'Content-Type': 'application/soap+xml; charset=UTF-8' });
        const codes = [options.mode.code, ...(options.mode.extraCodes ?? [])];
        res.end(buildErrorSignal(codes, options.mode.severity ?? 'failure', options.mode.detail));
        return;
      }
      try {
        const message = processIncoming(body, String(req.headers['content-type'] ?? ''), options.receiver);
        received.push(message);
        res.writeHead(200, { 'Content-Type': 'application/soap+xml; charset=UTF-8' });
        res.end(buildReceipt(message, options.receiver, options.mode?.kind === 'receipt-tampered'));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end(`receiver error: ${(err as Error).message}`);
      }
    });
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    url: `https://localhost:${port}/as4`,
    received,
    close: () => new Promise<void>((resolve, reject) => server.close((e) => (e ? reject(e) : resolve()))),
  };
}

function processIncoming(rawBody: Buffer, contentType: string, receiver: TestCert): ReceivedMessage {
  const parts = parseMultipart(contentType, rawBody);
  if (!parts.soap) throw new Error('no SOAP part');
  const envelope = parseXml(parts.soap);
  const attachment = parts.attachment ?? Buffer.alloc(0);

  const messageInfo = firstByLocalName(envelope, EBMS_NS, 'MessageInfo');
  const messageId = textOf(firstByLocalName(messageInfo, EBMS_NS, 'MessageId')) ?? '';

  const sessionKey = decryptSessionKey(envelope, receiver);
  const decryptedCompressed = decryptAttachment(attachment, sessionKey);
  const payload = gunzipSync(decryptedCompressed);
  const verification = verifySenderSignature(envelope, decryptedCompressed);

  return {
    envelope,
    rawBody,
    messageId,
    attachment,
    decryptedCompressed,
    payload,
    signedReferences: verification.references,
    signatureValid: verification.valid,
  };
}

interface MultipartParts {
  soap: Buffer | null;
  attachment: Buffer | null;
}

function parseMultipart(contentType: string, body: Buffer): MultipartParts {
  const boundaryMatch = /boundary\s*=\s*"?([^";]+)"?/i.exec(contentType);
  const result: MultipartParts = { soap: null, attachment: null };
  if (!boundaryMatch?.[1]) return result;
  const marker = Buffer.from(`--${boundaryMatch[1]}`);
  const positions: number[] = [];
  let from = 0;
  for (;;) {
    const idx = body.indexOf(marker, from);
    if (idx < 0) break;
    positions.push(idx);
    from = idx + marker.byteLength;
  }
  for (let i = 0; i < positions.length; i += 1) {
    const start = positions[i]! + marker.byteLength;
    const end = i + 1 < positions.length ? positions[i + 1]! : body.byteLength;
    const part = body.subarray(start, end);
    const headerEnd = part.indexOf('\r\n\r\n');
    if (headerEnd < 0) continue;
    const header = part.subarray(0, headerEnd).toString('latin1');
    let content = part.subarray(headerEnd + 4);
    if (content.length >= 2 && content[content.length - 2] === 0x0d && content[content.length - 1] === 0x0a) {
      content = content.subarray(0, content.length - 2);
    }
    if (/application\/soap\+xml/i.test(header)) result.soap = Buffer.from(content);
    else if (/application\/octet-stream/i.test(header)) result.attachment = Buffer.from(content);
  }
  return result;
}

function decryptSessionKey(envelope: Document, receiver: TestCert): Buffer {
  const encryptedKey = firstByLocalName(envelope, XENC_NS, 'EncryptedKey');
  const cipherValue = textOf(firstByLocalName(encryptedKey, XENC_NS, 'CipherValue'));
  if (!cipherValue) throw new Error('no EncryptedKey CipherValue');
  return privateDecrypt(
    { key: receiver.keyObject, oaepHash: 'sha256', padding: constants.RSA_PKCS1_OAEP_PADDING },
    Buffer.from(cipherValue.trim(), 'base64'),
  );
}

function decryptAttachment(attachment: Buffer, sessionKey: Buffer): Buffer {
  const iv = attachment.subarray(0, 12);
  const tag = attachment.subarray(attachment.length - 16);
  const ciphertext = attachment.subarray(12, attachment.length - 16);
  const decipher = createDecipheriv('aes-128-gcm', sessionKey, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function verifySenderSignature(
  envelope: Document,
  decryptedCompressed: Buffer,
): { valid: boolean; references: SignedReferenceView[] } {
  const references: SignedReferenceView[] = [];
  const signature = firstByLocalName(envelope, DS_NS, 'Signature');
  const signerPem = signature ? extractSignerPem(envelope, signature) : null;
  if (!signature || !signerPem) return { valid: false, references };

  const signedInfo = firstByLocalName(signature, DS_NS, 'SignedInfo');
  if (!signedInfo) return { valid: false, references };

  const publicKey = new X509Certificate(signerPem).publicKey;
  const signatureValue = textOf(firstByLocalName(signature, DS_NS, 'SignatureValue')) ?? '';
  const signatureOk = cryptoVerify(
    'sha256',
    Buffer.from(canonicalize(signedInfo), 'utf8'),
    { key: publicKey, padding: constants.RSA_PKCS1_PADDING },
    Buffer.from(signatureValue, 'base64'),
  );

  let referencesOk = true;
  for (const reference of elementsByLocalName(signedInfo, DS_NS, 'Reference')) {
    const uri = attrOf(reference, 'URI') ?? '';
    const transform = attrOf(elementsByLocalName(reference, DS_NS, 'Transform')[0] ?? null, 'Algorithm') ?? '';
    const digest = textOf(firstByLocalName(reference, DS_NS, 'DigestValue')) ?? '';
    references.push({ uri, transform, digest });
    if (transform === SWA_TRANSFORM_SIGNATURE) {
      if (digest !== createHash('sha256').update(decryptedCompressed).digest('base64')) referencesOk = false;
    } else if (uri.startsWith('#')) {
      const element = resolveId(envelope, uri.slice(1));
      if (!element || digest !== canonicalizeDigest(element)) referencesOk = false;
    }
  }
  return { valid: signatureOk && referencesOk, references };
}

function extractSignerPem(envelope: Document, signature: Element): string | null {
  const keyInfo = firstByLocalName(signature, DS_NS, 'KeyInfo');
  const reference = firstByLocalName(keyInfo, WSSE_NS, 'Reference');
  const uri = attrOf(reference, 'URI');
  if (!uri?.startsWith('#')) return null;
  const token = resolveId(envelope, uri.slice(1));
  const b64 = token ? textOf(token)?.replace(/\s+/g, '') : null;
  if (!b64) return null;
  return `-----BEGIN CERTIFICATE-----\n${(b64.match(/.{1,64}/g) ?? []).join('\n')}\n-----END CERTIFICATE-----`;
}

function buildErrorSignal(codes: readonly string[], severity: string, detail?: string): string {
  const doc = parseXml(`<x/>`);
  const eb = (local: string, attrs: Record<string, string> = {}, text?: string): Element => {
    const node = doc.createElementNS(EBMS_NS, `eb:${local}`);
    for (const [k, v] of Object.entries(attrs)) {
      if (k.startsWith('wsu:')) node.setAttributeNS(WSU_NS, k, v);
      else if (k.startsWith('env:')) node.setAttributeNS(SOAP_ENV_NS, k, v);
      else node.setAttribute(k, v);
    }
    if (text !== undefined) node.appendChild(doc.createTextNode(text));
    return node;
  };
  const signalMessage = eb('SignalMessage');
  const messageInfo = eb('MessageInfo');
  messageInfo.appendChild(eb('Timestamp', {}, new Date().toISOString()));
  messageInfo.appendChild(eb('MessageId', {}, `${randomBytes(16).toString('hex')}@receiver.test`));
  signalMessage.appendChild(messageInfo);
  for (const code of codes) {
    const error = eb('Error', { errorCode: code, severity, category: 'Communication' });
    error.appendChild(eb('Description', {}, 'test error'));
    if (detail) error.appendChild(eb('ErrorDetail', {}, detail));
    signalMessage.appendChild(error);
  }
  const signaling = eb('Messaging', { 'env:mustUnderstand': 'true' });
  signaling.setAttributeNS(XMLNS_NS, 'xmlns:env', SOAP_ENV_NS);
  signaling.setAttributeNS(XMLNS_NS, 'xmlns:wsu', WSU_NS);
  signaling.appendChild(signalMessage);
  const envelope = doc.createElementNS(SOAP_ENV_NS, 'env:Envelope');
  const header = doc.createElementNS(SOAP_ENV_NS, 'env:Header');
  header.appendChild(signaling);
  const body = doc.createElementNS(SOAP_ENV_NS, 'env:Body');
  envelope.appendChild(header);
  envelope.appendChild(body);
  envelope.setAttributeNS(XMLNS_NS, 'xmlns:env', SOAP_ENV_NS);
  envelope.setAttributeNS(XMLNS_NS, 'xmlns:eb', EBMS_NS);
  doc.replaceChild(envelope, doc.documentElement);
  return `<?xml version="1.0" encoding="UTF-8"?>${serializeXml(envelope)}`;
}

function resolveId(doc: Document, id: string): Element | null {
  const all = doc.getElementsByTagName('*');
  for (let i = 0; i < all.length; i += 1) {
    const el = all.item(i);
    if (!el) continue;
    if (el.getAttributeNS(WSU_NS, 'Id') === id || el.getAttribute('Id') === id || el.getAttribute('id') === id)
      return el;
  }
  return null;
}

function buildReceipt(message: ReceivedMessage, receiver: TestCert, tampered = false): string {
  const signalId = `_${randomBytes(16).toString('hex')}`;
  const doc = parseXml(
    '<env:Envelope ' +
      `xmlns:env="${SOAP_ENV_NS}" ` +
      `xmlns:eb="${EBMS_NS}" ` +
      `xmlns:ds="${DS_NS}" ` +
      `xmlns:ebbp="${EBBP_SIGNALS_NS}" ` +
      `xmlns:wsu="${WSU_NS}" ` +
      `xmlns:wsse="${WSSE_NS}"/>`,
  );
  const envelope = doc.documentElement!;
  const eb = (local: string, attrs: Record<string, string> = {}, text?: string): Element => {
    const node = doc.createElementNS(EBMS_NS, `eb:${local}`);
    for (const [k, v] of Object.entries(attrs)) {
      if (k.startsWith('wsu:')) node.setAttributeNS(WSU_NS, k, v);
      else if (k.startsWith('env:')) node.setAttributeNS(SOAP_ENV_NS, k, v);
      else node.setAttribute(k, v);
    }
    if (text !== undefined) node.appendChild(doc.createTextNode(text));
    return node;
  };
  const ds = (local: string, attrs: Record<string, string> = {}, text?: string): Element => {
    const node = doc.createElementNS(DS_NS, `ds:${local}`);
    for (const [k, v] of Object.entries(attrs)) {
      if (k.startsWith('wsu:')) node.setAttributeNS(WSU_NS, k, v);
      else if (k.startsWith('env:')) node.setAttributeNS(SOAP_ENV_NS, k, v);
      else node.setAttribute(k, v);
    }
    if (text !== undefined) node.appendChild(doc.createTextNode(text));
    return node;
  };

  const signalMessage = eb('SignalMessage', { Id: signalId });
  const messageInfo = eb('MessageInfo');
  messageInfo.appendChild(eb('Timestamp', {}, new Date().toISOString()));
  messageInfo.appendChild(eb('MessageId', {}, `${randomBytes(16).toString('hex')}@receiver.test`));
  messageInfo.appendChild(eb('RefToMessageId', {}, message.messageId));
  signalMessage.appendChild(messageInfo);

  const receipt = eb('Receipt');
  const nri = doc.createElementNS(EBBP_SIGNALS_NS, 'ebbp:NonRepudiationInformation');
  for (const ref of message.signedReferences) {
    const partInfo = doc.createElementNS(EBBP_SIGNALS_NS, 'ebbp:MessagePartNRInformation');
    const reference = ds('Reference', { URI: ref.uri });
    const transforms = ds('Transforms');
    transforms.appendChild(ds('Transform', { Algorithm: ref.transform }));
    reference.appendChild(transforms);
    reference.appendChild(ds('DigestMethod', { Algorithm: ALGO_SHA256 }));
    const digest =
      tampered && ref.transform === SWA_TRANSFORM_SIGNATURE
        ? 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
        : ref.digest;
    reference.appendChild(ds('DigestValue', {}, digest));
    partInfo.appendChild(reference);
    nri.appendChild(partInfo);
  }
  receipt.appendChild(nri);
  signalMessage.appendChild(receipt);

  const signalingId = `_msg_${randomBytes(8).toString('hex')}`;
  const signaling = eb('Messaging', { 'env:mustUnderstand': 'true', 'wsu:Id': signalingId });
  signaling.appendChild(signalMessage);

  const security = doc.createElementNS(WSSE_NS, 'wsse:Security');
  const bst = doc.createElementNS(WSSE_NS, 'wsse:BinarySecurityToken');
  bst.setAttributeNS(WSU_NS, 'wsu:Id', 'X509-RECEIPT');
  bst.setAttribute(
    'ValueType',
    'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3',
  );
  bst.appendChild(doc.createTextNode(receiver.certPem.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, '')));
  security.appendChild(bst);

  // Assemble the envelope before hashing the Messaging, so the digest matches
  // what a receiver computes over the parsed (in-envelope) element.
  const header = doc.createElementNS(SOAP_ENV_NS, 'env:Header');
  const bodyEl = doc.createElementNS(SOAP_ENV_NS, 'env:Body');
  header.appendChild(signaling);
  header.appendChild(security);
  envelope.appendChild(header);
  envelope.appendChild(bodyEl);

  const signedInfo = ds('SignedInfo');
  signedInfo.setAttributeNS(XMLNS_NS, 'xmlns:env', SOAP_ENV_NS);
  const c14nMethod = ds('CanonicalizationMethod', { Algorithm: ALGO_EXC_C14N });
  const inc = doc.createElementNS(ALGO_EXC_C14N, 'ec:InclusiveNamespaces');
  inc.setAttribute('PrefixList', 'env');
  c14nMethod.appendChild(inc);
  signedInfo.appendChild(c14nMethod);
  signedInfo.appendChild(ds('SignatureMethod', { Algorithm: ALGO_RSA_SHA256 }));
  const ref = ds('Reference', { URI: `#${signalingId}` });
  const transforms = ds('Transforms');
  transforms.appendChild(ds('Transform', { Algorithm: ALGO_EXC_C14N }));
  ref.appendChild(transforms);
  ref.appendChild(ds('DigestMethod', { Algorithm: ALGO_SHA256 }));
  ref.appendChild(ds('DigestValue', {}, canonicalizeDigest(signaling)));
  signedInfo.appendChild(ref);

  const signatureValue = cryptoSign('sha256', Buffer.from(canonicalize(signedInfo), 'utf8'), {
    key: receiver.keyObject,
    padding: constants.RSA_PKCS1_PADDING,
  }).toString('base64');

  const signature = ds('Signature');
  signature.appendChild(signedInfo);
  signature.appendChild(ds('SignatureValue', {}, signatureValue));
  const keyInfo = ds('KeyInfo');
  const str = doc.createElementNS(WSSE_NS, 'wsse:SecurityTokenReference');
  const strRef = doc.createElementNS(WSSE_NS, 'wsse:Reference');
  strRef.setAttribute('URI', '#X509-RECEIPT');
  str.appendChild(strRef);
  keyInfo.appendChild(str);
  signature.appendChild(keyInfo);
  security.appendChild(signature);

  return `<?xml version="1.0" encoding="UTF-8"?>${serializeXml(envelope)}`;
}
