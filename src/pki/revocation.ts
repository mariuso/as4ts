import { createHash, verify as cryptoVerify, X509Certificate } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import {
  children,
  decodeIntegerHex,
  decodeOid,
  decodeTime,
  derInteger,
  derNull,
  derOctetString,
  derOid,
  derSequence,
  parseDer,
  TAG,
  type DerNode,
} from './asn1.js';
import { certFingerprint256, commonNameOf } from '../util.js';

export type RevocationMode =
  /** A revocation answer that cannot be obtained is treated as failure. Default. */
  | 'strict'
  /** A revocation answer that cannot be obtained is treated as "not revoked". */
  | 'soft';

export interface RevocationPolicy {
  /** What to do when the revocation service cannot be reached. Defaults to `strict`. */
  readonly unreachable: RevocationMode;
  /** Try OCSP before CRL. Defaults to true. */
  readonly ocsp: boolean;
  /** Fall back to / use CRL. Defaults to true. */
  readonly crl: boolean;
  /** Network timeout for a revocation fetch, milliseconds. Applies to the whole exchange, including the response body. */
  readonly timeoutMs: number;
  /** Maximum bytes read from an OCSP/CRL response body. Defaults to 1 MiB. */
  readonly maxResponseBytes?: number;
  /** Maximum cache lifetime for a positive/negative revocation answer, milliseconds. */
  readonly maxCacheMs: number;
}

export interface RevocationEndpoints {
  readonly ocsp: readonly string[];
  readonly crl: readonly string[];
}

export type RevocationStatus = 'good' | 'revoked' | 'unknown';

export interface RevocationAnswer {
  readonly status: RevocationStatus;
  readonly source: 'ocsp' | 'crl' | 'config' | 'none';
  readonly reason: string;
  /** When the answer may be cached until. */
  readonly expiresAt?: Date;
}

export interface RevocationCheckerOptions {
  readonly policy: RevocationPolicy;
  readonly now: () => Date;
  readonly fetchImpl?: typeof fetch;
  readonly cache?: RevocationCache;
  /** Caller abort signal; aborts an in-flight revocation fetch. */
  readonly signal?: AbortSignal;
  /** Serials known revoked out of band, keyed by issuer common name. */
  readonly extraRevokedSerials?: Readonly<Record<string, readonly string[]>>;
}

const OID = {
  AIA: '1.3.6.1.5.5.7.1.1',
  OCSP: '1.3.6.1.5.5.7.48.1',
  CRL_DP: '2.5.29.31',
  OCSP_BASIC: '1.3.6.1.5.5.7.48.1.1',
  SHA1: '1.3.14.3.2.26',
} as const;

// ---------------------------------------------------------------------------
// Extension parsing
// ---------------------------------------------------------------------------

/** Find the tbsCertificate body of an X.509 certificate. */
function tbsOfCert(der: Buffer): DerNode {
  const cert = parseDer(der).node;
  const tbs = children(cert)[0];
  if (!tbs) throw new Error('certificate: no tbs');
  return tbs;
}

function extensionsOf(tbs: DerNode): DerNode[] {
  for (const child of children(tbs)) {
    if (child.cls === 2 && child.tag === 3) {
      const seq = parseDer(child.value).node;
      return children(seq);
    }
  }
  return [];
}

/** Extract OCSP responder URLs and CRL distribution point URLs. */
export function extractRevocationEndpoints(cert: X509Certificate): RevocationEndpoints {
  const ocsp: string[] = [];
  const crl: string[] = [];
  try {
    const tbs = tbsOfCert(Buffer.from(cert.raw));
    for (const ext of extensionsOf(tbs)) {
      const list = children(ext);
      const oidNode = list[0];
      if (!oidNode || oidNode.tag !== TAG.OID) continue;
      const oid = decodeOid(oidNode.value);
      const valueNode = list.find((n) => n.tag === TAG.OCTET_STRING);
      if (!valueNode) continue;
      if (oid === OID.AIA) ocsp.push(...parseAia(valueNode.value));
      if (oid === OID.CRL_DP) crl.push(...parseCrlDp(valueNode.value));
    }
  } catch {
    // Fall through with whatever was collected.
  }
  return { ocsp, crl };
}

function parseAia(content: Buffer): string[] {
  const urls: string[] = [];
  const seq = parseDer(content).node;
  for (const access of children(seq)) {
    const parts = children(access);
    const method = parts[0];
    const location = parts[1];
    if (!method || !location) continue;
    if (method.tag === TAG.OID && decodeOid(method.value) === OID.OCSP && location.cls === 2 && location.tag === 6) {
      urls.push(location.value.toString('latin1'));
    }
  }
  return urls;
}

function parseCrlDp(content: Buffer): string[] {
  const urls: string[] = [];
  const seq = parseDer(content).node;
  for (const dp of children(seq)) {
    const dpChildren = children(dp);
    const name = dpChildren.find((c) => c.cls === 2 && c.tag === 0);
    if (!name) continue;
    // DistributionPointName CHOICE -> fullName [0] GeneralNames
    const fullName = children(name).find((c) => c.cls === 2 && c.tag === 0);
    if (!fullName) continue;
    for (const gn of children(fullName)) {
      if (gn.cls === 2 && gn.tag === 6) urls.push(gn.value.toString('latin1'));
    }
  }
  return urls;
}

// ---------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------

interface CacheEntry {
  readonly answer: RevocationAnswer;
  readonly expiresAt: number;
}

export class RevocationCache {
  private readonly entries = new Map<string, CacheEntry>();

  get(key: string, now: Date): RevocationAnswer | null {
    const entry = this.entries.get(key);
    if (!entry) return null;
    if (entry.expiresAt <= now.getTime()) {
      this.entries.delete(key);
      return null;
    }
    return entry.answer;
  }

  set(key: string, answer: RevocationAnswer, now: Date, maxCacheMs: number): void {
    const cap = now.getTime() + maxCacheMs;
    const stated = answer.expiresAt ? answer.expiresAt.getTime() : cap;
    const expiresAt = Math.min(cap, stated);
    if (expiresAt <= now.getTime()) return;
    this.entries.set(key, { answer, expiresAt });
  }
}

// ---------------------------------------------------------------------------
// CRL
// ---------------------------------------------------------------------------

interface ParsedCrl {
  readonly thisUpdate: Date;
  readonly nextUpdate: Date | null;
  readonly revoked: ReadonlySet<string>;
  readonly tbsRaw: Buffer;
  readonly signature: Buffer;
  readonly signatureAlgorithmOid: string;
}

function parseCrl(der: Buffer): ParsedCrl {
  const list = parseDer(der).node;
  const parts = children(list);
  const tbs = parts[0];
  const sigAlg = parts[1];
  const sigValue = parts[2];
  if (!tbs || !sigAlg || !sigValue) throw new Error('CRL: malformed');
  const tbsChildren = children(tbs);
  let i = 0;
  if (tbsChildren[i] && tbsChildren[i]!.tag === TAG.INTEGER) i += 1; // version
  i += 1; // signature AlgorithmIdentifier
  i += 1; // issuer
  const thisNode = tbsChildren[i++];
  if (!thisNode) throw new Error('CRL: no thisUpdate');
  const thisUpdate = decodeTime(thisNode);
  let nextUpdate: Date | null = null;
  if (tbsChildren[i] && (tbsChildren[i]!.tag === TAG.UTC_TIME || tbsChildren[i]!.tag === TAG.GENERALIZED_TIME)) {
    nextUpdate = decodeTime(tbsChildren[i]!);
    i += 1;
  }
  const revoked = new Set<string>();
  const revokedSeq = tbsChildren[i];
  if (revokedSeq && revokedSeq.tag === TAG.SEQUENCE) {
    for (const entry of children(revokedSeq)) {
      const serial = children(entry)[0];
      if (serial && serial.tag === TAG.INTEGER) revoked.add(decodeIntegerHex(serial.value));
    }
  }
  const algChildren = children(sigAlg);
  const signatureAlgorithmOid = algChildren[0] ? decodeOid(algChildren[0].value) : '';
  const signature = sigValue.value.subarray(1); // drop unused-bits byte
  return { thisUpdate, nextUpdate, revoked, tbsRaw: tbs.raw, signature, signatureAlgorithmOid };
}

const RSA_HASH_BY_OID: Record<string, string> = {
  '1.2.840.113549.1.1.5': 'sha1',
  '1.2.840.113549.1.1.11': 'sha256',
  '1.2.840.113549.1.1.12': 'sha384',
  '1.2.840.113549.1.1.13': 'sha512',
  '1.2.840.10045.4.3.2': 'sha256',
  '1.2.840.10045.4.3.3': 'sha384',
  '1.2.840.10045.4.3.4': 'sha512',
};

function verifySignature(oid: string, tbsRaw: Buffer, signature: Buffer, key: KeyObject): boolean {
  const hash = RSA_HASH_BY_OID[oid];
  if (!hash) return false;
  const isEc = oid.startsWith('1.2.840.10045');
  return cryptoVerify(hash, tbsRaw, { key, ...(isEc ? { dsaEncoding: 'der' as const } : {}) }, signature);
}

// ---------------------------------------------------------------------------
// OCSP
// ---------------------------------------------------------------------------

function sha1(data: Buffer | Uint8Array): Buffer {
  return createHash('sha1').update(data).digest();
}

function subjectNameDer(certDer: Buffer): Buffer {
  const tbs = tbsOfCert(certDer);
  const list = children(tbs);
  let i = 0;
  if (list[i] && list[i]!.cls === 2 && list[i]!.tag === 0) i += 1; // version
  i += 1; // serial
  i += 1; // signature
  i += 1; // issuer
  i += 1; // validity
  const subject = list[i];
  if (!subject) throw new Error('certificate: no subject');
  return subject.raw;
}

function publicKeyBits(certDer: Buffer): Buffer {
  const tbs = tbsOfCert(certDer);
  const list = children(tbs);
  let i = 0;
  if (list[i] && list[i]!.cls === 2 && list[i]!.tag === 0) i += 1;
  i += 5; // serial, signature, issuer, validity, subject
  const spki = list[i];
  if (!spki) throw new Error('certificate: no spki');
  const bitString = children(spki)[1];
  if (!bitString) throw new Error('certificate: no public key bit string');
  return bitString.value.subarray(1);
}

export interface OcspCertId {
  readonly hashOid: string;
  readonly nameHash: Buffer;
  readonly keyHash: Buffer;
  readonly serialHex: string;
}

/** The CertID a response must carry for this certificate, per RFC 6960 §4.1.1. */
function expectedCertId(cert: X509Certificate, issuer: X509Certificate): OcspCertId {
  const serial = Buffer.from(cert.serialNumber.replace(/[^0-9a-fA-F]/g, ''), 'hex');
  return {
    hashOid: OID.SHA1,
    nameHash: sha1(subjectNameDer(Buffer.from(issuer.raw))),
    keyHash: sha1(publicKeyBits(Buffer.from(issuer.raw))),
    serialHex: decodeIntegerHex(serial.length ? serial : Buffer.from([0])),
  };
}

export function buildOcspRequest(cert: X509Certificate, issuer: X509Certificate): Buffer {
  const id = expectedCertId(cert, issuer);
  const serial = Buffer.from(cert.serialNumber.replace(/[^0-9a-fA-F]/g, ''), 'hex');
  const certId = derSequence(
    derSequence(derOid(id.hashOid), derNull()),
    derOctetString(id.nameHash),
    derOctetString(id.keyHash),
    derInteger(serial.length ? serial : Buffer.from([0])),
  );
  const request = derSequence(certId);
  const requestList = derSequence(request);
  const tbsRequest = derSequence(requestList);
  return derSequence(tbsRequest);
}

const enum OcspCertStatus {
  Good = 0,
  Revoked = 1,
  Unknown = 2,
}

interface OcspSingleResponse {
  readonly certId: OcspCertId | null;
  readonly status: RevocationStatus;
  readonly thisUpdate: Date | null;
  readonly nextUpdate: Date | null;
}

interface ParsedOcsp {
  readonly tbsRaw: Buffer;
  readonly signature: Buffer;
  readonly signatureAlgorithmOid: string;
  /** Certificates embedded in the response, used to find a delegated responder. */
  readonly certs: readonly Buffer[];
  readonly responses: readonly OcspSingleResponse[];
}

/** Parse a CertID SEQUENCE. */
function parseCertId(node: DerNode): OcspCertId | null {
  const parts = children(node);
  const alg = parts[0];
  const nameHash = parts[1];
  const keyHash = parts[2];
  const serial = parts[3];
  if (!alg || !nameHash || !keyHash || !serial) return null;
  if (nameHash.tag !== TAG.OCTET_STRING || keyHash.tag !== TAG.OCTET_STRING || serial.tag !== TAG.INTEGER) {
    return null;
  }
  const algParts = alg.tag === TAG.SEQUENCE ? children(alg) : [alg];
  const algOid = algParts[0];
  if (!algOid || algOid.tag !== TAG.OID) return null;
  return {
    hashOid: decodeOid(algOid.value),
    nameHash: Buffer.from(nameHash.value),
    keyHash: Buffer.from(keyHash.value),
    serialHex: decodeIntegerHex(serial.value),
  };
}

function certIdMatches(a: OcspCertId, b: OcspCertId): boolean {
  return (
    a.hashOid === b.hashOid &&
    a.serialHex === b.serialHex &&
    Buffer.compare(a.nameHash, b.nameHash) === 0 &&
    Buffer.compare(a.keyHash, b.keyHash) === 0
  );
}

function parseOcspResponse(der: Buffer): ParsedOcsp {
  const top = parseDer(der).node;
  const topChildren = children(top);
  const statusNode = topChildren[0];
  if (!statusNode || statusNode.tag !== 0x0a) throw new Error('OCSP: no response status');
  const responseStatus = statusNode.value[0] ?? 0xff;
  if (responseStatus !== 0) throw new Error(`OCSP: response status ${responseStatus}`);
  const responseBytesWrap = topChildren.find((c) => c.cls === 2 && c.tag === 0);
  if (!responseBytesWrap) throw new Error('OCSP: no response bytes');
  const responseBytes = parseDer(responseBytesWrap.value).node;
  const rbChildren = children(responseBytes);
  const responseOctet = rbChildren.find((c) => c.tag === TAG.OCTET_STRING);
  if (!responseOctet) throw new Error('OCSP: no basic response');
  const basic = parseDer(responseOctet.value).node;
  const basicChildren = children(basic);
  const tbsResponseData = basicChildren[0];
  const sigAlg = basicChildren[1];
  const sigValue = basicChildren[2];
  if (!tbsResponseData || !sigAlg || !sigValue) throw new Error('OCSP: malformed basic response');
  const sigAlgOid = decodeOid(children(sigAlg)[0]!.value);
  const signature = sigValue.value.subarray(1);

  // certs [0] EXPLICIT SEQUENCE OF Certificate
  const certsWrap = basicChildren.find((c) => c.cls === 2 && c.tag === 0);
  const certs: Buffer[] = [];
  if (certsWrap) {
    const certsSeq = parseDer(certsWrap.value).node;
    for (const cert of children(certsSeq)) certs.push(Buffer.from(cert.raw));
  }

  // ResponseData -> responses SEQUENCE OF SingleResponse
  const responses: OcspSingleResponse[] = [];
  const rdChildren = children(tbsResponseData);
  const responsesSeq = rdChildren.find(
    (c) => c.tag === TAG.SEQUENCE && children(c).some((x) => x.tag === TAG.SEQUENCE),
  );
  if (responsesSeq) {
    for (const single of children(responsesSeq)) {
      const sc = children(single);
      if (sc.length === 0) continue;
      const certId = parseCertId(sc[0]!);
      const certStatus = sc.find((c) => c.cls === 2 && (c.tag === 0 || c.tag === 1 || c.tag === 2));
      const times = sc.filter((c) => c.tag === TAG.UTC_TIME || c.tag === TAG.GENERALIZED_TIME);
      let status: RevocationStatus = 'unknown';
      if (certStatus) {
        if (certStatus.tag === OcspCertStatus.Good) status = 'good';
        else if (certStatus.tag === OcspCertStatus.Revoked) status = 'revoked';
      }
      responses.push({
        certId,
        status,
        thisUpdate: times[0] ? decodeTime(times[0]) : null,
        nextUpdate: times[1] ? decodeTime(times[1]) : null,
      });
    }
  }
  return { tbsRaw: tbsResponseData.raw, signature, signatureAlgorithmOid: sigAlgOid, certs, responses };
}

const OID_OCSP_SIGNING = '1.3.6.1.5.5.7.3.9';
const OID_EKU = '2.5.29.37';

/** True when the certificate asserts the id-kp-OCSPSigning extended key usage. */
function hasOcspSigningEku(cert: X509Certificate): boolean {
  try {
    const tbs = tbsOfCert(Buffer.from(cert.raw));
    for (const ext of extensionsOf(tbs)) {
      const list = children(ext);
      const oidNode = list[0];
      if (!oidNode || oidNode.tag !== TAG.OID || decodeOid(oidNode.value) !== OID_EKU) continue;
      const valueNode = list.find((n) => n.tag === TAG.OCTET_STRING);
      if (!valueNode) continue;
      const eku = parseDer(valueNode.value).node;
      return children(eku).some((n) => n.tag === TAG.OID && decodeOid(n.value) === OID_OCSP_SIGNING);
    }
  } catch {
    return false;
  }
  return false;
}

/** Verify the OCSP signature with the issuer key or a delegated responder cert. */
function verifyOcspSignature(parsed: ParsedOcsp, issuer: X509Certificate, now: Date): boolean {
  if (verifySignature(parsed.signatureAlgorithmOid, parsed.tbsRaw, parsed.signature, issuer.publicKey)) {
    return true;
  }
  for (const der of parsed.certs) {
    let responder: X509Certificate;
    try {
      responder = new X509Certificate(der);
    } catch {
      continue;
    }
    const from = new Date(responder.validFrom);
    const to = new Date(responder.validTo);
    if (now < from || now > to) continue;
    if (!hasOcspSigningEku(responder)) continue;
    try {
      if (!responder.verify(issuer.publicKey)) continue;
    } catch {
      continue;
    }
    if (verifySignature(parsed.signatureAlgorithmOid, parsed.tbsRaw, parsed.signature, responder.publicKey)) {
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

/** Default cap on an OCSP/CRL response body, in bytes. */
const DEFAULT_MAX_REVOCATION_RESPONSE_BYTES = 1024 * 1024;

/**
 * Fetch a revocation resource and read at most `maxBytes` of its body while the
 * deadline and caller cancellation stay active. The previous helper cleared its
 * timer as soon as the response headers arrived, leaving the body read
 * unbounded; here the timeout covers the whole exchange and an oversized body
 * aborts the read. Any network, timeout, abort or size failure propagates to the
 * caller, which treats it as "no answer".
 */
async function fetchBounded(
  url: string,
  init: RequestInit,
  timeoutMs: number,
  maxBytes: number,
  fetchImpl: typeof fetch,
  signal?: AbortSignal,
): Promise<Buffer | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const onAbort = () => controller.abort();
  signal?.addEventListener('abort', onAbort, { once: true });
  if (signal?.aborted) controller.abort();
  try {
    const response = await fetchImpl(url, { ...init, signal: controller.signal, redirect: 'follow' });
    if (!response.ok) return null;
    return await readCapped(response, maxBytes);
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', onAbort);
  }
}

/** Read a response body in full, failing if it exceeds `maxBytes`. */
async function readCapped(response: Response, maxBytes: number): Promise<Buffer> {
  if (response.body === null) return Buffer.alloc(0);
  const reader = response.body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new Error(`revocation response exceeds ${maxBytes} bytes`);
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks);
}

function cacheKey(cert: X509Certificate): string {
  return certFingerprint256(cert);
}

/**
 * Check revocation for `cert` against its `issuer`. OCSP is tried first when
 * configured and an OCSP responder is advertised; CRL is the fallback. A result
 * that cannot be obtained is returned as `unknown` and the caller applies the
 * configured unreachable policy.
 */
export async function checkRevocation(
  cert: X509Certificate,
  issuer: X509Certificate,
  endpoints: RevocationEndpoints,
  options: RevocationCheckerOptions,
): Promise<RevocationAnswer> {
  const { policy, now } = options;
  const fetchImpl = options.fetchImpl ?? fetch;
  const cache = options.cache;
  const current = now();

  const extra = options.extraRevokedSerials?.[commonNameOf(issuer)];
  if (extra?.some((s) => s.toLowerCase() === cert.serialNumber.toLowerCase())) {
    return { status: 'revoked', source: 'config', reason: 'serial present in configured revocation list' };
  }

  if (endpoints.ocsp.length === 0 && endpoints.crl.length === 0) {
    // Nothing is advertised, so there is no revocation service to reach. This
    // is not an unreachable-service condition; it is "no revocation information".
    return { status: 'good', source: 'none', reason: 'no revocation endpoint advertised' };
  }

  const cached = cache?.get(cacheKey(cert), current);
  if (cached) return { ...cached, reason: `${cached.reason} (cached)` };

  const attempt = async (): Promise<RevocationAnswer> => {
    let ocspAnswer: RevocationAnswer | null = null;
    if (policy.ocsp && endpoints.ocsp.length > 0) {
      ocspAnswer = await tryOcsp(cert, issuer, endpoints.ocsp[0]!, options, fetchImpl);
    }
    // Accept a definitive OCSP answer; on anything else (unverifiable, expired,
    // unknown) fall back to the CRL. This matters for the Peppol PKI, where
    // OCSP is signed by a delegated DigiCert responder.
    if (ocspAnswer && ocspAnswer.status !== 'unknown') return ocspAnswer;
    if (policy.crl && endpoints.crl.length > 0) {
      const crlAnswer = await tryCrl(cert, issuer, endpoints.crl[0]!, options, fetchImpl);
      if (crlAnswer) return crlAnswer;
    }
    if (ocspAnswer) return ocspAnswer;
    return { status: 'unknown', source: 'none', reason: 'no reachable revocation endpoint' };
  };

  const answer = await attempt();
  if (cache) cache.set(cacheKey(cert), answer, current, policy.maxCacheMs);
  return answer;
}

async function tryOcsp(
  cert: X509Certificate,
  issuer: X509Certificate,
  url: string,
  options: RevocationCheckerOptions,
  fetchImpl: typeof fetch,
): Promise<RevocationAnswer | null> {
  try {
    const requestDer = buildOcspRequest(cert, issuer);
    const bytes = await fetchBounded(
      url,
      { method: 'POST', headers: { 'Content-Type': 'application/ocsp-request' }, body: new Uint8Array(requestDer) },
      options.policy.timeoutMs,
      options.policy.maxResponseBytes ?? DEFAULT_MAX_REVOCATION_RESPONSE_BYTES,
      fetchImpl,
      options.signal,
    );
    if (!bytes) return null;
    const parsed = parseOcspResponse(bytes);
    // Accept the response if it is signed by the issuing CA, or by a delegated
    // responder certificate (id-kp-OCSPSigning) that the issuing CA signed.
    // If neither verifies we return null so the caller falls back to the CRL.
    const verifiedAt = options.now();
    if (!verifyOcspSignature(parsed, issuer, verifiedAt)) {
      return null;
    }
    // The response must contain a SingleResponse for *this* certificate, matched
    // by issuer name hash, issuer key hash and serial number (RFC 6960 §4.1.1).
    // Without this, a valid "good" answer for any other certificate from the
    // same CA (OCSP runs over plain HTTP) could be replayed to hide revocation.
    const expected = expectedCertId(cert, issuer);
    const match = parsed.responses.find((r) => r.certId && certIdMatches(r.certId, expected));
    if (!match) return null;
    if (match.thisUpdate && verifiedAt < match.thisUpdate) {
      return { status: 'unknown', source: 'ocsp', reason: 'OCSP thisUpdate in the future' };
    }
    if (match.nextUpdate && verifiedAt > match.nextUpdate) {
      return { status: 'unknown', source: 'ocsp', reason: 'OCSP response expired' };
    }
    return {
      status: match.status,
      source: 'ocsp',
      reason: `OCSP status ${match.status}`,
      ...(match.nextUpdate ? { expiresAt: match.nextUpdate } : {}),
    };
  } catch {
    return null;
  }
}

async function tryCrl(
  cert: X509Certificate,
  issuer: X509Certificate,
  url: string,
  options: RevocationCheckerOptions,
  fetchImpl: typeof fetch,
): Promise<RevocationAnswer | null> {
  try {
    const der = await fetchBounded(
      url,
      { method: 'GET' },
      options.policy.timeoutMs,
      options.policy.maxResponseBytes ?? DEFAULT_MAX_REVOCATION_RESPONSE_BYTES,
      fetchImpl,
      options.signal,
    );
    if (!der) return null;
    const crl = parseCrl(der);
    if (!verifySignature(crl.signatureAlgorithmOid, crl.tbsRaw, crl.signature, issuer.publicKey)) {
      return { status: 'unknown', source: 'crl', reason: 'CRL signature not verifiable with issuer key' };
    }
    const verifiedAt = options.now();
    if (verifiedAt < crl.thisUpdate)
      return { status: 'unknown', source: 'crl', reason: 'CRL thisUpdate in the future' };
    if (crl.nextUpdate && verifiedAt > crl.nextUpdate) {
      return { status: 'unknown', source: 'crl', reason: 'CRL expired' };
    }
    if (crl.revoked.has(cert.serialNumber.toLowerCase())) {
      return {
        status: 'revoked',
        source: 'crl',
        reason: 'serial revoked in CRL',
        ...(crl.nextUpdate ? { expiresAt: crl.nextUpdate } : {}),
      };
    }
    return {
      status: 'good',
      source: 'crl',
      reason: 'serial absent from CRL',
      ...(crl.nextUpdate ? { expiresAt: crl.nextUpdate } : {}),
    };
  } catch {
    return null;
  }
}
