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
import { readCertificateExtensions } from './x509-extensions.js';

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
  /**
   * Maximum age of an OCSP answer that carries no `nextUpdate`: an answer whose
   * `thisUpdate` is older than this is treated as `unknown`, and its effective
   * expiry is `thisUpdate + ocspMaxAgeMs`, so it is never cached beyond that.
   * Defaults to 24 hours. [RFC6960] §3.2.
   */
  readonly ocspMaxAgeMs?: number;
  /** Maximum cache lifetime for a positive/negative revocation answer, milliseconds. */
  readonly maxCacheMs: number;
  /**
   * Maximum cache lifetime for an `unknown` answer (no revocation service could
   * be reached, or the responder answered "unknown"), milliseconds. Kept short
   * so a recovered service is used again quickly. `0` disables caching of
   * `unknown`. Never longer than `maxCacheMs`. Defaults to 60 000.
   *
   * A non-positive or non-finite value (such as `0`, a negative number or `NaN`)
   * also means "not cached": `RevocationCache.set` refuses any entry that would
   * not outlive `now`, so the safe direction needs no separate validation.
   */
  readonly unknownCacheMs?: number;
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
    if (!Number.isFinite(entry.expiresAt) || entry.expiresAt <= now.getTime()) {
      this.entries.delete(key);
      return null;
    }
    return entry.answer;
  }

  set(key: string, answer: RevocationAnswer, now: Date, maxCacheMs: number): void {
    const cap = now.getTime() + maxCacheMs;
    const stated = answer.expiresAt ? answer.expiresAt.getTime() : cap;
    const expiresAt = Math.min(cap, stated);
    // Never store an entry that could never expire (a non-finite expiry).
    if (!Number.isFinite(expiresAt) || expiresAt <= now.getTime()) return;
    this.entries.set(key, { answer, expiresAt });
  }
}

// ---------------------------------------------------------------------------
// CRL
// ---------------------------------------------------------------------------

interface CrlExtension {
  readonly oid: string;
  readonly critical: boolean;
}

interface ParsedCrl {
  readonly version: number;
  /** DER of the CRL issuer Name, compared with the certificate issuer's Name. */
  readonly issuerDer: Buffer;
  readonly thisUpdate: Date;
  readonly nextUpdate: Date | null;
  readonly revoked: ReadonlySet<string>;
  readonly extensions: readonly CrlExtension[];
  readonly tbsRaw: Buffer;
  readonly signature: Buffer;
  readonly signatureAlgorithmOid: string;
}

/** CRL extensions the constrained profile cannot honour. [RFC5280] §5.2.4. */
const CRL_DELTA_INDICATOR = '2.5.29.27';
const CRL_ISSUING_DISTRIBUTION_POINT = '2.5.29.28';

function parseCrl(der: Buffer): ParsedCrl {
  const list = parseDer(der).node;
  const parts = children(list);
  const tbs = parts[0];
  const sigAlg = parts[1];
  const sigValue = parts[2];
  if (!tbs || !sigAlg || !sigValue) throw new Error('CRL: malformed');
  const tbsChildren = children(tbs);
  let i = 0;
  let version = 0; // v1
  if (tbsChildren[i] && tbsChildren[i]!.tag === TAG.INTEGER) {
    version = tbsChildren[i]!.value[0] ?? 0;
    i += 1;
  }
  i += 1; // signature AlgorithmIdentifier
  const issuer = tbsChildren[i];
  i += 1;
  if (!issuer) throw new Error('CRL: no issuer');
  const thisNode = tbsChildren[i];
  i += 1;
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
    i += 1;
  }
  // crlExtensions [0] EXPLICIT Extensions OPTIONAL. Extensions require v2.
  const extensions: CrlExtension[] = [];
  const extWrap = tbsChildren[i];
  if (extWrap && extWrap.cls === 2 && extWrap.tag === 0) {
    if (version < 1) throw new Error('CRL: extensions on a v1 CRL');
    const extSeq = parseDer(extWrap.value).node;
    for (const ext of children(extSeq)) {
      const extParts = children(ext);
      const oidNode = extParts[0];
      if (!oidNode || oidNode.tag !== TAG.OID) throw new Error('CRL: malformed extension');
      const booleanNode = extParts.find((n) => n.tag === TAG.BOOLEAN);
      extensions.push({ oid: decodeOid(oidNode.value), critical: booleanNode ? booleanNode.value[0] !== 0 : false });
    }
  }
  const algChildren = children(sigAlg);
  const signatureAlgorithmOid = algChildren[0] ? decodeOid(algChildren[0].value) : '';
  const signature = sigValue.value.subarray(1); // drop unused-bits byte
  return {
    version,
    issuerDer: Buffer.from(issuer.raw),
    thisUpdate,
    nextUpdate,
    revoked,
    extensions,
    tbsRaw: tbs.raw,
    signature,
    signatureAlgorithmOid,
  };
}

/**
 * Hash algorithms accepted for OCSP-response and CRL signatures. Unlike the
 * certificate profile, which rejects SHA-1 certificates, revocation responses are
 * accepted with SHA-1 for compatibility with deployed responders and CAs. This is
 * deliberately separate from the SHA-1 used to compute OCSP CertID identifier
 * hashes (see `expectedCertId`).
 */
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
  /** Set when a mandatory field is missing/malformed or an extension is unsupported. */
  readonly unsupported: string | null;
}

interface ParsedOcsp {
  readonly tbsRaw: Buffer;
  readonly signature: Buffer;
  readonly signatureAlgorithmOid: string;
  /** Certificates embedded in the response, used to find a delegated responder. */
  readonly certs: readonly Buffer[];
  /** ResponderID carried by the response: byName (subject) or byKey (key hash). */
  readonly responderId: ResponderId | null;
  /** Set when the response carries a version or extension the profile cannot honour. */
  readonly unsupported: string | null;
  readonly responses: readonly OcspSingleResponse[];
}

interface ResponderId {
  readonly kind: 'name' | 'key';
  /** The Name DER for `name`, or the KeyHash bytes for `key`. */
  readonly value: Buffer;
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

  // ResponseData -> version [0], responderID, responses, responseExtensions [1].
  const rdChildren = children(tbsResponseData);
  let unsupported: string | null = null;

  // version [0] EXPLICIT Version DEFAULT v1: only v1 is supported.
  const versionNode = rdChildren.find((c) => c.cls === 2 && c.tag === 0);
  if (versionNode) {
    let version = -1;
    try {
      const inner = parseDer(versionNode.value).node;
      if (inner.tag === TAG.INTEGER) version = inner.value[0] ?? 0;
    } catch {
      version = -1;
    }
    if (version !== 0) unsupported = 'OCSP: unsupported or malformed response version';
  }

  const responsesSeq = rdChildren.find(
    (c) => c.tag === TAG.SEQUENCE && children(c).some((x) => x.tag === TAG.SEQUENCE),
  );
  const responsesIndex = responsesSeq ? rdChildren.indexOf(responsesSeq) : rdChildren.length;

  // responderID (before responses): byName [1] or byKey [2].
  let responderId: ResponderId | null = null;
  for (let idx = 0; idx < responsesIndex; idx += 1) {
    const node = rdChildren[idx]!;
    if (node.cls !== 2) continue;
    if (node.tag === 1) {
      responderId = { kind: 'name', value: Buffer.from(node.value) };
      break;
    }
    if (node.tag === 2) {
      let value = Buffer.from(node.value);
      if (node.constructed) {
        // [2] EXPLICIT OCTET STRING (normative OCSP module): the inner node is the
        // OCTET STRING itself, not its content.
        const inner = parseDer(node.value).node;
        if (inner.tag === TAG.OCTET_STRING) value = Buffer.from(inner.value);
      }
      responderId = { kind: 'key', value };
      break;
    }
  }

  // responseExtensions [1] (after responses): unrecognized critical ones reject.
  const responseExtensions = rdChildren.find((c, idx) => idx > responsesIndex && c.cls === 2 && c.tag === 1);
  if (responseExtensions) {
    const critical = criticalExtensionOids(responseExtensions);
    if (critical.length > 0) unsupported = `OCSP: unsupported critical response extension ${critical[0]}`;
  }

  const responses: OcspSingleResponse[] = [];
  if (responsesSeq) {
    for (const single of children(responsesSeq)) {
      const sc = children(single);
      if (sc.length < 2) continue; // certID and certStatus are the minimum
      const certId = parseCertId(sc[0]!);
      const certStatus = sc[1];
      let status: RevocationStatus = 'unknown';
      if (certStatus && certStatus.cls === 2) {
        if (certStatus.tag === OcspCertStatus.Good) status = 'good';
        else if (certStatus.tag === OcspCertStatus.Revoked) status = 'revoked';
      }
      let singleUnsupported: string | null = null;
      // thisUpdate is a mandatory direct GeneralizedTime/UTCTime.
      let index = 2;
      const thisNode = sc[index];
      let thisUpdate: Date | null = null;
      if (thisNode && (thisNode.tag === TAG.GENERALIZED_TIME || thisNode.tag === TAG.UTC_TIME)) {
        thisUpdate = decodeTime(thisNode);
        index += 1;
      } else {
        singleUnsupported = 'OCSP: malformed or missing thisUpdate';
      }
      // nextUpdate is optional and wrapped in [0] EXPLICIT. A present-but-malformed
      // [0] must not be treated as an absent nextUpdate (which would fall back to
      // the max-age window).
      let nextUpdate: Date | null = null;
      const nextNode = sc[index];
      if (nextNode && nextNode.cls === 2 && nextNode.tag === 0) {
        try {
          const inner = parseDer(nextNode.value).node;
          if (inner.tag === TAG.GENERALIZED_TIME || inner.tag === TAG.UTC_TIME) nextUpdate = decodeTime(inner);
          else singleUnsupported = 'OCSP: malformed nextUpdate';
        } catch {
          singleUnsupported = 'OCSP: malformed nextUpdate';
        }
        index += 1;
      }
      // singleExtensions [1]: unrecognized critical ones reject.
      const singleExt = sc[index];
      if (singleExt && singleExt.cls === 2 && singleExt.tag === 1) {
        const critical = criticalExtensionOids(singleExt);
        if (critical.length > 0) singleUnsupported = `OCSP: unsupported critical single extension ${critical[0]}`;
      }
      responses.push({ certId, status, thisUpdate, nextUpdate, unsupported: singleUnsupported });
    }
  }
  return {
    tbsRaw: tbsResponseData.raw,
    signature,
    signatureAlgorithmOid: sigAlgOid,
    certs,
    responderId,
    unsupported,
    responses,
  };
}

/** OIDs of critical extensions inside an explicit Extensions wrapper. */
function criticalExtensionOids(wrapper: DerNode): string[] {
  const oids: string[] = [];
  const seq = parseDer(wrapper.value).node;
  for (const ext of children(seq)) {
    const parts = children(ext);
    const oidNode = parts[0];
    if (!oidNode || oidNode.tag !== TAG.OID) continue;
    const booleanNode = parts.find((n) => n.tag === TAG.BOOLEAN);
    const critical = booleanNode ? booleanNode.value[0] !== 0 : false;
    if (critical) oids.push(decodeOid(oidNode.value));
  }
  return oids;
}

const OID_OCSP_SIGNING = '1.3.6.1.5.5.7.3.9';
/** id-pkix-ocsp-nocheck: asserts the responder need not be checked for revocation. */
const OID_OCSP_NO_CHECK = '1.3.6.1.5.5.7.48.1.5';
const RESPONDER_CRITICAL_ALLOWLIST: ReadonlySet<string> = new Set([OID_OCSP_NO_CHECK]);

/** SHA-1 of the responder's public key, per [RFC6960] §4.2.2.2 (excludes tag/length). */
function responderKeyHash(cert: X509Certificate): Buffer {
  return sha1(publicKeyBits(Buffer.from(cert.raw)));
}

/** The response's ResponderID must identify the certificate that signed it. [RFC6960] §4.2.2.2.1. */
function matchesResponderId(responder: X509Certificate, id: ResponderId): boolean {
  if (id.kind === 'name') {
    try {
      return Buffer.compare(id.value, subjectNameDer(Buffer.from(responder.raw))) === 0;
    } catch {
      return false;
    }
  }
  return Buffer.compare(id.value, responderKeyHash(responder)) === 0;
}

/**
 * Verify the OCSP signature with the issuer key or a delegated responder cert.
 *
 * A delegated responder is accepted only when it is an end entity the issuer
 * signed, carries id-kp-OCSPSigning, is within its validity window, asserts
 * digitalSignature when Key Usage is present, has no unsupported critical
 * extension, and its identity matches the response's ResponderID. The responder's
 * own revocation status is not checked (it is directly issued by the configured
 * CA and short-lived); that policy is deliberate and can be tightened later.
 */
function verifyOcspSignature(parsed: ParsedOcsp, issuer: X509Certificate, now: Date): boolean {
  if (verifySignature(parsed.signatureAlgorithmOid, parsed.tbsRaw, parsed.signature, issuer.publicKey)) {
    return true;
  }
  const id = parsed.responderId;
  if (!id) return false;
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
    const extensions = readCertificateExtensions(Buffer.from(responder.raw), RESPONDER_CRITICAL_ALLOWLIST);
    if (!extensions.ok) continue;
    if (!extensions.extensions.extendedKeyUsage?.includes(OID_OCSP_SIGNING)) continue;
    if (extensions.extensions.keyUsage && !extensions.extensions.keyUsage.includes('digitalSignature')) continue;
    if (!matchesResponderId(responder, id)) continue;
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

/** Default maximum age of an OCSP answer that carries no `nextUpdate`. */
const DEFAULT_OCSP_MAX_AGE_MS = 24 * 60 * 60 * 1000;

/** Default maximum cache lifetime for an `unknown` revocation answer. */
export const DEFAULT_UNKNOWN_CACHE_MS = 60_000;

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
  if (cache) {
    // An `unknown` answer means no revocation service could be reached. Cache it
    // only briefly, so a service that has recovered is used again quickly,
    // instead of the outage being remembered for the full `maxCacheMs`.
    const maxCacheMs =
      answer.status === 'unknown'
        ? Math.min(policy.unknownCacheMs ?? DEFAULT_UNKNOWN_CACHE_MS, policy.maxCacheMs)
        : policy.maxCacheMs;
    cache.set(cacheKey(cert), answer, current, maxCacheMs);
  }
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
    if (parsed.unsupported) {
      return { status: 'unknown', source: 'ocsp', reason: parsed.unsupported };
    }
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
    if (match.unsupported) {
      return { status: 'unknown', source: 'ocsp', reason: match.unsupported };
    }
    if (!match.thisUpdate || Number.isNaN(match.thisUpdate.getTime())) {
      return { status: 'unknown', source: 'ocsp', reason: 'OCSP response has no valid thisUpdate' };
    }
    if (verifiedAt < match.thisUpdate) {
      return { status: 'unknown', source: 'ocsp', reason: 'OCSP thisUpdate in the future' };
    }
    const maxAgeMs = options.policy.ocspMaxAgeMs ?? DEFAULT_OCSP_MAX_AGE_MS;
    let expiresAt: Date;
    if (match.nextUpdate) {
      if (Number.isNaN(match.nextUpdate.getTime()) || match.nextUpdate < match.thisUpdate) {
        return { status: 'unknown', source: 'ocsp', reason: 'OCSP nextUpdate is invalid' };
      }
      if (verifiedAt > match.nextUpdate) {
        return { status: 'unknown', source: 'ocsp', reason: 'OCSP response expired' };
      }
      expiresAt = match.nextUpdate;
    } else {
      // No nextUpdate: bound the answer's age, and expire it at
      // thisUpdate + maxAgeMs so a replayed answer is never cached past that.
      if (verifiedAt.getTime() - match.thisUpdate.getTime() > maxAgeMs) {
        return {
          status: 'unknown',
          source: 'ocsp',
          reason: 'OCSP response without nextUpdate is older than ocspMaxAgeMs',
        };
      }
      expiresAt = new Date(match.thisUpdate.getTime() + maxAgeMs);
    }
    return { status: match.status, source: 'ocsp', reason: `OCSP status ${match.status}`, expiresAt };
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
    // Coverage: reject CRLs the constrained profile cannot interpret, rather than
    // treating absence from them as non-revocation. [RFC5280] §5.2.4, §6.3.3.
    for (const ext of crl.extensions) {
      if (ext.oid === CRL_DELTA_INDICATOR) {
        return { status: 'unknown', source: 'crl', reason: 'delta CRLs are not supported' };
      }
      if (ext.oid === CRL_ISSUING_DISTRIBUTION_POINT) {
        return { status: 'unknown', source: 'crl', reason: 'scoped or indirect CRLs are not supported' };
      }
      if (ext.critical) {
        return { status: 'unknown', source: 'crl', reason: `unsupported critical CRL extension ${ext.oid}` };
      }
    }
    // The CRL must be issued by this certificate's issuer (full Name, not CN).
    if (Buffer.compare(crl.issuerDer, subjectNameDer(Buffer.from(issuer.raw))) !== 0) {
      return { status: 'unknown', source: 'crl', reason: 'CRL issuer does not match the certificate issuer' };
    }
    // The issuer must be permitted to sign CRLs when it asserts Key Usage.
    const issuerExtensions = readCertificateExtensions(Buffer.from(issuer.raw));
    if (
      issuerExtensions.ok &&
      issuerExtensions.extensions.keyUsage &&
      !issuerExtensions.extensions.keyUsage.includes('cRLSign')
    ) {
      return { status: 'unknown', source: 'crl', reason: 'CRL issuer lacks cRLSign' };
    }
    const verifiedAt = options.now();
    if (Number.isNaN(crl.thisUpdate.getTime())) {
      return { status: 'unknown', source: 'crl', reason: 'CRL has no valid thisUpdate' };
    }
    if (verifiedAt < crl.thisUpdate) {
      return { status: 'unknown', source: 'crl', reason: 'CRL thisUpdate in the future' };
    }
    if (!crl.nextUpdate) {
      return { status: 'unknown', source: 'crl', reason: 'CRL has no nextUpdate' };
    }
    if (Number.isNaN(crl.nextUpdate.getTime())) {
      return { status: 'unknown', source: 'crl', reason: 'CRL has no valid nextUpdate' };
    }
    if (crl.nextUpdate < crl.thisUpdate) {
      return { status: 'unknown', source: 'crl', reason: 'CRL nextUpdate precedes thisUpdate' };
    }
    if (verifiedAt > crl.nextUpdate) {
      return { status: 'unknown', source: 'crl', reason: 'CRL expired' };
    }
    if (crl.revoked.has(cert.serialNumber.toLowerCase())) {
      return { status: 'revoked', source: 'crl', reason: 'serial revoked in CRL', expiresAt: crl.nextUpdate };
    }
    return { status: 'good', source: 'crl', reason: 'serial absent from CRL', expiresAt: crl.nextUpdate };
  } catch {
    return null;
  }
}
