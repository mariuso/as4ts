import {
  createPublicKey,
  randomBytes,
  sign as cryptoSign,
  constants,
  generateKeyPairSync,
  X509Certificate,
} from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { derBitString, derContext, derInteger, derNull, derOid, derSequence, tlv } from '../../src/pki/asn1.js';

export interface TestCert {
  readonly certPem: string;
  readonly keyPem: string;
  readonly keyObject: KeyObject;
  readonly cert: X509Certificate;
  readonly commonName: string;
  readonly serialHex: string;
}

export interface TestPki {
  readonly root: TestCert;
  readonly intermediate: TestCert;
  readonly sender: TestCert;
  readonly receiver: TestCert;
  readonly revoked: TestCert;
  /** Build a CRL signed by the intermediate that revokes the given serials. */
  makeCrl(
    revokedSerialHexes?: readonly string[],
    opts?: {
      thisUpdate?: Date;
      nextUpdate?: Date;
      extensions?: readonly { readonly oid: string; readonly critical: boolean; readonly der: Buffer }[];
    },
  ): Buffer;
}

export interface TestPkiOptions {
  /** URL placed in every end-entity certificate's CRL distribution point. */
  readonly crlUrl?: string;
  readonly now?: Date;
}

const RSA_SHA256_WITH_RSA = '1.2.840.113549.1.1.11';
const OID = { CN: '2.5.4.3', O: '2.5.4.10', C: '2.5.4.6' } as const;
const EKU = {
  clientAuth: '1.3.6.1.5.5.7.3.2',
  serverAuth: '1.3.6.1.5.5.7.3.1',
  ocspSigning: '1.3.6.1.5.5.7.3.9',
} as const;

const VALIDITY_START_OFFSET_MS = 60 * 1000;
const LEAF_DAYS = 365;
const CA_DAYS = 3650;

type RdnAttrs = ReadonlyArray<readonly [string, string]>;

function toArrayBuffer(buf: Buffer): ArrayBuffer {
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer;
}

function pemEncode(der: Buffer, label: string): string {
  return `-----BEGIN ${label}-----\n${der
    .toString('base64')
    .replace(/(.{64})/g, '$1\n')
    .trim()}\n-----END ${label}-----`;
}

function randomSerial(): { hex: string; der: ArrayBuffer } {
  const bytes = randomBytes(8);
  bytes[0] = bytes[0]! & 0x7f || 1;
  return { hex: bytes.toString('hex'), der: toArrayBuffer(bytes) };
}

function nowOffset(base: Date, days: number): Date {
  return new Date(base.getTime() + days * 24 * 3600 * 1000);
}

interface KeyMaterial {
  readonly keyObject: KeyObject;
  readonly keyPem: string;
  readonly spkiDer: Buffer;
}

function newKey(): KeyMaterial {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return {
    keyObject: privateKey,
    keyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    spkiDer: publicKey.export({ type: 'spki', format: 'der' }),
  };
}

function rdn(attrs: RdnAttrs): pkijs.RelativeDistinguishedNames {
  // One RelativeDistinguishedName (SET) per attribute, so the rendered subject
  // has "CN=..\nO=..\nC=.." rather than a single multi-valued RDN. pkijs's own
  // RelativeDistinguishedNames packs everything into one SET, so build the Name
  // ASN.1 ourselves; Certificate.encodeTBS only calls `.toSchema()` on it.
  const node = new asn1js.Sequence({
    value: attrs.map(
      ([oid, text]) =>
        new asn1js.Set({
          value: [
            new asn1js.Sequence({
              value: [new asn1js.ObjectIdentifier({ value: oid }), new asn1js.Utf8String({ value: text })],
            }),
          ],
        }),
    ),
  });
  return { toSchema: () => node, toJSON: () => ({}) } as unknown as pkijs.RelativeDistinguishedNames;
}

function extension(extnID: string, critical: boolean, der: Buffer): pkijs.Extension {
  return new pkijs.Extension({ extnID, critical, extnValue: toArrayBuffer(der) });
}

function basicConstraints(cA: boolean, pathLen?: number): Buffer {
  const params: pkijs.BasicConstraintsParameters = { cA };
  if (pathLen !== undefined) params.pathLenConstraint = pathLen;
  return Buffer.from(new pkijs.BasicConstraints(params).toSchema().toBER(false));
}

function keyUsage(bytes: readonly number[], unusedBits: number): Buffer {
  return derBitString(Buffer.from(bytes), unusedBits);
}

function extKeyUsage(...oids: readonly string[]): Buffer {
  return Buffer.from(new pkijs.ExtKeyUsage({ keyPurposes: [...oids] }).toSchema().toBER(false));
}

function subjectAltName(name: string): Buffer {
  return Buffer.from(
    new pkijs.GeneralNames({ names: [new pkijs.GeneralName({ type: 2, value: name })] }).toSchema().toBER(false),
  );
}

function crlDistributionPoints(url: string): Buffer {
  const uri = tlv(0x86, Buffer.from(url, 'latin1'));
  return derSequence(derSequence(derContext(0, derContext(0, uri, true), true)));
}

interface MakeCertParams {
  readonly subject: RdnAttrs;
  readonly issuer: RdnAttrs;
  readonly issuerKey: KeyObject;
  readonly subjectSpkiDer: Buffer;
  readonly notBefore: Date;
  readonly notAfter: Date;
  readonly serial: { hex: string; der: ArrayBuffer };
  readonly extensions: readonly pkijs.Extension[];
  /** Override the certificate's own signature algorithm (negative tests). */
  readonly signatureAlgorithm?: { readonly oid: string; readonly hash: string };
}

function makeCertificate(p: MakeCertParams): { certPem: string; serialHex: string } {
  const cert = new pkijs.Certificate();
  cert.version = 2;
  cert.serialNumber = new asn1js.Integer({ valueHex: p.serial.der });
  cert.issuer = rdn(p.issuer);
  cert.subject = rdn(p.subject);
  cert.notBefore = new pkijs.Time({ type: 0, value: p.notBefore });
  cert.notAfter = new pkijs.Time({ type: 0, value: p.notAfter });
  cert.subjectPublicKeyInfo = pkijs.PublicKeyInfo.fromBER(toArrayBuffer(p.subjectSpkiDer));
  cert.extensions = [...p.extensions];
  const signatureAlgorithm = p.signatureAlgorithm ?? { oid: RSA_SHA256_WITH_RSA, hash: 'sha256' };
  const algorithm = new pkijs.AlgorithmIdentifier({
    algorithmId: signatureAlgorithm.oid,
    algorithmParams: new asn1js.Null(),
  });
  cert.signature = algorithm;
  cert.signatureAlgorithm = algorithm;
  const tbs = Buffer.from(cert.encodeTBS().toBER(false));
  const signature = cryptoSign(signatureAlgorithm.hash, tbs, {
    key: p.issuerKey,
    padding: constants.RSA_PKCS1_PADDING,
  });
  cert.signatureValue = new asn1js.BitString({ valueHex: toArrayBuffer(signature) });
  const der = Buffer.from(cert.toSchema(true).toBER(false));
  return { certPem: pemEncode(der, 'CERTIFICATE'), serialHex: new X509Certificate(der).serialNumber.toLowerCase() };
}

function toKey(certPem: string, key: KeyMaterial, commonName: string): TestCert {
  const cert = new X509Certificate(certPem);
  return {
    certPem,
    keyPem: key.keyPem,
    keyObject: key.keyObject,
    cert,
    commonName,
    serialHex: cert.serialNumber.toLowerCase(),
  };
}

function createRoot(now: Date): { cert: TestCert; key: KeyMaterial } {
  const key = newKey();
  const serial = randomSerial();
  const subject = [
    [OID.CN, 'AS4 Sender Test Root CA'],
    [OID.O, 'AS4 Sender Test'],
    [OID.C, 'NO'],
  ] as const;
  const { certPem } = makeCertificate({
    subject,
    issuer: subject,
    issuerKey: key.keyObject,
    subjectSpkiDer: key.spkiDer,
    notBefore: new Date(now.getTime() - VALIDITY_START_OFFSET_MS),
    notAfter: nowOffset(now, CA_DAYS),
    serial,
    extensions: [
      extension('2.5.29.19', true, basicConstraints(true, 1)),
      extension('2.5.29.15', true, keyUsage([0x06], 1)),
    ],
  });
  return { cert: toKey(certPem, key, 'AS4 Sender Test Root CA'), key };
}

function createIntermediate(now: Date, root: TestCert): { cert: TestCert; key: KeyMaterial } {
  const key = newKey();
  const subject = [
    [OID.CN, 'AS4 Sender Test AP CA'],
    [OID.O, 'AS4 Sender Test'],
    [OID.C, 'NO'],
  ] as const;
  const { certPem } = makeCertificate({
    subject,
    issuer: rdnAttrs(root.cert),
    issuerKey: root.keyObject,
    subjectSpkiDer: key.spkiDer,
    notBefore: new Date(now.getTime() - VALIDITY_START_OFFSET_MS),
    notAfter: nowOffset(now, CA_DAYS),
    serial: randomSerial(),
    extensions: [
      extension('2.5.29.19', true, basicConstraints(true, 0)),
      extension('2.5.29.15', true, keyUsage([0x06], 1)),
    ],
  });
  return { cert: toKey(certPem, key, 'AS4 Sender Test AP CA'), key };
}

function createLeaf(
  now: Date,
  ca: TestCert,
  commonName: string,
  crlUrl?: string,
): { cert: TestCert; key: KeyMaterial } {
  const key = newKey();
  const subject = [
    [OID.CN, commonName],
    [OID.O, 'AS4 Sender Test'],
    [OID.C, 'NO'],
  ] as const;
  const extensions = [
    extension('2.5.29.19', true, basicConstraints(false)),
    extension('2.5.29.15', true, keyUsage([0xa0], 5)),
    extension('2.5.29.37', false, extKeyUsage(EKU.clientAuth)),
  ];
  if (crlUrl) extensions.push(extension('2.5.29.31', false, crlDistributionPoints(crlUrl)));
  const { certPem } = makeCertificate({
    subject,
    issuer: rdnAttrs(ca.cert),
    issuerKey: ca.keyObject,
    subjectSpkiDer: key.spkiDer,
    notBefore: new Date(now.getTime() - VALIDITY_START_OFFSET_MS),
    notAfter: nowOffset(now, LEAF_DAYS),
    serial: randomSerial(),
    extensions,
  });
  return { cert: toKey(certPem, key, commonName), key };
}

function rdnAttrs(cert: X509Certificate): RdnAttrs {
  // Rebuild the RDN from the certificate's parsed subject so the issuer bytes match.
  const attrs: Array<readonly [string, string]> = [];
  for (const line of cert.subject.split('\n')) {
    const [key, ...rest] = line.split('=');
    const oid = key?.trim() === 'CN' ? OID.CN : key?.trim() === 'O' ? OID.O : OID.C;
    attrs.push([oid, rest.join('=').trim()]);
  }
  return attrs;
}

/**
 * A delegated OCSP responder certificate: issued by the intermediate CA and
 * carrying the id-kp-OCSPSigning extended key usage.
 */
export function createDelegatedResponder(pki: TestPki, now = new Date()): TestCert {
  const key = newKey();
  const subject = [
    [OID.CN, 'AS4 Test OCSP Responder'],
    [OID.O, 'AS4 Sender Test'],
    [OID.C, 'NO'],
  ] as const;
  const { certPem } = makeCertificate({
    subject,
    issuer: rdnAttrs(pki.intermediate.cert),
    issuerKey: pki.intermediate.keyObject,
    subjectSpkiDer: key.spkiDer,
    notBefore: new Date(now.getTime() - VALIDITY_START_OFFSET_MS),
    notAfter: nowOffset(now, LEAF_DAYS),
    serial: randomSerial(),
    extensions: [
      extension('2.5.29.19', true, basicConstraints(false)),
      extension('2.5.29.15', true, keyUsage([0x80], 7)),
      extension('2.5.29.37', false, extKeyUsage(EKU.ocspSigning)),
    ],
  });
  return toKey(certPem, key, 'AS4 Test OCSP Responder');
}

export function createTestPki(options: TestPkiOptions = {}): TestPki {
  const now = options.now ?? new Date();
  const root = createRoot(now);
  const intermediate = createIntermediate(now, root.cert);
  const sender = createLeaf(now, intermediate.cert, 'POP000001', options.crlUrl);
  const receiver = createLeaf(now, intermediate.cert, 'POP000002', options.crlUrl);
  const revoked = createLeaf(now, intermediate.cert, 'POP000003', options.crlUrl);

  const makeCrl = (
    revokedSerialHexes: readonly string[] = [revoked.cert.serialHex],
    opts: {
      thisUpdate?: Date;
      nextUpdate?: Date;
      extensions?: readonly { readonly oid: string; readonly critical: boolean; readonly der: Buffer }[];
    } = {},
  ): Buffer => buildCrl(intermediate.cert.cert, intermediate.key.keyObject, revokedSerialHexes, opts, now);

  return {
    root: root.cert,
    intermediate: intermediate.cert,
    sender: sender.cert,
    receiver: receiver.cert,
    revoked: revoked.cert,
    makeCrl,
  };
}

function utcTime(date: Date): Buffer {
  const pad = (n: number) => String(n).padStart(2, '0');
  const text =
    pad(date.getUTCFullYear() % 100) +
    pad(date.getUTCMonth() + 1) +
    pad(date.getUTCDate()) +
    pad(date.getUTCHours()) +
    pad(date.getUTCMinutes()) +
    pad(date.getUTCSeconds()) +
    'Z';
  return tlv(0x17, Buffer.from(text, 'latin1'));
}

function buildCrl(
  issuerCert: X509Certificate,
  issuerKey: KeyObject,
  revokedSerials: readonly string[],
  opts: {
    thisUpdate?: Date;
    nextUpdate?: Date;
    extensions?: readonly { readonly oid: string; readonly critical: boolean; readonly der: Buffer }[];
  },
  now: Date,
): Buffer {
  const parsed = pkijs.Certificate.fromBER(Buffer.from(issuerCert.raw));
  const issuerName = Buffer.from(parsed.subject.toSchema().toBER(false));
  const signatureAlgorithm = derSequence(derOid(RSA_SHA256_WITH_RSA), derNull());
  const entries = revokedSerials.map((hex) => derSequence(derInteger(Buffer.from(hex, 'hex')), utcTime(now)));
  const extensionList = opts.extensions ?? [];
  const crlExtensions =
    extensionList.length > 0
      ? derContext(
          0,
          derSequence(
            ...extensionList.map((e) =>
              derSequence(derOid(e.oid), ...(e.critical ? [tlv(0x01, Buffer.from([0xff]))] : []), tlv(0x04, e.der)),
            ),
          ),
          true,
        )
      : null;
  const tbs = derSequence(
    derInteger(Buffer.from([1])),
    signatureAlgorithm,
    issuerName,
    utcTime(opts.thisUpdate ?? new Date(now.getTime() - 60_000)),
    utcTime(opts.nextUpdate ?? new Date(now.getTime() + 7 * 24 * 3600 * 1000)),
    derSequence(...entries),
    ...(crlExtensions ? [crlExtensions] : []),
  );
  const signature = cryptoSign('sha256', tbs, { key: issuerKey, padding: constants.RSA_PKCS1_PADDING });
  return derSequence(tbs, signatureAlgorithm, derBitString(signature));
}

/** A self-signed test TLS server certificate, used as its own trust anchor. */
export function createTlsServerCert(now = new Date()): { keyPem: string; certPem: string; caPem: string } {
  const key = newKey();
  const subject = [
    [OID.CN, 'localhost'],
    [OID.O, 'AS4 Sender Test'],
  ] as const;
  const { certPem } = makeCertificate({
    subject,
    issuer: subject,
    issuerKey: key.keyObject,
    subjectSpkiDer: key.spkiDer,
    notBefore: new Date(now.getTime() - VALIDITY_START_OFFSET_MS),
    notAfter: nowOffset(now, LEAF_DAYS),
    serial: randomSerial(),
    extensions: [
      extension('2.5.29.19', true, basicConstraints(true)),
      extension('2.5.29.15', true, keyUsage([0xa4], 2)),
      extension('2.5.29.37', false, extKeyUsage(EKU.serverAuth)),
      extension('2.5.29.17', false, subjectAltName('localhost')),
    ],
  });
  return { keyPem: key.keyPem, certPem, caPem: certPem };
}

/** A self-signed end-entity certificate: used for unrelated/rogue signer tests. */
export function createSelfSignedCert(commonName: string, now = new Date()): TestCert {
  const key = newKey();
  const subject = [[OID.CN, commonName]] as const;
  const { certPem } = makeCertificate({
    subject,
    issuer: subject,
    issuerKey: key.keyObject,
    subjectSpkiDer: key.spkiDer,
    notBefore: new Date(now.getTime() - VALIDITY_START_OFFSET_MS),
    notAfter: nowOffset(now, LEAF_DAYS),
    serial: randomSerial(),
    extensions: [
      extension('2.5.29.19', true, basicConstraints(false)),
      extension('2.5.29.15', true, keyUsage([0x80], 7)),
    ],
  });
  return toKey(certPem, key, commonName);
}

export interface CustomKeyUsage {
  readonly bytes: readonly number[];
  readonly unusedBits: number;
}

export interface CustomCertOptions {
  readonly commonName: string;
  readonly isCa: boolean;
  /** BasicConstraints pathLenConstraint; omit for none. */
  readonly pathLen?: number;
  /** Key Usage bits; null omits the extension. Defaults per `isCa`. */
  readonly keyUsage?: CustomKeyUsage | null;
  /** Extended Key Usage OIDs; omit for none. */
  readonly extKeyUsage?: readonly string[];
  /** Raw additional extensions (unknown critical, duplicates, unsupported path constraints). */
  readonly extra?: readonly { readonly oid: string; readonly critical: boolean; readonly der: Buffer }[];
  /** Emit a basicConstraints extension whose extnValue is not a valid SEQUENCE. */
  readonly malformedBasicConstraints?: boolean;
  /** Override the certificate's own signature algorithm (negative tests). */
  readonly signatureAlgorithm?: { readonly oid: string; readonly hash: string };
}

/**
 * Build a certificate with an explicit profile, for the constrained-validator
 * regression tests. Pass `issuer: null` for a self-signed root. This deliberately
 * allows combinations the production PKI never emits (missing keyCertSign,
 * unknown critical extensions, malformed extensions, path-length violations).
 */
export function createCustomCert(now: Date, issuer: TestCert | null, options: CustomCertOptions): TestCert {
  const key = newKey();
  const subject = [
    [OID.CN, options.commonName],
    [OID.O, 'AS4 Sender Test'],
    [OID.C, 'NO'],
  ] as const;

  const extensions: pkijs.Extension[] = [];
  if (options.malformedBasicConstraints) {
    extensions.push(extension('2.5.29.19', true, Buffer.from([0x02, 0x01, 0x00])));
  } else {
    extensions.push(extension('2.5.29.19', true, basicConstraints(options.isCa, options.pathLen)));
  }

  const usage =
    options.keyUsage === undefined
      ? options.isCa
        ? { bytes: [0x06], unusedBits: 1 }
        : { bytes: [0xa0], unusedBits: 5 }
      : options.keyUsage;
  if (usage) extensions.push(extension('2.5.29.15', true, keyUsage(usage.bytes, usage.unusedBits)));

  if (options.extKeyUsage && options.extKeyUsage.length > 0) {
    extensions.push(extension('2.5.29.37', false, extKeyUsage(...options.extKeyUsage)));
  }
  for (const extra of options.extra ?? []) extensions.push(extension(extra.oid, extra.critical, extra.der));

  const { certPem } = makeCertificate({
    subject,
    issuer: issuer ? rdnAttrs(issuer.cert) : subject,
    issuerKey: issuer ? issuer.keyObject : key.keyObject,
    subjectSpkiDer: key.spkiDer,
    notBefore: new Date(now.getTime() - VALIDITY_START_OFFSET_MS),
    notAfter: nowOffset(now, options.isCa ? CA_DAYS : LEAF_DAYS),
    serial: randomSerial(),
    extensions,
    ...(options.signatureAlgorithm ? { signatureAlgorithm: options.signatureAlgorithm } : {}),
  });
  return toKey(certPem, key, options.commonName);
}

export function publicKeyPem(certPem: string): string {
  return createPublicKey(new X509Certificate(certPem).publicKey).export({ type: 'spki', format: 'pem' }).toString();
}

// Kept for callers that only need a fresh PEM key pair (e.g. fixtures).
export function generateKeyPem(): { keyObject: KeyObject; keyPem: string; spkiDer: Buffer } {
  const key = newKey();
  return { keyObject: key.keyObject, keyPem: key.keyPem, spkiDer: key.spkiDer };
}
