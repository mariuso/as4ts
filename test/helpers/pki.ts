import { createPrivateKey, randomBytes, sign as cryptoSign, createPublicKey, constants } from 'node:crypto';
import type { KeyObject, X509Certificate } from 'node:crypto';
import { X509Certificate as X509 } from 'node:crypto';
import forge from 'node-forge';
import { derBitString, derInteger, derNull, derOid, derSequence, tlv } from '../../src/pki/asn1.js';

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
  makeCrl(revokedSerialHexes?: readonly string[], opts?: { thisUpdate?: Date; nextUpdate?: Date }): Buffer;
}

export interface TestPkiOptions {
  /** URL placed in every end-entity certificate's CRL distribution point. */
  readonly crlUrl?: string;
  readonly now?: Date;
}

const VALIDITY_START_OFFSET_MS = 60 * 1000;
const LEAF_DAYS = 365;
const CA_DAYS = 3650;

function toKey(certPem: string, keyPem: string, commonName: string, serialHex: string): TestCert {
  return {
    certPem,
    keyPem,
    keyObject: createPrivateKey(keyPem),
    cert: new X509(certPem),
    commonName,
    serialHex,
  };
}

function randomSerial(): string {
  const bytes = randomBytes(8);
  bytes[0] = bytes[0]! & 0x7f || 1;
  return bytes.toString('hex');
}

function nowOffset(base: Date, days: number, extraMs = 0): Date {
  return new Date(base.getTime() + days * 24 * 3600 * 1000 + extraMs);
}

function createRoot(now: Date): { certPem: string; keyPem: string; commonName: string; serialHex: string } {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  const serialHex = randomSerial();
  cert.serialNumber = serialHex;
  cert.validity.notBefore = new Date(now.getTime() - VALIDITY_START_OFFSET_MS);
  cert.validity.notAfter = nowOffset(now, CA_DAYS);
  const attrs = [
    { name: 'commonName', value: 'AS4 Sender Test Root CA' },
    { name: 'organizationName', value: 'AS4 Sender Test' },
    { name: 'countryName', value: 'NO' },
  ];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    { name: 'basicConstraints', cA: true, pathLenConstraint: 1, critical: true },
    { name: 'keyUsage', critical: true, keyCertSign: true, cRLSign: true },
    { name: 'subjectKeyIdentifier' },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return {
    certPem: forge.pki.certificateToPem(cert),
    keyPem: forge.pki.privateKeyToPem(keys.privateKey),
    commonName: 'AS4 Sender Test Root CA',
    serialHex,
  };
}

function createIntermediate(
  now: Date,
  rootPem: string,
  rootKeyPem: string,
): { certPem: string; keyPem: string; commonName: string; serialHex: string } {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  const serialHex = randomSerial();
  cert.serialNumber = serialHex;
  cert.validity.notBefore = new Date(now.getTime() - VALIDITY_START_OFFSET_MS);
  cert.validity.notAfter = nowOffset(now, CA_DAYS);
  cert.setSubject([
    { name: 'commonName', value: 'AS4 Sender Test AP CA' },
    { name: 'organizationName', value: 'AS4 Sender Test' },
    { name: 'countryName', value: 'NO' },
  ]);
  const rootCert = forge.pki.certificateFromPem(rootPem);
  cert.setIssuer(rootCert.subject.attributes);
  cert.setExtensions([
    { name: 'basicConstraints', cA: true, pathLenConstraint: 0, critical: true },
    { name: 'keyUsage', critical: true, keyCertSign: true, cRLSign: true },
    { name: 'subjectKeyIdentifier' },
    { name: 'authorityKeyIdentifier', keyIdentifier: true },
  ]);
  cert.sign(forge.pki.privateKeyFromPem(rootKeyPem), forge.md.sha256.create());
  return {
    certPem: forge.pki.certificateToPem(cert),
    keyPem: forge.pki.privateKeyToPem(keys.privateKey),
    commonName: 'AS4 Sender Test AP CA',
    serialHex,
  };
}

function createLeaf(
  now: Date,
  caPem: string,
  caKeyPem: string,
  commonName: string,
  crlUrl?: string,
): { certPem: string; keyPem: string; commonName: string; serialHex: string } {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  const serialHex = randomSerial();
  cert.serialNumber = serialHex;
  cert.validity.notBefore = new Date(now.getTime() - VALIDITY_START_OFFSET_MS);
  cert.validity.notAfter = nowOffset(now, LEAF_DAYS);
  cert.setSubject([
    { name: 'commonName', value: commonName },
    { name: 'organizationName', value: 'AS4 Sender Test' },
    { name: 'countryName', value: 'NO' },
  ]);
  const caCert = forge.pki.certificateFromPem(caPem);
  cert.setIssuer(caCert.subject.attributes);
  const extensions: Parameters<forge.pki.Certificate['setExtensions']>[0] = [
    { name: 'basicConstraints', cA: false, critical: true },
    { name: 'keyUsage', critical: true, digitalSignature: true, keyEncipherment: true },
    { name: 'extKeyUsage', clientAuth: true },
    { name: 'subjectKeyIdentifier' },
    { name: 'authorityKeyIdentifier', keyIdentifier: true },
  ];
  if (crlUrl) {
    extensions.push({ name: 'cRLDistributionPoints', altNames: [{ type: 6, value: crlUrl }] });
  }
  cert.setExtensions(extensions);
  cert.sign(forge.pki.privateKeyFromPem(caKeyPem), forge.md.sha256.create());
  return {
    certPem: forge.pki.certificateToPem(cert),
    keyPem: forge.pki.privateKeyToPem(keys.privateKey),
    commonName,
    serialHex,
  };
}

/**
 * A delegated OCSP responder certificate: issued by the intermediate CA and
 * carrying the id-kp-OCSPSigning extended key usage.
 */
export function createDelegatedResponder(pki: TestPki, now = new Date()): TestCert {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  const serialHex = randomSerial();
  cert.serialNumber = serialHex;
  cert.validity.notBefore = new Date(now.getTime() - VALIDITY_START_OFFSET_MS);
  cert.validity.notAfter = nowOffset(now, LEAF_DAYS);
  cert.setSubject([
    { name: 'commonName', value: 'AS4 Test OCSP Responder' },
    { name: 'organizationName', value: 'AS4 Sender Test' },
    { name: 'countryName', value: 'NO' },
  ]);
  cert.setIssuer(forge.pki.certificateFromPem(pki.intermediate.certPem).subject.attributes);
  // node-forge has no ocspSigning flag; build the id-kp-OCSPSigning EKU directly.
  const ocspSigningOid = forge.asn1.oidToDer('1.3.6.1.5.5.7.3.9');
  const ekuValue = forge.asn1
    .toDer(
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false, ocspSigningOid.getBytes()),
      ]),
    )
    .getBytes();
  cert.setExtensions([
    { name: 'basicConstraints', cA: false, critical: true },
    { name: 'keyUsage', critical: true, digitalSignature: true },
    { id: '2.5.29.37', value: ekuValue },
    { name: 'subjectKeyIdentifier' },
    { name: 'authorityKeyIdentifier', keyIdentifier: true },
  ]);
  cert.sign(forge.pki.privateKeyFromPem(pki.intermediate.keyPem), forge.md.sha256.create());
  const certPem = forge.pki.certificateToPem(cert);
  return toKey(certPem, forge.pki.privateKeyToPem(keys.privateKey), 'AS4 Test OCSP Responder', serialHex);
}

export function createTestPki(options: TestPkiOptions = {}): TestPki {
  const now = options.now ?? new Date();
  const root = createRoot(now);
  const intermediate = createIntermediate(now, root.certPem, root.keyPem);
  const sender = createLeaf(now, intermediate.certPem, intermediate.keyPem, 'POP000001', options.crlUrl);
  const receiver = createLeaf(now, intermediate.certPem, intermediate.keyPem, 'POP000002', options.crlUrl);
  const revoked = createLeaf(now, intermediate.certPem, intermediate.keyPem, 'POP000003', options.crlUrl);

  const makeCrl = (
    revokedSerialHexes: readonly string[] = [revoked.serialHex],
    opts: { thisUpdate?: Date; nextUpdate?: Date } = {},
  ): Buffer => buildCrl(intermediate, revokedSerialHexes, opts, now);

  return {
    root: toKey(root.certPem, root.keyPem, root.commonName, root.serialHex),
    intermediate: toKey(intermediate.certPem, intermediate.keyPem, intermediate.commonName, intermediate.serialHex),
    sender: toKey(sender.certPem, sender.keyPem, sender.commonName, sender.serialHex),
    receiver: toKey(receiver.certPem, receiver.keyPem, receiver.commonName, receiver.serialHex),
    revoked: toKey(revoked.certPem, revoked.keyPem, revoked.commonName, revoked.serialHex),
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
  issuer: { certPem: string; keyPem: string },
  revokedSerials: readonly string[],
  opts: { thisUpdate?: Date; nextUpdate?: Date },
  now: Date,
): Buffer {
  const issuerCert = forge.pki.certificateFromPem(issuer.certPem);
  const issuerName = Buffer.from(
    forge.asn1.toDer(forge.pki.distinguishedNameToAsn1(issuerCert.subject)).getBytes(),
    'binary',
  );
  const signatureAlgorithm = derSequence(derOid('1.2.840.113549.1.1.11'), derNull());
  const entries = revokedSerials.map((hex) => derSequence(derInteger(Buffer.from(hex, 'hex')), utcTime(now)));
  const tbs = derSequence(
    derInteger(Buffer.from([1])),
    signatureAlgorithm,
    issuerName,
    utcTime(opts.thisUpdate ?? new Date(now.getTime() - 60_000)),
    utcTime(opts.nextUpdate ?? new Date(now.getTime() + 7 * 24 * 3600 * 1000)),
    derSequence(...entries),
  );
  const signature = cryptoSign('sha256', tbs, {
    key: createPrivateKey(issuer.keyPem),
    padding: constants.RSA_PKCS1_PADDING,
  });
  return derSequence(tbs, signatureAlgorithm, derBitString(signature));
}

/** A self-signed test TLS server certificate, used as its own trust anchor. */
export function createTlsServerCert(now = new Date()): { keyPem: string; certPem: string; caPem: string } {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = randomSerial();
  cert.validity.notBefore = new Date(now.getTime() - VALIDITY_START_OFFSET_MS);
  cert.validity.notAfter = nowOffset(now, LEAF_DAYS);
  const attrs = [
    { name: 'commonName', value: 'localhost' },
    { name: 'organizationName', value: 'AS4 Sender Test' },
  ];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    { name: 'basicConstraints', cA: true, critical: true },
    { name: 'keyUsage', critical: true, digitalSignature: true, keyEncipherment: true, keyCertSign: true },
    { name: 'extKeyUsage', serverAuth: true },
    { name: 'subjectAltName', altNames: [{ type: 2, value: 'localhost' }] },
    { name: 'subjectKeyIdentifier' },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  const certPem = forge.pki.certificateToPem(cert);
  return {
    keyPem: forge.pki.privateKeyToPem(keys.privateKey),
    certPem,
    caPem: certPem,
  };
}

export function publicKeyPem(certPem: string): string {
  return createPublicKey(new X509(certPem).publicKey).export({ type: 'spki', format: 'pem' }).toString();
}
