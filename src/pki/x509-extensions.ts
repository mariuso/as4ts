/**
 * Strict, read-only decoding of the X.509 extensions the constrained Peppol
 * certificate profile depends on.
 *
 * The constrained validator does not use Node's `X509Certificate` convenience
 * accessors for path constraints: `keyUsage` there exposes Extended Key Usage
 * OIDs rather than the Key Usage bit string, and neither accessor reports
 * duplicate or malformed extensions. Everything a path decision rests on is
 * decoded here from DER so the rules are explicit and can fail closed.
 *
 * See `docs/certificate-profile.md` for the supported profile this implements.
 */
import { children, decodeOid, isUniversal, parseDer, TAG } from './asn1.js';

export const EXTENSION_OID = {
  subjectKeyIdentifier: '2.5.29.14',
  keyUsage: '2.5.29.15',
  privateKeyUsagePeriod: '2.5.29.16',
  subjectAltName: '2.5.29.17',
  basicConstraints: '2.5.29.19',
  nameConstraints: '2.5.29.30',
  crlDistributionPoints: '2.5.29.31',
  certificatePolicies: '2.5.29.32',
  policyMappings: '2.5.29.33',
  authorityKeyIdentifier: '2.5.29.35',
  policyConstraints: '2.5.29.36',
  extendedKeyUsage: '2.5.29.37',
  inhibitAnyPolicy: '2.5.29.54',
  authorityInfoAccess: '1.3.6.1.5.5.7.1.1',
} as const;

export type KeyUsageName =
  | 'digitalSignature'
  | 'nonRepudiation'
  | 'keyEncipherment'
  | 'dataEncipherment'
  | 'keyAgreement'
  | 'keyCertSign'
  | 'cRLSign'
  | 'encipherOnly'
  | 'decipherOnly';

/** Certificate signature algorithms the constrained profile accepts. */
export const SUPPORTED_SIGNATURE_ALGORITHMS: ReadonlySet<string> = new Set([
  '1.2.840.113549.1.1.11', // sha256WithRSAEncryption
  '1.2.840.113549.1.1.12', // sha384WithRSAEncryption
  '1.2.840.113549.1.1.13', // sha512WithRSAEncryption
]);

/**
 * The OID of the algorithm that signed the certificate itself (the
 * `signatureAlgorithm` field, which the issuer's key must satisfy). Throws on a
 * certificate that does not carry one.
 */
export function readSignatureAlgorithmOid(der: Buffer): string {
  const certificate = parseDer(der).node;
  const algorithm = children(certificate)[1];
  if (!algorithm) throw new Error('no signatureAlgorithm');
  const oid = children(algorithm)[0];
  if (!oid || !isUniversal(oid, TAG.OID)) throw new Error('signatureAlgorithm without an OID');
  return decodeOid(oid.value);
}

/** Key Usage bit names, bit 0 first, as defined by RFC 5280 §4.2.1.3. */
const KEY_USAGE_NAMES: readonly KeyUsageName[] = [
  'digitalSignature',
  'nonRepudiation',
  'keyEncipherment',
  'dataEncipherment',
  'keyAgreement',
  'keyCertSign',
  'cRLSign',
  'encipherOnly',
  'decipherOnly',
];

export interface BasicConstraints {
  readonly ca: boolean;
  /** Present only when the certificate asserts it; `cA` must be true if so. */
  readonly pathLenConstraint?: number;
}

export interface CertificateExtensions {
  readonly basicConstraints: BasicConstraints | null;
  readonly keyUsage: readonly KeyUsageName[] | null;
  readonly extendedKeyUsage: readonly string[] | null;
}

export type ExtensionsResult =
  { readonly ok: true; readonly extensions: CertificateExtensions } | { readonly ok: false; readonly reason: string };

/**
 * Critical extensions whose semantics this validator actually implements. A
 * critical extension outside this set is rejected: recognising an OID is not the
 * same as processing its meaning.
 */
const SUPPORTED_CRITICAL = new Set<string>([
  EXTENSION_OID.basicConstraints,
  EXTENSION_OID.keyUsage,
  EXTENSION_OID.extendedKeyUsage,
]);

/**
 * Extensions that change path processing and are not implemented. They are
 * rejected whether or not they are marked critical, because ignoring them would
 * accept a path the issuer intended to constrain.
 */
const UNSUPPORTED_PATH_CONSTRAINTS = new Set<string>([
  EXTENSION_OID.nameConstraints,
  EXTENSION_OID.policyMappings,
  EXTENSION_OID.policyConstraints,
  EXTENSION_OID.inhibitAnyPolicy,
]);

interface RawExtension {
  readonly oid: string;
  readonly critical: boolean;
  readonly value: Buffer;
}

/** Decode a certificate's extensions, rejecting malformed, duplicate or unsupported ones. */
export function readCertificateExtensions(der: Buffer): ExtensionsResult {
  let raw: RawExtension[];
  try {
    raw = rawExtensions(der);
  } catch (err) {
    return { ok: false, reason: `malformed certificate: ${messageOf(err)}` };
  }

  const seen = new Set<string>();
  let basicConstraints: BasicConstraints | null = null;
  let keyUsage: KeyUsageName[] | null = null;
  let extendedKeyUsage: string[] | null = null;

  try {
    for (const ext of raw) {
      if (seen.has(ext.oid)) return { ok: false, reason: `duplicate extension ${ext.oid}` };
      seen.add(ext.oid);

      if (UNSUPPORTED_PATH_CONSTRAINTS.has(ext.oid)) {
        return { ok: false, reason: `unsupported path-affecting extension ${ext.oid}` };
      }
      if (ext.critical && !SUPPORTED_CRITICAL.has(ext.oid)) {
        return { ok: false, reason: `unsupported critical extension ${ext.oid}` };
      }

      if (ext.oid === EXTENSION_OID.basicConstraints) basicConstraints = parseBasicConstraints(ext.value);
      else if (ext.oid === EXTENSION_OID.keyUsage) keyUsage = parseKeyUsage(ext.value);
      else if (ext.oid === EXTENSION_OID.extendedKeyUsage) extendedKeyUsage = parseExtendedKeyUsage(ext.value);
      // Any other non-critical extension is outside the constrained profile and
      // is ignored, because none of them affect the path decisions made here.
    }
  } catch (err) {
    return { ok: false, reason: `malformed extension: ${messageOf(err)}` };
  }

  return { ok: true, extensions: { basicConstraints, keyUsage, extendedKeyUsage } };
}

function rawExtensions(der: Buffer): RawExtension[] {
  const certificate = parseDer(der).node;
  const tbs = children(certificate)[0];
  if (!tbs) throw new Error('no tbsCertificate');

  const extensionsWrapper = children(tbs).find((node) => node.cls === 2 && node.tag === 3);
  if (!extensionsWrapper) return [];

  const sequence = parseDer(extensionsWrapper.value).node;
  const out: RawExtension[] = [];
  for (const ext of children(sequence)) {
    const parts = children(ext);
    const oidNode = parts[0];
    if (!oidNode || !isUniversal(oidNode, TAG.OID)) throw new Error('extension without an OID');
    const oid = decodeOid(oidNode.value);

    const booleanNode = parts.find((node) => isUniversal(node, TAG.BOOLEAN));
    const critical = booleanNode ? booleanNode.value[0] !== 0 : false;

    const valueNode = parts.find((node) => isUniversal(node, TAG.OCTET_STRING));
    if (!valueNode) throw new Error(`extension ${oid} has no extnValue`);
    out.push({ oid, critical, value: valueNode.value });
  }
  return out;
}

function parseBasicConstraints(value: Buffer): BasicConstraints {
  const sequence = parseDer(value).node;
  if (!isUniversal(sequence, TAG.SEQUENCE)) throw new Error('basicConstraints is not a SEQUENCE');

  const items = children(sequence);
  let index = 0;
  let ca = false;
  if (items[index] && isUniversal(items[index]!, TAG.BOOLEAN)) {
    ca = items[index]!.value[0] !== 0;
    index += 1;
  }
  let pathLenConstraint: number | undefined;
  if (items[index] && isUniversal(items[index]!, TAG.INTEGER)) {
    pathLenConstraint = decodeNonNegativeInteger(items[index]!.value);
    index += 1;
  }
  if (index !== items.length) throw new Error('basicConstraints has unexpected content');
  if (pathLenConstraint !== undefined && !ca) {
    throw new Error('basicConstraints has a pathLenConstraint but cA is false');
  }
  return pathLenConstraint === undefined ? { ca } : { ca, pathLenConstraint };
}

function parseKeyUsage(value: Buffer): KeyUsageName[] {
  const bitString = parseDer(value).node;
  if (!isUniversal(bitString, TAG.BIT_STRING)) throw new Error('keyUsage is not a BIT STRING');
  const unusedBits = bitString.value[0];
  const bits = bitString.value.subarray(1);
  if (unusedBits === undefined || unusedBits > 7) throw new Error('keyUsage has an invalid unused-bits count');

  const totalBits = bits.length * 8 - unusedBits;
  if (totalBits === 0) throw new Error('keyUsage is empty');
  if (totalBits > KEY_USAGE_NAMES.length) throw new Error('keyUsage sets bits beyond the defined names');

  const names: KeyUsageName[] = [];
  for (let i = 0; i < totalBits; i += 1) {
    const byte = bits[i >> 3]!;
    if ((byte >> (7 - (i & 7))) & 1) names.push(KEY_USAGE_NAMES[i]!);
  }
  if (names.length === 0) throw new Error('keyUsage has no bits set');
  return names;
}

function parseExtendedKeyUsage(value: Buffer): string[] {
  const sequence = parseDer(value).node;
  if (!isUniversal(sequence, TAG.SEQUENCE)) throw new Error('extendedKeyUsage is not a SEQUENCE');
  const purposes = children(sequence).map((node) => {
    if (!isUniversal(node, TAG.OID)) throw new Error('extendedKeyUsage contains a non-OID');
    return decodeOid(node.value);
  });
  if (purposes.length === 0) throw new Error('extendedKeyUsage is empty');
  return purposes;
}

function decodeNonNegativeInteger(value: Buffer): number {
  if (value.length === 0) throw new Error('empty INTEGER');
  if ((value[0]! & 0x80) !== 0) throw new Error('negative INTEGER');
  if (value.length > 4) throw new Error('INTEGER too large');
  let result = 0;
  for (const byte of value) result = (result << 8) | byte;
  return result;
}

function messageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
