import type { X509Certificate } from 'node:crypto';
import type { CertificatePurpose } from '../types.js';
import { certFingerprint256, commonNameOf, normalizePem, parseCertificate } from '../util.js';
import {
  readCertificateExtensions,
  readSignatureAlgorithmOid,
  SUPPORTED_SIGNATURE_ALGORITHMS,
  type CertificateExtensions,
  type KeyUsageName,
} from './x509-extensions.js';

export interface PathFailure {
  readonly ok: false;
  readonly reason: string;
}

export interface PathSuccess {
  readonly ok: true;
  /** Ordered leaf -> ... -> anchor (the anchor is the last element). */
  readonly chain: readonly X509Certificate[];
  readonly anchor: X509Certificate;
}

export type PathResult = PathSuccess | PathFailure;

export interface PathOptions {
  /**
   * What the leaf is being validated for. Selects the leaf Key Usage
   * requirement; absent accepts any signing or encryption use.
   */
  readonly purpose?: CertificatePurpose;
}

/** Maximum certificates in a path, leaf through anchor. */
const MAX_CHAIN_LENGTH = 12;

function isSelfSigned(cert: X509Certificate): boolean {
  return cert.subject === cert.issuer;
}

/**
 * Build a real certification path from the leaf through the provided Peppol
 * intermediate(s) to a Peppol root trust anchor, enforcing the constrained
 * profile in `docs/certificate-profile.md`.
 *
 * Checks, per RFC 5280 / [PEPPOL-PKI]:
 *  - every certificate is within its validity window at `now`;
 *  - the leaf is an end entity (BasicConstraints `cA=false`), and its Key Usage,
 *    when present, permits the requested purpose;
 *  - each issuer is actually issued and signed by the next one (`verify`), is a
 *    CA (BasicConstraints `cA=true`, Key Usage `keyCertSign` when asserted);
 *  - `pathLenConstraint` is enforced, counting the non-self-issued CA
 *    certificates below each CA and excluding the leaf and self-issued rollover
 *    certificates;
 *  - unknown critical extensions, unsupported path-affecting extensions,
 *    duplicate extensions and malformed extensions are rejected;
 *  - the path terminates at a caller-supplied trust anchor.
 *
 * The trust anchor is treated as a CA: its BasicConstraints and
 * `pathLenConstraint` are enforced like any other issuer's. It does not consult
 * the network; revocation is a separate step.
 */
export function buildCertificatePath(
  leaf: X509Certificate,
  intermediates: readonly string[],
  roots: readonly string[],
  now: Date,
  options: PathOptions = {},
): PathResult {
  let intermediateCerts: X509Certificate[];
  let rootCerts: X509Certificate[];
  try {
    intermediateCerts = intermediates.map((pem) => parseCertificate(normalizePem(pem)));
    rootCerts = roots.map((pem) => parseCertificate(normalizePem(pem)));
  } catch {
    return { ok: false, reason: 'a configured trust certificate could not be parsed' };
  }

  const validity = checkValidity(leaf, now);
  if (validity) return validity;

  const leafExtensions = readCertificateExtensions(Buffer.from(leaf.raw));
  if (!leafExtensions.ok) return { ok: false, reason: `leaf: ${leafExtensions.reason}` };
  const leafProfile = checkSignatureAlgorithm(leaf);
  if (leafProfile) return leafProfile;
  const leafCheck = checkLeaf(leaf, leafExtensions.extensions, options.purpose);
  if (leafCheck) return leafCheck;

  const rootFingerprints = new Set(rootCerts.map(certFingerprint256));
  const candidates = [...intermediateCerts, ...rootCerts];

  const chain: X509Certificate[] = [leaf];
  const chainExtensions: CertificateExtensions[] = [leafExtensions.extensions];
  let current = leaf;
  const seen = new Set<string>([certFingerprint256(leaf)]);

  for (let depth = 0; depth < MAX_CHAIN_LENGTH; depth += 1) {
    if (isSelfSigned(current) && rootFingerprints.has(certFingerprint256(current))) {
      return finish(chain, current, chainExtensions);
    }

    const issuer = findIssuer(current, candidates, rootFingerprints);
    if (!issuer) {
      return { ok: false, reason: `no trusted issuer for ${commonNameOf(current)}` };
    }

    const issuerValidity = checkValidity(issuer, now);
    if (issuerValidity) return issuerValidity;

    const issuerExtensions = readCertificateExtensions(Buffer.from(issuer.raw));
    if (!issuerExtensions.ok) {
      return { ok: false, reason: `${commonNameOf(issuer)}: ${issuerExtensions.reason}` };
    }
    const issuerProfile = checkSignatureAlgorithm(issuer);
    if (issuerProfile) return issuerProfile;
    const caCheck = checkCa(issuer, issuerExtensions.extensions);
    if (caCheck) return caCheck;

    const fp = certFingerprint256(issuer);
    if (seen.has(fp)) return { ok: false, reason: 'certificate path loop' };
    seen.add(fp);

    chain.push(issuer);
    chainExtensions.push(issuerExtensions.extensions);
    if (rootFingerprints.has(fp)) return finish(chain, issuer, chainExtensions);
    current = issuer;
  }
  return { ok: false, reason: 'certificate path too long' };
}

function finish(
  chain: readonly X509Certificate[],
  anchor: X509Certificate,
  chainExtensions: readonly CertificateExtensions[],
): PathResult {
  const lengthCheck = checkPathLengths(chain, chainExtensions);
  if (lengthCheck) return lengthCheck;
  return { ok: true, chain, anchor };
}

/** The leaf must be an end entity whose Key Usage permits the requested purpose. */
function checkLeaf(
  leaf: X509Certificate,
  extensions: CertificateExtensions,
  purpose: CertificatePurpose | undefined,
): PathFailure | null {
  if (extensions.basicConstraints?.ca === true) {
    return { ok: false, reason: `leaf ${commonNameOf(leaf)} is a CA certificate` };
  }
  if (extensions.keyUsage && !leafUsageSatisfied(extensions.keyUsage, purpose)) {
    return {
      ok: false,
      reason: `leaf ${commonNameOf(leaf)} key usage does not permit ${purpose ?? 'signing or encryption'}`,
    };
  }
  return null;
}

function leafUsageSatisfied(usage: readonly KeyUsageName[], purpose: CertificatePurpose | undefined): boolean {
  switch (purpose) {
    case 'receiver-encryption':
      // RSA-OAEP is key transport, so keyEncipherment is required. keyAgreement
      // authorizes key establishment, a different operation.
      return usage.includes('keyEncipherment');
    case 'message-signer':
    case 'receipt-signer':
    case 'smp-signer':
      return usage.includes('digitalSignature') || usage.includes('nonRepudiation');
    default:
      return (
        usage.includes('digitalSignature') || usage.includes('keyEncipherment') || usage.includes('nonRepudiation')
      );
  }
}

/**
 * The certificate's own signature algorithm must be one the profile supports.
 * The issuer's key has to satisfy it, but an algorithm the validator does not
 * implement is rejected outright rather than left to a default.
 */
function checkSignatureAlgorithm(cert: X509Certificate): PathFailure | null {
  let oid: string;
  try {
    oid = readSignatureAlgorithmOid(Buffer.from(cert.raw));
  } catch {
    return { ok: false, reason: `${commonNameOf(cert)}: unreadable signature algorithm` };
  }
  if (!SUPPORTED_SIGNATURE_ALGORITHMS.has(oid)) {
    return { ok: false, reason: `${commonNameOf(cert)}: unsupported signature algorithm ${oid}` };
  }
  return null;
}

/** An issuer must be a CA that is permitted to sign certificates. */
function checkCa(issuer: X509Certificate, extensions: CertificateExtensions): PathFailure | null {
  if (extensions.basicConstraints?.ca !== true) {
    return { ok: false, reason: `issuer ${commonNameOf(issuer)} is not a CA` };
  }
  if (extensions.keyUsage && !extensions.keyUsage.includes('keyCertSign')) {
    return { ok: false, reason: `issuer ${commonNameOf(issuer)} lacks keyCertSign` };
  }
  return null;
}

/**
 * Enforce `pathLenConstraint`. For each CA in the path, the number of
 * non-self-issued CA certificates between it and the leaf (the leaf itself is
 * excluded, and self-issued rollover certificates do not count) must not exceed
 * its constraint.
 */
function checkPathLengths(
  chain: readonly X509Certificate[],
  chainExtensions: readonly CertificateExtensions[],
): PathFailure | null {
  for (let i = 1; i < chain.length; i += 1) {
    const limit = chainExtensions[i]?.basicConstraints?.pathLenConstraint;
    if (limit === undefined) continue;
    let subordinate = 0;
    for (let k = 1; k < i; k += 1) {
      if (isSelfSigned(chain[k]!)) continue;
      subordinate += 1;
    }
    if (subordinate > limit) {
      return {
        ok: false,
        reason: `${commonNameOf(chain[i]!)} path length constraint ${limit} exceeded by ${subordinate} subordinate CA(s)`,
      };
    }
  }
  return null;
}

function findIssuer(
  cert: X509Certificate,
  candidates: readonly X509Certificate[],
  rootFingerprints: ReadonlySet<string>,
): X509Certificate | null {
  const matches: X509Certificate[] = [];
  for (const candidate of candidates) {
    if (candidate.subject !== cert.issuer) continue;
    // The cryptographic check that matters: the issuer's key signed this
    // certificate. (Node's checkIssued also enforces AKI/SKI consistency, which
    // not all issuers populate; signature verification is the security boundary.)
    try {
      if (!cert.verify(candidate.publicKey)) continue;
    } catch {
      continue;
    }
    matches.push(candidate);
  }
  // Prefer a root when several issuers match.
  return matches.find((c) => rootFingerprints.has(certFingerprint256(c))) ?? matches[0] ?? null;
}

function checkValidity(cert: X509Certificate, now: Date): PathFailure | null {
  const from = new Date(cert.validFrom);
  const to = new Date(cert.validTo);
  if (Number.isNaN(from.getTime()) || Number.isNaN(to.getTime())) {
    return { ok: false, reason: 'unreadable validity' };
  }
  if (now < from) return { ok: false, reason: `certificate not yet valid until ${cert.validFrom}` };
  if (now > to) return { ok: false, reason: `certificate expired at ${cert.validTo}` };
  return null;
}
