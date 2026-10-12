import type { X509Certificate } from 'node:crypto';
import { certFingerprint256, commonNameOf, normalizePem, parseCertificate } from '../util.js';

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

function isSelfSigned(cert: X509Certificate): boolean {
  return cert.subject === cert.issuer;
}

/**
 * Build a real certification path from the leaf through the provided Peppol
 * intermediate(s) to a Peppol root trust anchor.
 *
 * Checks, per RFC 5280 / [PEPPOL-PKI]:
 *  - every certificate is within its validity window at `now`;
 *  - each certificate is actually issued and signed by the next one
 *    (`checkIssued` for name/AKI/SKI and `verify` for the signature);
 *  - issuers are CAs (BasicConstraints cA=true, KeyUsage keyCertSign);
 *  - the path terminates at a caller-supplied trust anchor.
 *
 * It does not consult the network. Revocation is a separate step.
 */
export function buildCertificatePath(
  leaf: X509Certificate,
  intermediates: readonly string[],
  roots: readonly string[],
  now: Date,
): PathResult {
  const validity = checkValidity(leaf, now);
  if (validity) return validity;

  const intermediateCerts = intermediates.map((pem) => parseCertificate(normalizePem(pem)));
  const rootCerts = roots.map((pem) => parseCertificate(normalizePem(pem)));
  const rootFingerprints = new Set(rootCerts.map(certFingerprint256));
  const candidates = [...intermediateCerts, ...rootCerts];

  const chain: X509Certificate[] = [leaf];
  let current = leaf;
  const seen = new Set<string>([certFingerprint256(leaf)]);

  for (let depth = 0; depth < 12; depth += 1) {
    if (isSelfSigned(current) && rootFingerprints.has(certFingerprint256(current))) {
      return { ok: true, chain, anchor: current };
    }

    const issuer = findIssuer(current, candidates, rootFingerprints);
    if (!issuer) {
      return { ok: false, reason: `no trusted issuer for ${commonNameOf(current)}` };
    }

    const issuerValidity = checkValidity(issuer, now);
    if (issuerValidity) return issuerValidity;
    if (!issuer.ca) return { ok: false, reason: `issuer ${commonNameOf(issuer)} is not a CA` };
    const issuerUsage: string[] = issuer.keyUsage ?? [];
    if (issuerUsage.length > 0 && !issuerUsage.includes('keyCertSign')) {
      return { ok: false, reason: `issuer ${commonNameOf(issuer)} lacks keyCertSign` };
    }

    const fp = certFingerprint256(issuer);
    if (seen.has(fp)) return { ok: false, reason: 'certificate path loop' };
    seen.add(fp);

    chain.push(issuer);
    if (rootFingerprints.has(fp)) return { ok: true, chain, anchor: issuer };
    current = issuer;
  }
  return { ok: false, reason: 'certificate path too long' };
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
