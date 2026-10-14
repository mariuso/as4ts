import { constants, createHash, verify as cryptoVerify } from 'node:crypto';
import type { X509Certificate } from 'node:crypto';
import {
  ALGO_EXC_C14N,
  ALGO_RSA_SHA256,
  ALGO_SHA256,
  DS_NS,
  SWA_TRANSFORM_SIGNATURE,
  WSSE_NS,
  WSU_NS,
} from '../constants.js';
import { normalizePem, parseCertificate, safeMessage } from '../util.js';
import {
  CanonicalizationLimitExceeded,
  canonicalize,
  canonicalizeDigest,
  canonicalizeDigestWithin,
  canonicalizeWithin,
  materializeInclusiveNamespaces,
} from './c14n.js';
import { attrOf, elementsByLocalName, firstByLocalName, textOf } from './nodes.js';

/** One reference declared in a signature's SignedInfo: its URI and base64 digest. */
export interface SignedReference {
  readonly uri: string;
  readonly digest: string;
}

/**
 * A reference as verified from an inbound signature: the minimal
 * {@link SignedReference} facts plus the digest algorithm and the exact
 * transform sequence that were validated for it. Carrying these lets a caller
 * reconstruct the reference faithfully (for example in a receipt's
 * `NonRepudiationInformation`) instead of guessing it back.
 */
export interface VerifiedReference extends SignedReference {
  /** The validated `ds:DigestMethod/@Algorithm`. */
  readonly digestMethod: string;
  /** The validated transforms, in document order, with their parameters. */
  readonly transforms: readonly VerifiedTransform[];
}

/** One validated transform on a reference, including its parameters. */
export interface VerifiedTransform {
  readonly algorithm: string;
  /** `InclusiveNamespaces/@PrefixList` entries declared on the transform. */
  readonly inclusivePrefixes: readonly string[];
}

/** The facts a verified WS-Security signature yields. Direction-neutral. */
export interface VerifiedSignature {
  /** The signer's X.509 certificate (PEM), taken from the signed KeyInfo. */
  readonly signerCertificatePem: string;
  readonly signerCertificate: X509Certificate;
  /** Every reference declared in SignedInfo, including non-envelope (`cid:`) ones. */
  readonly references: readonly VerifiedReference[];
  /** The in-envelope elements whose digests actually verified. */
  readonly coveredElements: readonly Element[];
}

export type SignatureFailureReason = 'malformed' | 'bad-signature' | 'digest-mismatch' | 'too-large';

/** Options for verification. `maxCanonicalBytes` bounds canonicalisation expansion. */
export interface VerifySignatureOptions {
  /**
   * Conservative upper bound on any single canonicalisation's output. When
   * omitted, canonicalisation is unbounded. Receipts come from the remote access
   * point, so bounding receipt and lookup parsing is tracked separately.
   */
  readonly maxCanonicalBytes?: number;
}

export interface SignatureVerificationFailure {
  readonly ok: false;
  readonly reason: SignatureFailureReason;
  readonly detail: string;
}

export type SignatureVerification =
  { readonly ok: true; readonly signature: VerifiedSignature } | SignatureVerificationFailure;

/**
 * Verify the WS-Security XML signature of an envelope and report what it covers.
 *
 * This is the direction-neutral half of receipt verification: it checks the
 * signature with no knowledge of what the message means, so a future receiver
 * can verify an inbound user message with the same code. It applies:
 *
 *  - exclusive C14N (`InclusiveNamespaces/PrefixList` honoured) and RSA-SHA256
 *    over `ds:SignedInfo`;
 *  - the duplicate-id rejection: a reference URI is resolved only when exactly
 *    one element carries the id, so an attacker cannot shadow it;
 *  - strict profile validation of every reference before any digest is
 *    computed: SHA-256 digest methods only, exclusive C14N transforms for SOAP
 *    parts and the SwA content-signature transform for `cid:` attachments, so an
 *    unsupported algorithm or transform is rejected even when its content is
 *    resolved later;
 *  - a single signature selected structurally from a `wsse:Security` header
 *    (ambiguous headers are rejected), with all expected parsing and
 *    cryptographic failures returned as values.
 *
 * It does **not** decide what the signature must cover, and it does **not**
 * validate the signer certificate: both are the caller's policy. Every failure
 * is a value with a reason in the `malformed` / `bad-signature` /
 * `digest-mismatch` family; nothing is thrown.
 */
export function verifyWsSecuritySignature(doc: Document, options: VerifySignatureOptions = {}): SignatureVerification {
  const maxCanonicalBytes = options.maxCanonicalBytes;
  try {
    const selected = selectSignature(doc);
    if (!selected.ok) return selected;
    const signature = selected.signature;

    const signerPem = extractSignerCertificate(doc, signature);
    if (!signerPem) return fail('malformed', 'no signer certificate found');
    const signer = parseCertificate(signerPem);

    const signedInfo = firstByLocalName(signature, DS_NS, 'SignedInfo');
    if (!signedInfo) return fail('malformed', 'no SignedInfo');

    const c14nMethod = firstByLocalName(signedInfo, DS_NS, 'CanonicalizationMethod');
    if (attrOf(c14nMethod, 'Algorithm') !== ALGO_EXC_C14N) {
      return fail('bad-signature', 'unexpected canonicalization method');
    }
    const signatureMethod = firstByLocalName(signedInfo, DS_NS, 'SignatureMethod');
    if (attrOf(signatureMethod, 'Algorithm') !== ALGO_RSA_SHA256) {
      return fail('bad-signature', 'unexpected signature method');
    }

    const inclusivePrefixes = inclusivePrefixList(c14nMethod);
    materializeInclusiveNamespaces(signedInfo, inclusivePrefixes);
    const canonicalSignedInfo =
      maxCanonicalBytes === undefined
        ? inclusivePrefixes.length
          ? canonicalize(signedInfo, inclusivePrefixes)
          : canonicalize(signedInfo)
        : canonicalizeWithin(signedInfo, maxCanonicalBytes, inclusivePrefixes.length ? inclusivePrefixes : undefined);

    const signatureValue = textOf(firstByLocalName(signature, DS_NS, 'SignatureValue'));
    if (!signatureValue) return fail('malformed', 'no SignatureValue');
    const signatureBytes = Buffer.from(signatureValue.trim(), 'base64');
    const signatureOk = cryptoVerify(
      'sha256',
      Buffer.from(canonicalSignedInfo, 'utf8'),
      { key: signer.publicKey, padding: constants.RSA_PKCS1_PADDING },
      signatureBytes,
    );
    if (!signatureOk) return fail('bad-signature', 'SignatureValue does not verify over SignedInfo');

    const references = verifyReferences(doc, signedInfo, maxCanonicalBytes);
    if (!references.ok) return references;
    if (references.coveredElements.length === 0) {
      return fail('malformed', 'no verifiable in-envelope references');
    }

    return {
      ok: true,
      signature: {
        signerCertificatePem: signerPem,
        signerCertificate: signer,
        references: references.references,
        coveredElements: references.coveredElements,
      },
    };
  } catch (err) {
    if (err instanceof CanonicalizationLimitExceeded) return fail('too-large', err.message);
    // Malformed certificates and other unexpected cryptographic/parsing errors
    // are facts, never exceptions: the verifier's contract is value-only.
    return fail('malformed', `signature verification failed: ${safeMessage(err)}`);
  }
}

type SignatureSelection = { readonly ok: true; readonly signature: Element } | SignatureVerificationFailure;

/**
 * Select the one signature this verifier is willing to consider. Only a
 * `ds:Signature` inside a `wsse:Security` header is eligible — a signature
 * sitting anywhere else in the document is not — and more than one eligible
 * signature is ambiguous and rejected rather than guessed between.
 */
function selectSignature(doc: Document): SignatureSelection {
  const signatures: Element[] = [];
  for (const security of elementsByLocalName(doc, WSSE_NS, 'Security')) {
    signatures.push(...elementsByLocalName(security, DS_NS, 'Signature'));
  }
  if (signatures.length === 0) return fail('malformed', 'no WS-Security signature found');
  if (signatures.length > 1) return fail('malformed', 'ambiguous WS-Security signature');
  return { ok: true, signature: signatures[0]! };
}

const fail = (reason: SignatureFailureReason, detail: string): SignatureVerificationFailure => ({
  ok: false,
  reason,
  detail,
});

/** Cap on SignedInfo references, so a hostile envelope cannot force unbounded work. */
const MAX_REFERENCES = 64;

type ReferencesVerification =
  | {
      readonly ok: true;
      readonly references: readonly VerifiedReference[];
      readonly coveredElements: readonly Element[];
    }
  | SignatureVerificationFailure;

/**
 * Validate every SignedInfo reference and verify the digests of the in-envelope
 * ones. The profile fixes both the digest algorithm and the transform sequence:
 * SOAP parts use SHA-256 over exclusive C14N, and attachments use the SwA
 * content-signature transform. A reference with any other algorithm or
 * transform is rejected whether or not its content is resolved here, so an
 * unsupported `cid:` reference can no longer slip through unchecked. `cid:`
 * references are returned as validated-and-declared; their content is
 * authenticated by the receiving layer after decryption.
 */
function verifyReferences(doc: Document, signedInfo: Element, maxCanonicalBytes?: number): ReferencesVerification {
  const references = elementsByLocalName(signedInfo, DS_NS, 'Reference');
  if (references.length === 0) return fail('malformed', 'SignedInfo has no references');
  if (references.length > MAX_REFERENCES) return fail('malformed', 'too many references');

  const declared: VerifiedReference[] = [];
  const coveredElements: Element[] = [];
  for (const reference of references) {
    const uri = attrOf(reference, 'URI') ?? '';
    const digest = textOf(firstByLocalName(reference, DS_NS, 'DigestValue'))?.trim();
    if (!digest) return fail('malformed', 'missing DigestValue');

    const digestMethod = attrOf(firstByLocalName(reference, DS_NS, 'DigestMethod'), 'Algorithm');
    if (digestMethod !== ALGO_SHA256) {
      return fail('bad-signature', 'unexpected digest method');
    }

    const transforms: VerifiedTransform[] = elementsByLocalName(reference, DS_NS, 'Transform').map((t) => ({
      algorithm: attrOf(t, 'Algorithm') ?? '',
      inclusivePrefixes: transformInclusivePrefixes(t),
    }));
    const verified: VerifiedReference = { uri, digest, digestMethod, transforms };

    if (uri.startsWith('cid:')) {
      if (transforms.length !== 1 || transforms[0]?.algorithm !== SWA_TRANSFORM_SIGNATURE) {
        return fail('bad-signature', `unsupported attachment transform for ${uri}`);
      }
      declared.push(verified);
      continue; // content is authenticated later, after decryption
    }

    if (!uri.startsWith('#')) return fail('malformed', `unsupported reference ${uri}`);
    if (transforms.length !== 1 || transforms[0]?.algorithm !== ALGO_EXC_C14N) {
      return fail('bad-signature', `unsupported transform for ${uri}`);
    }

    const resolved = resolveIdUnique(doc, uri.slice(1));
    if (resolved.matches > 1) return fail('malformed', `duplicate id ${uri}`);
    if (!resolved.element) return fail('malformed', `unresolved reference ${uri}`);

    const prefixes = transforms[0].inclusivePrefixes;
    materializeInclusiveNamespaces(resolved.element, prefixes);
    const actual =
      maxCanonicalBytes === undefined
        ? prefixes.length
          ? createHash('sha256').update(canonicalize(resolved.element, prefixes), 'utf8').digest('base64')
          : canonicalizeDigest(resolved.element)
        : canonicalizeDigestWithin(resolved.element, maxCanonicalBytes, prefixes.length ? prefixes : undefined);
    if (actual !== digest) return fail('digest-mismatch', `digest mismatch for ${uri}`);
    declared.push(verified);
    coveredElements.push(resolved.element);
  }
  return { ok: true, references: declared, coveredElements };
}

function extractSignerCertificate(doc: Document, signature: Element): string | null {
  const keyInfo = firstByLocalName(signature, DS_NS, 'KeyInfo');
  if (!keyInfo) return null;

  const str = firstByLocalName(keyInfo, WSSE_NS, 'SecurityTokenReference');
  if (str) {
    const reference = firstByLocalName(str, WSSE_NS, 'Reference');
    const uri = attrOf(reference, 'URI');
    const id = uri?.startsWith('#') ? uri.slice(1) : null;
    if (id) {
      const resolved = resolveIdUnique(doc, id);
      const token = resolved.element;
      const b64 = token ? textOf(token)?.replace(/\s+/g, '') : null;
      if (b64) return derBase64ToPem(b64);
    }
  }

  const inline = firstByLocalName(keyInfo, DS_NS, 'X509Certificate');
  const b64 = inline ? textOf(inline)?.replace(/\s+/g, '') : null;
  return b64 ? derBase64ToPem(b64) : null;
}

interface ResolveResult {
  readonly element: Element | null;
  readonly matches: number;
}

/** Resolve an XML id, and report how many elements carry it (duplicates are fatal). */
export function resolveIdUnique(doc: Document, id: string): ResolveResult {
  const all = doc.getElementsByTagName('*');
  const matches: Element[] = [];
  for (let i = 0; i < all.length; i += 1) {
    const element = all.item(i);
    if (!element) continue;
    if (
      element.getAttributeNS(WSU_NS, 'Id') === id ||
      element.getAttribute('Id') === id ||
      element.getAttribute('id') === id
    ) {
      matches.push(element);
    }
  }
  return { element: matches.length === 1 ? matches[0]! : null, matches: matches.length };
}

function inclusivePrefixList(c14nMethod: Element | null): string[] {
  if (!c14nMethod) return [];
  const inc = firstByLocalName(c14nMethod, ALGO_EXC_C14N, 'InclusiveNamespaces');
  const list = attrOf(inc, 'PrefixList');
  return list ? list.split(/\s+/).filter(Boolean) : [];
}

function transformInclusivePrefixes(transform: Element): string[] {
  const inc = firstByLocalName(transform, ALGO_EXC_C14N, 'InclusiveNamespaces');
  const list = attrOf(inc, 'PrefixList');
  return list ? list.split(/\s+/).filter(Boolean) : [];
}

function derBase64ToPem(base64: string): string {
  return normalizePem(`-----BEGIN CERTIFICATE-----\n${base64}\n-----END CERTIFICATE-----`);
}
