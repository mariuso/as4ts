# Constrained certificate profile

This document defines the certificate profile the Peppol AS4 library validates
against. It is deliberately narrow: a certificate or path outside these rules is
**rejected as a value**, not accepted by default. The implementation lives in
[`src/pki/chain.ts`](../src/pki/chain.ts) and
[`src/pki/x509-extensions.ts`](../src/pki/x509-extensions.ts).

The profile covers the Peppol Access Point and SMP certificates used by the
sender, the receiver and SMP discovery. Revocation (OCSP/CRL) is a separate,
mandatory stage under the configured policy; it is not part of path building.

## Supported algorithms

- **Keys:** RSA.
- **Certificate signatures:** RSA PKCS#1 v1.5 with SHA-256, SHA-384 or SHA-512
  (`sha256WithRSAEncryption`, `sha384WithRSAEncryption`,
  `sha512WithRSAEncryption`). Any other certificate signature algorithm — for
  example SHA-1 or ECDSA — is rejected.
- **Content signatures and encryption:** as defined by the Peppol AS4 profile
  (RSA-SHA256, RSA-OAEP/SHA-256, AES-128-GCM); those are enforced by the AS4
  layer, not here.

## Extensions

Processed:

| Extension          | OID         | Handling                                                           |
| ------------------ | ----------- | ------------------------------------------------------------------ |
| Basic Constraints  | `2.5.29.19` | `cA`, `pathLenConstraint` (decoded strictly)                       |
| Key Usage          | `2.5.29.15` | bit string decoded to names (`keyCertSign`, `digitalSignature`, …) |
| Extended Key Usage | `2.5.29.37` | OIDs decoded and kept separate from Key Usage                      |

Ignored when non-critical (they do not affect the path decisions made here):
`subjectKeyIdentifier`, `authorityKeyIdentifier`, `subjectAltName`,
`authorityInfoAccess`, `crlDistributionPoints`, `certificatePolicies`,
`privateKeyUsagePeriod`.

Rejected:

- **Any unrecognised critical extension.** Recognising an OID is not the same as
  processing its meaning; an unimplemented critical extension fails closed.
- **Path-affecting extensions that are not implemented**, whether or not they are
  critical: `nameConstraints` (`2.5.29.30`), `policyMappings` (`2.5.29.33`),
  `policyConstraints` (`2.5.29.36`), `inhibitAnyPolicy` (`2.5.29.54`).
- **Duplicate extensions** (the same OID twice).
- **Malformed extensions**: e.g. a Basic Constraints `extnValue` that is not a
  SEQUENCE, a `pathLenConstraint` without `cA`, a Key Usage with an invalid
  unused-bits count or set bits beyond the defined names.

## Chain shape

- A path is leaf → intermediate(s) → **trust anchor**, terminated at a
  caller-configured root. Intermediates are supplied per purpose; a leaf may
  never be its own issuer.
- Every issuer must be a CA: Basic Constraints present with `cA=true`, and Key
  Usage, when asserted, containing `keyCertSign`.
- The **leaf must be an end entity**: Basic Constraints `cA` must not be true.
- The **leaf Key Usage**, when asserted, must permit the requested purpose:
  - signing purposes (`message-signer`, `receipt-signer`, `smp-signer`) require
    `digitalSignature` or `nonRepudiation`;
  - `receiver-encryption` requires `keyEncipherment` (RSA-OAEP is key
    transport); `keyAgreement` authorizes a different operation and is not
    accepted.
  - internal callers that omit the purpose require at least one supported
    usage: `digitalSignature`, `nonRepudiation`, or `keyEncipherment`.
    `keyAgreement` alone is rejected here too. The public certificate validator
    always supplies a purpose.
- `pathLenConstraint` is enforced on every CA, **including the trust anchor**:
  for each CA, the number of non-self-issued CA certificates between it and the
  leaf (excluding the leaf, and excluding self-issued rollover certificates) must
  not exceed its constraint.
- Every certificate in the path must be within its validity window at the
  caller-supplied `now`, and each certificate's signature must verify with the
  next certificate's key.

## Trust anchors

Trust anchors are caller-supplied and treated as CA certificates: their Basic
Constraints and `pathLenConstraint` are enforced like any other issuer's. This
is a deliberate, stricter choice than treating anchor constraints as advisory.
The configured intermediate set limits which chains can be constructed; it is not
a substitute for the checks above.

## Revocation

Revocation is a separate, mandatory stage: a certificate is checked against its
issuer's OCSP responder or CRL, and an answer that cannot be obtained is `unknown`
(the configured `unreachable` policy decides).

- **OCSP.** The response must be signed by the certificate's issuer, or by a
  delegated responder that the issuer signed, carries `id-kp-OCSPSigning` and
  `digitalSignature` (when Key Usage is present), is within its validity window,
  has no unsupported critical extension, and matches the response's `ResponderID`
  (by name or key hash). The response must carry a `CertID` for this certificate
  and a valid `thisUpdate`. An answer whose `nextUpdate` has passed, or which has
  no `nextUpdate` and is older than `ocspMaxAgeMs` (default 24 hours), is
  `unknown`; an answer without `nextUpdate` is bounded and expires at
  `thisUpdate + ocspMaxAgeMs`.
- **CRL.** The CRL must be signed by, and issued by, the certificate's issuer
  (compared by full `Name`, not common name), and the issuer must assert
  `cRLSign` when its Key Usage is present. Delta CRLs (`deltaCRLIndicator`),
  scoped or indirect CRLs (`issuingDistributionPoint`), unsupported critical CRL
  extensions, and CRLs without a `nextUpdate` are rejected (`unknown`) rather than
  treated as "not revoked".
- **SHA-1.** Revocation signatures (OCSP and CRL) may use SHA-1 for compatibility
  with deployed responders and CAs, unlike certificate signatures, which are
  SHA-256/384/512 only. This is separate from the SHA-1 used to compute OCSP
  `CertID` identifier hashes.
- **Responder revocation.** A delegated responder's own revocation status is not
  checked; it is expected to be directly issued by the configured CA and
  short-lived. This is a stated limit, not an authorization bypass.

## Limits of this profile

This is a constrained validator, not a general RFC 5280 implementation. It does
not implement name constraints, certificate policies, policy mapping or
`inhibitAnyPolicy`; such certificates are rejected rather than mis-processed. If
broader PKI compatibility is required, select a maintained validation engine by
demonstrated behaviour against an acceptance corpus — and re-run the regression
fixtures in [`test/certificate-profile.test.ts`](../test/certificate-profile.test.ts),
which compare the supported cases against OpenSSL as well.
