# Security policy

This is signature-verification and message-encryption code for Peppol AS4. Please
report suspected vulnerabilities privately.

## Reporting a vulnerability

Use **GitHub's private vulnerability reporting** — the repository's **Security**
tab → **Report a vulnerability**. That channel stays private. If you cannot use
it, open a minimal issue asking a maintainer to contact you privately, without
including any details of the issue.

Please include:

- the affected version or commit,
- a description and, where possible, a proof of concept,
- whether the issue is already public.

**Response time:** we aim to acknowledge within **3 business days** and to give
an initial assessment within **10 business days**. Please do **not** open a public
issue for a suspected vulnerability.

## Supported versions

Until the first tagged release, only the latest `main` is supported.

## Dependency security

Runtime dependencies are `@xmldom/xmldom` and `xml-crypto` (only its low-level
`ExclusiveCanonicalization`, never `SignedXml`). `npm audit --omit=dev` is clean
and runs in CI.

`npm audit` including dev dependencies is also clean. The test PKI/CRL/OCSP
fixtures and the example's PKCS#12 parsing use `pkijs`/`asn1js`, which carry no
known advisories.

## Scope

In scope:

- Receipt signature verification (`src/receipt/verify.ts`) and the shared,
  direction-neutral WS-Security signature verification (`src/xml/ws-security.ts`).
- Envelope signing and encryption, and exclusive C14N (`src/xml/*`).
- Certificate path building and revocation (`src/pki/*`).
- The streaming payload pipeline (`src/crypto/*`).
- SML/SMP participant lookup and SMP signature verification (`src/lookup/*`).

Out of scope:

- The caller's trust policy, signer and certificate validator (injected by the
  caller; the security of those is the caller's responsibility).
- The example scripts under `examples/` (not part of the package).
- The Peppol Testbed and OpenPeppol PKI themselves.

## Design properties we rely on

- Trust is injected and mandatory; there is no code path that sends without
  calling the caller's validator.
- The produced signature is verified against the signer certificate before it is
  put on the wire.
- TLS 1.2 is the floor and certificate verification cannot be disabled.
- Temporary files are mode `0600` and are always removed.
- No key material, payload bytes or private certificate parts leave the process
  through the observation hook.

## Not a certification

Interoperation has been demonstrated on the Peppol test network, but this
software is **not certified**. Each user must pass the Peppol Testbed with their
own certificate.
