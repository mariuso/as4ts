import { constants, createPrivateKey, privateDecrypt } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createCertificateValidator, defaultRevocationPolicy } from '../../src/certificate-validator.js';
import { PEPPOL_PARTY_ID_TYPE } from '../../src/constants.js';
import type { InboundKeyHolder } from '../../src/receive/types.js';
import type { ScopedId, ValidateCertificate } from '../../src/types.js';
import type { TestPki } from './pki.js';

/**
 * Helpers for the Item 5 measurement harness. The fixture generator persists a
 * test PKI to disk; the measured child process rebuilds the key holder, the
 * certificate validator and our receiver identity from those PEMs, so the child
 * never has to regenerate keys (which is slow and would pollute its memory
 * measurement).
 */
const FILES = {
  root: 'root.cert.pem',
  intermediate: 'intermediate.cert.pem',
  senderCert: 'sender.cert.pem',
  senderKey: 'sender.key.pem',
  receiverCert: 'receiver.cert.pem',
  receiverKey: 'receiver.key.pem',
  receiverCommonName: 'receiver.cn.txt',
} as const;

export function persistPki(pki: TestPki, dir: string): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, FILES.root), pki.root.certPem);
  writeFileSync(join(dir, FILES.intermediate), pki.intermediate.certPem);
  writeFileSync(join(dir, FILES.senderCert), pki.sender.certPem);
  writeFileSync(join(dir, FILES.senderKey), pki.sender.keyPem);
  writeFileSync(join(dir, FILES.receiverCert), pki.receiver.certPem);
  writeFileSync(join(dir, FILES.receiverKey), pki.receiver.keyPem);
  writeFileSync(join(dir, FILES.receiverCommonName), pki.receiver.commonName);
}

export function pkiExists(dir: string): boolean {
  try {
    readFileSync(join(dir, FILES.receiverKey));
    return true;
  } catch {
    return false;
  }
}

export function senderSignerFromPkiDir(dir: string): { certificate: string; keyPem: string } {
  return {
    certificate: readFileSync(join(dir, FILES.senderCert), 'utf8'),
    keyPem: readFileSync(join(dir, FILES.senderKey), 'utf8'),
  };
}

export function receiverCertificateFromPkiDir(dir: string): string {
  return readFileSync(join(dir, FILES.receiverCert), 'utf8');
}

export function validatorFromPkiDir(dir: string): ValidateCertificate {
  const validator = createCertificateValidator({
    roots: [readFileSync(join(dir, FILES.root), 'utf8')],
    intermediates: [readFileSync(join(dir, FILES.intermediate), 'utf8')],
    revocation: defaultRevocationPolicy({ ocsp: false, crl: false }),
  });
  return (input) => validator.validate(input);
}

export function holderFromPkiDir(dir: string): InboundKeyHolder {
  const certificate = readFileSync(join(dir, FILES.receiverCert), 'utf8');
  const key = createPrivateKey(readFileSync(join(dir, FILES.receiverKey), 'utf8'));
  return {
    certificate,
    async unwrap(wrapped) {
      return privateDecrypt(
        { key, oaepHash: 'sha256', padding: constants.RSA_PKCS1_OAEP_PADDING },
        Buffer.from(wrapped),
      );
    },
  };
}

export function receiverIdentityFromPkiDir(dir: string): ScopedId {
  return { scheme: PEPPOL_PARTY_ID_TYPE, value: readFileSync(join(dir, FILES.receiverCommonName), 'utf8').trim() };
}
