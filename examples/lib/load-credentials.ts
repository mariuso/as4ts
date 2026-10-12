import { createPrivateKey, webcrypto } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import { readFileSync } from 'node:fs';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';

export interface SigningMaterial {
  readonly signingKey: KeyObject;
  readonly signingCertificate: string;
  /** Any CA certificates found in the container, for building the trust path. */
  readonly chainPem: readonly string[];
  readonly source: 'pem' | 'p12';
}

// PKCS#12 bag OIDs.
const CERT_BAG = '1.2.840.113549.1.12.10.1.3';
const SHROUDED_KEY_BAG = '1.2.840.113549.1.12.10.1.2';
const KEY_BAG = '1.2.840.113549.1.12.10.1.1';

let engineReady = false;
function ensureEngine(): void {
  if (engineReady) return;
  pkijs.setEngine('node', new pkijs.CryptoEngine({ name: 'node', crypto: webcrypto as unknown as Crypto }));
  engineReady = true;
}

function pem(der: Buffer, label: string): string {
  return `-----BEGIN ${label}-----\n${der
    .toString('base64')
    .replace(/(.{64})/g, '$1\n')
    .trim()}\n-----END ${label}-----`;
}

/**
 * Load the sender's signing key and certificate from a PKCS#12 container. This
 * lives at the example boundary: the library itself receives a Node KeyObject
 * and a certificate PEM and never touches files or passphrases.
 *
 * Node's `crypto` cannot extract a private key from PKCS#12, so the container is
 * parsed with pkijs (a dev dependency). The key is only held in memory.
 */
export async function loadSigningMaterialFromP12(path: string, passphrase: string): Promise<SigningMaterial> {
  ensureEngine();
  const password = new Uint8Array(Buffer.from(passphrase, 'utf8')).buffer as ArrayBuffer;
  const der = readFileSync(path);
  const pfx = pkijs.PFX.fromBER(new Uint8Array(der));
  await pfx.parseInternalValues({ password, checkIntegrity: true });

  const authenticatedSafe = pfx.parsedValue?.authenticatedSafe;
  if (!authenticatedSafe) throw new Error('no authenticated safe found in the PKCS#12 container');

  let keyDer: Buffer | null = null;
  const certs: string[] = [];
  for (const contentInfo of authenticatedSafe.safeContents) {
    const safeContents = await decryptSafeContents(contentInfo, password);
    if (!safeContents) continue;
    for (const bag of safeContents.safeBags) {
      if (bag.bagId === CERT_BAG) {
        const certificate = (bag.bagValue as pkijs.CertBag).parsedValue as pkijs.Certificate;
        certs.push(pem(Buffer.from(certificate.toSchema(true).toBER(false)), 'CERTIFICATE'));
      } else if (bag.bagId === SHROUDED_KEY_BAG) {
        const keyBag = bag.bagValue as pkijs.PKCS8ShroudedKeyBag;
        await decryptKeyBag(keyBag, password);
        const info = keyBag.parsedValue;
        if (info) keyDer = Buffer.from(info.toSchema().toBER(false));
      } else if (bag.bagId === KEY_BAG) {
        const info = bag.bagValue as pkijs.PrivateKeyInfo;
        keyDer = Buffer.from(info.toSchema().toBER(false));
      }
    }
  }

  if (!keyDer) throw new Error('no private key found in the PKCS#12 container');
  if (certs.length === 0) throw new Error('no certificate found in the PKCS#12 container');

  const leaf = pickLeafCertificate(certs);
  return {
    signingKey: createPrivateKey({ key: keyDer, format: 'der', type: 'pkcs8' }),
    signingCertificate: leaf,
    chainPem: certs.filter((pemString) => pemString !== leaf),
    source: 'p12',
  };
}

async function decryptKeyBag(bag: pkijs.PKCS8ShroudedKeyBag, password: ArrayBuffer): Promise<void> {
  // parseInternalValues is protected in pkijs, but is the only way to unwrap the
  // password-encrypted key; the PFX parser does not do it for shrouded key bags.
  const shroud = bag as unknown as { parseInternalValues(p: { password: ArrayBuffer }): Promise<void> };
  await shroud.parseInternalValues({ password });
}

async function decryptSafeContents(
  contentInfo: pkijs.ContentInfo,
  password: ArrayBuffer,
): Promise<pkijs.SafeContents | null> {
  if (contentInfo.contentType === '1.2.840.113549.1.7.1') {
    const octets = contentInfo.content as asn1js.OctetString;
    return pkijs.SafeContents.fromBER(octets.getValue());
  }
  if (contentInfo.contentType === '1.2.840.113549.1.7.6') {
    const encrypted = new pkijs.EncryptedData({ schema: contentInfo.content });
    const decrypted = await encrypted.decrypt({ password });
    return pkijs.SafeContents.fromBER(decrypted);
  }
  return null;
}

export function loadSigningMaterialFromPem(certPath: string, keyPath: string): SigningMaterial {
  const signingCertificate = readFileSync(certPath, 'utf8');
  const signingKey = createPrivateKey(readFileSync(keyPath, 'utf8'));
  return { signingKey, signingCertificate, chainPem: [], source: 'pem' };
}

function pickLeafCertificate(certs: readonly string[]): string {
  for (const certPem of certs) {
    try {
      const basic = pkijs.Certificate.fromBER(Buffer.from(pemToDer(certPem))).extensions?.find(
        (e) => e.extnID === '2.5.29.19',
      );
      if (!basic) return certPem;
    } catch {
      // ignore unreadable
    }
  }
  return certs[0]!;
}

function pemToDer(certPem: string): Uint8Array {
  return new Uint8Array(Buffer.from(certPem.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, ''), 'base64'));
}
