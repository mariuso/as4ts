import { createPrivateKey } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import { readFileSync } from 'node:fs';
import forge from 'node-forge';

export interface SigningMaterial {
  readonly signingKey: KeyObject;
  readonly signingCertificate: string;
  /** Any CA certificates found in the container, for building the trust path. */
  readonly chainPem: readonly string[];
  readonly source: 'pem' | 'p12';
}

/**
 * Load the sender's signing key and certificate from either a PKCS#12 container
 * or separate PEM files. This lives at the script boundary: the library itself
 * deliberately receives a Node KeyObject and a certificate PEM and never touches
 * files or passphrases.
 *
 * Node's `crypto` cannot extract a private key from PKCS#12, so we parse the
 * container with node-forge (a dev dependency, already used for the test PKI).
 * The key is only held in memory and never logged.
 */
export function loadSigningMaterialFromP12(path: string, passphrase: string): SigningMaterial {
  const der = readFileSync(path, 'binary');
  const asn1 = forge.asn1.fromDer(der);
  const p12 = forge.pkcs12.pkcs12FromAsn1(asn1, passphrase);

  const keyBagType = forge.pki.oids.pkcs8ShroudedKeyBag as string;
  const keyBags = (p12.getBags({ bagType: keyBagType })[keyBagType] ?? []) as forge.pkcs12.Bag[];
  const key = (keyBags[0] as forge.pkcs12.Bag | undefined)?.key;
  if (!key) throw new Error('no private key found in the PKCS#12 container');

  const certBagType = forge.pki.oids.certBag as string;
  const certBags = (p12.getBags({ bagType: certBagType })[certBagType] ?? []) as forge.pkcs12.Bag[];
  const certs = certBags
    .map((bag) => (bag.cert ? forge.pki.certificateToPem(bag.cert) : null))
    .filter((pem): pem is string => Boolean(pem));
  if (certs.length === 0) throw new Error('no certificate found in the PKCS#12 container');

  const leaf = pickLeafCertificate(certs);
  return {
    signingKey: createPrivateKey(forge.pki.privateKeyToPem(key)),
    signingCertificate: leaf,
    chainPem: certs.filter((pem) => pem !== leaf),
    source: 'p12',
  };
}

export function loadSigningMaterialFromPem(certPath: string, keyPath: string): SigningMaterial {
  const signingCertificate = readFileSync(certPath, 'utf8');
  const signingKey = createPrivateKey(readFileSync(keyPath, 'utf8'));
  return { signingKey, signingCertificate, chainPem: [], source: 'pem' };
}

function pickLeafCertificate(certs: readonly string[]): string {
  for (const pem of certs) {
    try {
      const cert = forge.pki.certificateFromPem(pem);
      const basic = cert.getExtension('basicConstraints') as { cA?: boolean } | undefined;
      if (!basic?.cA) return pem;
    } catch {
      // ignore unreadable
    }
  }
  return certs[0]!;
}
