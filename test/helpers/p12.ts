import { createPrivateKey, webcrypto } from 'node:crypto';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';

pkijs.setEngine('node-p12', new pkijs.CryptoEngine({ name: 'node-p12', crypto: webcrypto as unknown as Crypto }));

const CERT_BAG = '1.2.840.113549.1.9.22.1';
const CERT_SAFE_BAG = '1.2.840.113549.1.12.10.1.3';
const SHROUDED_KEY_BAG = '1.2.840.113549.1.12.10.1.2';
const DATA = '1.2.840.113549.1.7.1';

function passwordBuffer(password: string): ArrayBuffer {
  return new Uint8Array(Buffer.from(password, 'utf8')).buffer as ArrayBuffer;
}

function pemToDer(pem: string): Buffer {
  return Buffer.from(pem.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, ''), 'base64');
}

/** Build a PKCS#12 container (test-only), mirroring a typical AP export. */
export async function createP12(input: {
  readonly keyPem: string;
  readonly certPem: string;
  readonly chainPem?: readonly string[];
  readonly passphrase: string;
}): Promise<Buffer> {
  const keyDer = createPrivateKey(input.keyPem).export({ type: 'pkcs8', format: 'der' });
  const keyBag = new pkijs.PKCS8ShroudedKeyBag();
  keyBag.parsedValue = pkijs.PrivateKeyInfo.fromBER(keyDer);
  await keyBag.makeInternalValues({
    password: passwordBuffer(input.passphrase),
    contentEncryptionAlgorithm: { name: 'AES-CBC', length: 256 } as unknown as pkijs.ContentEncryptionAlgorithm,
    hmacHashAlgorithm: 'SHA-256',
    iterationCount: 2048,
  });

  const certBags = [input.certPem, ...(input.chainPem ?? [])].map((certPem) => {
    const certificate = pkijs.Certificate.fromBER(new Uint8Array(pemToDer(certPem)));
    const bag = new pkijs.CertBag({ certId: CERT_BAG });
    bag.parsedValue = certificate;
    return new pkijs.SafeBag({ bagId: CERT_SAFE_BAG, bagValue: bag });
  });

  const keySafeBag = new pkijs.SafeBag({ bagId: SHROUDED_KEY_BAG, bagValue: keyBag });
  const safeContents = new pkijs.SafeContents({ safeBags: [keySafeBag, ...certBags] });
  const contentInfo = new pkijs.ContentInfo({
    contentType: DATA,
    content: new asn1js.OctetString({ valueHex: safeContents.toSchema().toBER(false) }),
  });
  const authenticatedSafe = new pkijs.AuthenticatedSafe({ safeContents: [contentInfo] });

  const pfx = new pkijs.PFX({ version: 3 });
  pfx.parsedValue = { integrityMode: 0, authenticatedSafe };
  await pfx.makeInternalValues({
    password: passwordBuffer(input.passphrase),
    iterations: 2048,
    pbkdf2HashAlgorithm: 'SHA-256',
    hmacHashAlgorithm: 'SHA-256',
  });
  return Buffer.from(pfx.toSchema().toBER(false));
}
