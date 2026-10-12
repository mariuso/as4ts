import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createPublicKey } from 'node:crypto';
import { loadSigningMaterialFromP12, loadSigningMaterialFromPem } from '../examples/lib/load-credentials.js';
import { normalizePem } from '../src/util.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, 'fixtures', 'p12');
const fixture = (name: string): string => join(fixtures, name);
const pem = (name: string): string => normalizePem(readFileSync(fixture(name), 'utf8'));

/** DER-encoded public key of a private key or a certificate. */
const publicKeyDer = (key: Parameters<typeof createPublicKey>[0]): Buffer =>
  createPublicKey(key).export({ type: 'spki', format: 'der' });

test('loads a modern OpenSSL PKCS#12, picking the leaf that matches the key', async () => {
  const material = await loadSigningMaterialFromP12(fixture('modern.p12'), 'secret');
  assert.equal(material.source, 'p12');
  assert.equal(material.signingKey.asymmetricKeyType, 'rsa');
  assert.equal(publicKeyDer(material.signingKey).equals(publicKeyDer(pem('leaf-cert.pem'))), true);
  assert.equal(material.signingCertificate, pem('leaf-cert.pem'));
  assert.deepEqual(material.chainPem.map(normalizePem), [pem('ca-cert.pem')]);
});

test('picks the leaf by public key even when the CA is listed first', async () => {
  const material = await loadSigningMaterialFromP12(fixture('ca-first.p12'), 'secret');
  assert.equal(material.signingCertificate, pem('leaf-cert.pem'));
  assert.deepEqual(material.chainPem.map(normalizePem), [pem('ca-cert.pem')]);
});

test('rejects a legacy (pre-PBES2) container with a re-export hint', async () => {
  await assert.rejects(
    () => loadSigningMaterialFromP12(fixture('legacy.p12'), 'secret'),
    /legacy algorithm[\s\S]*--sender-cert and --sender-key/,
  );
});

test('rejects a PKCS#12 with the wrong passphrase', async () => {
  await assert.rejects(() => loadSigningMaterialFromP12(fixture('modern.p12'), 'wrong'));
});

test('a PEM key and certificate round-trip through the PEM loader', () => {
  const material = loadSigningMaterialFromPem(fixture('leaf-cert.pem'), fixture('leaf-key.pem'));
  assert.equal(material.source, 'pem');
  assert.equal(material.signingKey.asymmetricKeyType, 'rsa');
  assert.equal(normalizePem(material.signingCertificate), pem('leaf-cert.pem'));
});
