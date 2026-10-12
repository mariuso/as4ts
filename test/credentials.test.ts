import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import forge from 'node-forge';
import { loadSigningMaterialFromP12 } from '../examples/lib/load-credentials.js';
import { createTestPki } from './helpers/pki.js';

const pki = createTestPki();

test('loads key, leaf certificate and chain from a PKCS#12 container', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'as4-p12-'));
  try {
    const key = forge.pki.privateKeyFromPem(pki.sender.keyPem);
    const leaf = forge.pki.certificateFromPem(pki.sender.certPem);
    const ca = forge.pki.certificateFromPem(pki.intermediate.certPem);
    const asn1 = forge.pkcs12.toPkcs12Asn1(key, [leaf, ca], 'secret', { algorithm: '3des' });
    const der = Buffer.from(forge.asn1.toDer(asn1).getBytes(), 'binary');
    const path = join(dir, 'ap.p12');
    await writeFile(path, der);

    const material = loadSigningMaterialFromP12(path, 'secret');
    assert.equal(material.source, 'p12');
    assert.equal(material.signingKey.asymmetricKeyType, 'rsa');
    assert.match(material.signingCertificate, /BEGIN CERTIFICATE/);
    assert.equal(material.chainPem.length, 1);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('rejects a PKCS#12 with the wrong passphrase', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'as4-p12-'));
  try {
    const key = forge.pki.privateKeyFromPem(pki.sender.keyPem);
    const leaf = forge.pki.certificateFromPem(pki.sender.certPem);
    const asn1 = forge.pkcs12.toPkcs12Asn1(key, [leaf], 'secret', { algorithm: '3des' });
    const path = join(dir, 'ap.p12');
    await writeFile(path, Buffer.from(forge.asn1.toDer(asn1).getBytes(), 'binary'));
    assert.throws(() => loadSigningMaterialFromP12(path, 'wrong'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
