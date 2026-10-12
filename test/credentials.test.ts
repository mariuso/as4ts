import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { loadSigningMaterialFromP12 } from '../examples/lib/load-credentials.js';
import { createTestPki } from './helpers/pki.js';
import { createP12 } from './helpers/p12.js';

const pki = createTestPki();

test('loads key, leaf certificate and chain from a PKCS#12 container', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'as4-p12-'));
  try {
    const der = await createP12({
      keyPem: pki.sender.keyPem,
      certPem: pki.sender.certPem,
      chainPem: [pki.intermediate.certPem],
      passphrase: 'secret',
    });
    const path = join(dir, 'ap.p12');
    await writeFile(path, der);

    const material = await loadSigningMaterialFromP12(path, 'secret');
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
    const der = await createP12({
      keyPem: pki.sender.keyPem,
      certPem: pki.sender.certPem,
      passphrase: 'secret',
    });
    const path = join(dir, 'ap.p12');
    await writeFile(path, der);
    await assert.rejects(() => loadSigningMaterialFromP12(path, 'wrong'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
