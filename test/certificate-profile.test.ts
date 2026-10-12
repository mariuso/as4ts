import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildCertificatePath, type PathResult } from '../src/pki/chain.js';
import { validateCertificatePem } from '../src/pki/validate.js';
import { defaultRevocationPolicy } from '../src/certificate-validator.js';
import { derNull, derSequence } from '../src/pki/asn1.js';
import { createTestPki, createCustomCert, type TestCert } from './helpers/pki.js';

/**
 * Regression tests for the constrained certificate profile (see
 * docs/certificate-profile.md). They cover the defects the sending review found:
 * missing path-length enforcement and unknown-critical-extension processing, and
 * the false rejection caused by reading Node's Extended Key Usage accessor as if
 * it were Key Usage.
 */
const now = new Date();
const pki = createTestPki({ now });

function chain(leaf: TestCert, intermediates: readonly TestCert[], roots: readonly TestCert[]): PathResult {
  return buildCertificatePath(
    leaf.cert,
    intermediates.map((c) => c.certPem),
    roots.map((c) => c.certPem),
    now,
  );
}

test('accepts the standard leaf -> intermediate -> root chain', () => {
  assert.equal(chain(pki.receiver, [pki.intermediate], [pki.root]).ok, true);
});

test('rejects a certificate chain under a pathLenConstraint=0 intermediate', () => {
  const subCa = createCustomCert(now, pki.intermediate, { commonName: 'Subordinate CA', isCa: true, pathLen: 0 });
  const leaf = createCustomCert(now, subCa, { commonName: 'SUBLEAF', isCa: false });
  const result = chain(leaf, [pki.intermediate, subCa], [pki.root]);
  assert.equal(result.ok, false);
  if (!result.ok) assert.match(result.reason, /path length constraint/);
});

test('accepts a deeper chain when every pathLenConstraint allows it', () => {
  const root = createCustomCert(now, null, { commonName: 'Boundary Root', isCa: true, pathLen: 2 });
  const intermediate = createCustomCert(now, root, { commonName: 'Boundary CA', isCa: true, pathLen: 1 });
  const subCa = createCustomCert(now, intermediate, { commonName: 'Boundary Sub CA', isCa: true, pathLen: 0 });
  const leaf = createCustomCert(now, subCa, { commonName: 'BOUNDARYLEAF', isCa: false });
  assert.equal(chain(leaf, [intermediate, subCa], [root]).ok, true);
});

test('rejects a CA whose Key Usage lacks keyCertSign', () => {
  const badCa = createCustomCert(now, pki.root, {
    commonName: 'No Cert Sign CA',
    isCa: true,
    keyUsage: { bytes: [0x80], unusedBits: 7 },
  });
  const leaf = createCustomCert(now, badCa, { commonName: 'NOCSLEAF', isCa: false });
  const result = chain(leaf, [badCa], [pki.root]);
  assert.equal(result.ok, false);
  if (!result.ok) assert.match(result.reason, /keyCertSign/);
});

test('accepts a CA that also carries an extendedKeyUsage extension', () => {
  // Regression: Node's keyUsage accessor returns Extended Key Usage OIDs, so the
  // previous check falsely rejected any CA that asserted an EKU.
  const ekuCa = createCustomCert(now, pki.root, {
    commonName: 'EKU CA',
    isCa: true,
    extKeyUsage: ['1.3.6.1.5.5.7.3.2'],
  });
  const leaf = createCustomCert(now, ekuCa, { commonName: 'EKULEAF', isCa: false });
  assert.equal(chain(leaf, [ekuCa], [pki.root]).ok, true);
});

test('rejects an unknown critical extension', () => {
  const leaf = createCustomCert(now, pki.intermediate, {
    commonName: 'CRITLEAF',
    isCa: false,
    extra: [{ oid: '1.2.3.4.5.6', critical: true, der: derNull() }],
  });
  const result = chain(leaf, [pki.intermediate], [pki.root]);
  assert.equal(result.ok, false);
  if (!result.ok) assert.match(result.reason, /unsupported critical extension/);
});

test('rejects an unsupported path-affecting extension even when non-critical', () => {
  const leaf = createCustomCert(now, pki.intermediate, {
    commonName: 'NCLEAF',
    isCa: false,
    extra: [{ oid: '2.5.29.30', critical: false, der: derSequence() }],
  });
  const result = chain(leaf, [pki.intermediate], [pki.root]);
  assert.equal(result.ok, false);
  if (!result.ok) assert.match(result.reason, /unsupported path-affecting extension/);
});

test('rejects a malformed basicConstraints extension', () => {
  const leaf = createCustomCert(now, pki.intermediate, {
    commonName: 'MALLEAF',
    isCa: false,
    malformedBasicConstraints: true,
  });
  const result = chain(leaf, [pki.intermediate], [pki.root]);
  assert.equal(result.ok, false);
  if (!result.ok) assert.match(result.reason, /malformed/);
});

test('rejects duplicate extensions', () => {
  const leaf = createCustomCert(now, pki.intermediate, {
    commonName: 'DUPLEAF',
    isCa: false,
    // The helper already emits a Key Usage; add a second one.
    extra: [{ oid: '2.5.29.15', critical: true, der: Buffer.from([0x03, 0x02, 0x07, 0x80]) }],
  });
  const result = chain(leaf, [pki.intermediate], [pki.root]);
  assert.equal(result.ok, false);
  if (!result.ok) assert.match(result.reason, /duplicate extension/);
});

test('rejects a leaf that is itself a CA certificate', () => {
  const caLeaf = createCustomCert(now, pki.intermediate, { commonName: 'CALEAF', isCa: true });
  const result = chain(caLeaf, [pki.intermediate], [pki.root]);
  assert.equal(result.ok, false);
  if (!result.ok) assert.match(result.reason, /is a CA certificate/);
});

test('rejects a certificate signed with an unsupported algorithm', () => {
  const sha1Ca = createCustomCert(now, pki.root, {
    commonName: 'SHA1 CA',
    isCa: true,
    // sha1WithRSAEncryption: signature valid, but outside the constrained profile.
    signatureAlgorithm: { oid: '1.2.840.113549.1.1.5', hash: 'sha1' },
  });
  const leaf = createCustomCert(now, sha1Ca, { commonName: 'SHA1LEAF', isCa: false });
  const result = chain(leaf, [sha1Ca], [pki.root]);
  assert.equal(result.ok, false);
  if (!result.ok) assert.match(result.reason, /unsupported signature algorithm/);
});

test('applies the leaf Key Usage requirement for the requested purpose', () => {
  // keyEncipherment only.
  const encOnly = createCustomCert(now, pki.intermediate, {
    commonName: 'ENCONLY',
    isCa: false,
    keyUsage: { bytes: [0x20], unusedBits: 2 },
  });
  const asSigner = buildCertificatePath(encOnly.cert, [pki.intermediate.certPem], [pki.root.certPem], now, {
    purpose: 'receipt-signer',
  });
  assert.equal(asSigner.ok, false);
  if (!asSigner.ok) assert.match(asSigner.reason, /key usage/);

  const asEncryption = buildCertificatePath(encOnly.cert, [pki.intermediate.certPem], [pki.root.certPem], now, {
    purpose: 'receiver-encryption',
  });
  assert.equal(asEncryption.ok, true);
});

test('receiver-encryption requires keyEncipherment, not keyAgreement', () => {
  // RSA-OAEP is key transport; keyAgreement authorizes a different operation and
  // must not satisfy a receiver-encryption certificate.
  const keyAgreementOnly = createCustomCert(now, pki.intermediate, {
    commonName: 'AGREEONLY',
    isCa: false,
    keyUsage: { bytes: [0x08], unusedBits: 3 },
  });
  const keyEnciphermentOnly = createCustomCert(now, pki.intermediate, {
    commonName: 'ENCONLY2',
    isCa: false,
    keyUsage: { bytes: [0x20], unusedBits: 2 },
  });

  const rejected = buildCertificatePath(keyAgreementOnly.cert, [pki.intermediate.certPem], [pki.root.certPem], now, {
    purpose: 'receiver-encryption',
  });
  assert.equal(rejected.ok, false);
  if (!rejected.ok) assert.match(rejected.reason, /key usage/);

  const accepted = buildCertificatePath(keyEnciphermentOnly.cert, [pki.intermediate.certPem], [pki.root.certPem], now, {
    purpose: 'receiver-encryption',
  });
  assert.equal(accepted.ok, true);
});

test('validation without a purpose accepts only supported signing and key-transport usages', async () => {
  const cases = [
    { usage: 'digitalSignature', byte: 0x80, unusedBits: 7, accepted: true },
    { usage: 'nonRepudiation', byte: 0x40, unusedBits: 6, accepted: true },
    { usage: 'keyEncipherment', byte: 0x20, unusedBits: 5, accepted: true },
    { usage: 'keyAgreement', byte: 0x08, unusedBits: 3, accepted: false },
  ];

  for (const { usage, byte, unusedBits, accepted } of cases) {
    const leaf = createCustomCert(now, pki.intermediate, {
      commonName: `UNSCOPED-${usage}`,
      isCa: false,
      keyUsage: { bytes: [byte], unusedBits },
    });
    const result = await validateCertificatePem(leaf.certPem, {
      roots: [pki.root.certPem],
      intermediates: [pki.intermediate.certPem],
      revocation: defaultRevocationPolicy({ ocsp: false, crl: false, unreachable: 'soft' }),
      now,
    });
    assert.equal(result.ok, accepted, usage);
    if (!result.ok) {
      assert.equal(result.status, 'invalid');
      assert.match(result.reason, /key usage/);
    }
  }
});

test('selects the correct issuer when two intermediates share a subject (rollover)', () => {
  const root = createCustomCert(now, null, { commonName: 'Rollover Root', isCa: true, pathLen: 1 });
  const oldCa = createCustomCert(now, root, { commonName: 'Rollover AP CA', isCa: true, pathLen: 0 });
  const newCa = createCustomCert(now, root, { commonName: 'Rollover AP CA', isCa: true, pathLen: 0 });
  const leaf = createCustomCert(now, newCa, { commonName: 'ROLLLEAF', isCa: false });

  const withOldOnly = chain(leaf, [oldCa], [root]);
  assert.equal(withOldOnly.ok, false);
  if (!withOldOnly.ok) assert.match(withOldOnly.reason, /no trusted issuer/);

  assert.equal(chain(leaf, [oldCa, newCa], [root]).ok, true);
});

test('agrees with OpenSSL on a valid chain and a path-length violation', (t) => {
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' });
  } catch {
    t.skip('openssl is not available');
    return;
  }

  const dir = mkdtempSync(join(tmpdir(), 'as4ts-pki-'));
  const write = (name: string, pem: string) => writeFileSync(join(dir, name), pem);
  try {
    write('root.pem', pki.root.certPem);
    write('intermediate.pem', pki.intermediate.certPem);
    write('leaf.pem', pki.receiver.certPem);
    const good = execFileSync(
      'openssl',
      ['verify', '-CAfile', join(dir, 'root.pem'), '-untrusted', join(dir, 'intermediate.pem'), join(dir, 'leaf.pem')],
      { encoding: 'utf8' },
    );
    assert.match(good, /OK/);

    const subCa = createCustomCert(now, pki.intermediate, { commonName: 'OpenSSL Sub CA', isCa: true, pathLen: 0 });
    const subLeaf = createCustomCert(now, subCa, { commonName: 'OPENSSLLEAFLOW', isCa: false });
    write('subca.pem', subCa.certPem);
    write('subleaf.pem', subLeaf.certPem);

    let rejectedByOpenSsl = false;
    try {
      execFileSync(
        'openssl',
        [
          'verify',
          '-CAfile',
          join(dir, 'root.pem'),
          '-untrusted',
          join(dir, 'intermediate.pem'),
          '-untrusted',
          join(dir, 'subca.pem'),
          join(dir, 'subleaf.pem'),
        ],
        { stdio: 'ignore' },
      );
    } catch {
      rejectedByOpenSsl = true;
    }
    assert.equal(rejectedByOpenSsl, true, 'openssl must also reject the path-length violation');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
