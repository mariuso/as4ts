import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PACKAGE_NAME, PACKAGE_VERSION } from '../src/version.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as {
  name: string;
  version: string;
  dependencies: Record<string, string>;
  exports: Record<string, unknown>;
};

test('the sender entry point exports a stable surface', async () => {
  const module = await import('../src/index.js');
  assert.deepEqual(Object.keys(module).sort(), ['peppolProfile', 'sendAs4', 'signerFromKey']);
});

test('the certificate-validator entry point exports a stable surface', async () => {
  const module = await import('../src/certificate-validator.js');
  assert.deepEqual(Object.keys(module).sort(), [
    'RevocationCache',
    'createCertificateValidator',
    'defaultRevocationPolicy',
  ]);
});

test('the classifier entry point exports a stable surface', async () => {
  const module = await import('../src/classifier.js');
  assert.deepEqual(Object.keys(module).sort(), [
    'DEFAULT_CLASSIFY_TABLE',
    'EBMS_ERROR_TABLE',
    'classify',
    'classifyEbmsError',
  ]);
});

test('there are exactly three entry points', () => {
  assert.deepEqual(Object.keys(pkg.exports).sort(), ['.', './certificate-validator', './classifier']);
});

test('package identity matches the User-Agent constants', () => {
  assert.equal(PACKAGE_NAME, pkg.name);
  assert.equal(PACKAGE_VERSION, pkg.version);
});

test('runtime dependencies stay at two caret ranges whose floor is the pinned version', () => {
  const deps = pkg.dependencies;
  assert.deepEqual(Object.keys(deps).sort(), ['@xmldom/xmldom', 'xml-crypto']);
  assert.equal(deps['@xmldom/xmldom'], '^0.8.15');
  assert.equal(deps['xml-crypto'], '^6.3.3');
});
