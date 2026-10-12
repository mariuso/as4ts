import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PACKAGE_NAME, PACKAGE_VERSION } from '../src/version.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as {
  name: string;
  version: string;
  dependencies: Record<string, string>;
  exports: Record<string, unknown>;
  repository?: { url?: string };
  bugs?: { url?: string };
  homepage?: string;
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

test('there are exactly four entry points', () => {
  assert.deepEqual(Object.keys(pkg.exports).sort(), ['.', './certificate-validator', './classifier', './lookup']);
});

test('the lookup entry point exports a stable surface', async () => {
  const module = await import('../src/lookup/index.js');
  assert.deepEqual(Object.keys(module).sort(), [
    'PEPPOL_TRANSPORT_PROFILE',
    'documentTypeMatches',
    'lookupParticipant',
    'participantDnsName',
    'participantHash',
    'participantSegment',
  ]);
});

test('package identity matches the User-Agent constants', () => {
  assert.equal(PACKAGE_NAME, pkg.name);
  assert.equal(PACKAGE_VERSION, pkg.version);
});

test('package metadata points at the GitHub repository', () => {
  assert.match(pkg.repository?.url ?? '', /github\.com\/mariuso\/as4ts/);
  assert.match(pkg.bugs?.url ?? '', /github\.com\/mariuso\/as4ts\/issues/);
  assert.match(pkg.homepage ?? '', /github\.com\/mariuso\/as4ts/);
});

test('runtime dependencies stay at two caret ranges whose floor is the pinned version', () => {
  const deps = pkg.dependencies;
  assert.deepEqual(Object.keys(deps).sort(), ['@xmldom/xmldom', 'xml-crypto']);
  assert.equal(deps['@xmldom/xmldom'], '^0.8.15');
  assert.equal(deps['xml-crypto'], '^6.3.3');
});

/**
 * The receiving side is planned but not implemented. No entry point may already
 * export a `receive*` value or type, so a future `receiveAs4` can add one
 * without a breaking rename. This guards the reservation (see docs/receiving.md).
 */
test('no entry point exports a receive* value', async () => {
  const modules = await Promise.all([
    import('../src/index.js'),
    import('../src/certificate-validator.js'),
    import('../src/classifier.js'),
    import('../src/lookup/index.js'),
  ]);
  for (const module of modules) {
    const offenders = Object.keys(module).filter((name) => /^receive/i.test(name));
    assert.deepEqual(offenders, [], `unexpected receive* runtime export: ${offenders.join(', ')}`);
  }
});

test('no source export is named receive* (values or types)', () => {
  const src = join(root, 'src');
  const files: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith('.ts')) files.push(full);
    }
  };
  walk(src);
  const declared: string[] = [];
  for (const file of files) {
    const text = readFileSync(file, 'utf8');
    // export function receiveX / export class receiveX / export type receiveX
    // export interface receiveX / export const receiveX / export { receiveX }
    const patterns = [
      /\bexport\s+(?:async\s+)?function\s+(receive\w*)/g,
      /\bexport\s+class\s+(receive\w*)/gi,
      /\bexport\s+interface\s+(receive\w*)/gi,
      /\bexport\s+type\s+(receive\w*)/g,
      /\bexport\s+const\s+(receive\w*)/g,
    ];
    for (const pattern of patterns) {
      for (const match of text.matchAll(pattern)) declared.push(`${file}:${match[1]}`);
    }
  }
  assert.deepEqual(declared, [], `receive* names must be reserved for the future: ${declared.join(', ')}`);
});
