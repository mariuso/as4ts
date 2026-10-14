import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * The receiver reuses `xml/`, `pki/`, `crypto/` and `profile`. Those must stay
 * direction-neutral, so they must never import from the sender-only modules
 * (`index.ts`, `send.ts`, `http/`, `multipart.ts`, `outcome.ts`); and the
 * receiving tree (`src/receive/`) must not reach into the sender either. This
 * test fails if one does, which keeps the sender from leaking into the shared
 * building blocks or the receiving entry point.
 */
const here = dirname(fileURLToPath(import.meta.url));
const src = join(here, '..', 'src');

const SHARED_DIRS = ['xml', 'pki', 'crypto'];
const SHARED_FILES = ['profile.ts'];

const SENDER_ONLY_FILES = new Set(['index.ts', 'send.ts', 'multipart.ts', 'outcome.ts']);
const SENDER_ONLY_DIRS = new Set(['http']);

interface SourceFile {
  readonly file: string;
  readonly text: string;
}

/** Recursively collect every `.ts` file under a directory. */
function walk(dir: string): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) files.push(...walk(full));
    else if (entry.isFile() && entry.name.endsWith('.ts')) files.push(full);
  }
  return files;
}

function sharedFiles(): string[] {
  const files: string[] = [];
  for (const dir of SHARED_DIRS) files.push(...walk(join(src, dir)));
  for (const file of SHARED_FILES) files.push(join(src, file));
  return files;
}

function load(files: readonly string[]): SourceFile[] {
  return files.map((file) => ({ file, text: readFileSync(file, 'utf8') }));
}

function importSpecifiers(text: string): string[] {
  const specifiers: string[] = [];
  const patterns = [
    /\bfrom\s+['"]([^'"]+)['"]/g,
    /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
    /\bimport\s+['"]([^'"]+)['"]/g,
  ];
  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern)) specifiers.push(match[1]!);
  }
  return specifiers;
}

/**
 * Normalise a resolved module path so a NodeNext `.js` import matches the `.ts`
 * source it refers to. Without this the guard silently misses every file import
 * (the previous bug: `SENDER_ONLY` held `.ts` names, `resolve` produced `.js`).
 */
function normalizeExtension(path: string): string {
  return path.replace(/\.(js|ts)$/, '.ts');
}

/**
 * The pure guard: given file/source pairs, return the imports that reach a
 * sender-only module. Kept separate from filesystem walking so it can be tested
 * directly with deliberate violations.
 */
function findSenderOnlyImports(files: readonly SourceFile[]): string[] {
  const violations: string[] = [];
  for (const { file, text } of files) {
    for (const specifier of importSpecifiers(text)) {
      if (!specifier.startsWith('.')) continue;
      const resolved = relative(src, resolve(dirname(file), specifier)).replace(/\\/g, '/');
      const [head, ...rest] = resolved.split('/');
      if (head !== undefined && SENDER_ONLY_DIRS.has(head) && rest.length > 0) {
        violations.push(`${relative(here, file)} -> ${specifier}`);
        continue;
      }
      if (SENDER_ONLY_FILES.has(normalizeExtension(resolved))) {
        violations.push(`${relative(here, file)} -> ${specifier}`);
      }
    }
  }
  return violations;
}

test('xml/, pki/, crypto/ and profile do not import sender-only modules', () => {
  const violations = findSenderOnlyImports(load(sharedFiles()));
  assert.deepEqual(violations, [], `shared modules must not import sender-only modules:\n${violations.join('\n')}`);
});

test('as4ts/lookup imports nothing from the sender-only modules', () => {
  const violations = findSenderOnlyImports(load(walk(join(src, 'lookup'))));
  assert.deepEqual(violations, [], `as4ts/lookup must not import sender-only modules:\n${violations.join('\n')}`);
});

test('as4ts/receive imports nothing from the sender-only modules', () => {
  const violations = findSenderOnlyImports(load(walk(join(src, 'receive'))));
  assert.deepEqual(violations, [], `as4ts/receive must not import sender-only modules:\n${violations.join('\n')}`);
});

test('the guard catches extension-normalized file and directory imports', () => {
  // A deliberate violation of exactly the shapes the guard must reject: a direct
  // sender-only file import (through its `.js` specifier) and a sender-only
  // directory import. Both must be reported.
  const fake = join(src, 'xml', 'fake.ts');
  const violations = findSenderOnlyImports([
    { file: fake, text: `import { sendAs4 } from '../index.js';` },
    { file: fake, text: `import { sendHttp } from '../http/send.js';` },
    { file: fake, text: `import { classify } from '../outcome.js';` },
  ]);
  assert.deepEqual(violations, [
    `${relative(here, fake)} -> ../index.js`,
    `${relative(here, fake)} -> ../http/send.js`,
    `${relative(here, fake)} -> ../outcome.js`,
  ]);
});

test('the guard allows shared and third-party imports', () => {
  const fake = join(src, 'xml', 'fake.ts');
  const violations = findSenderOnlyImports([
    { file: fake, text: `import { parseXml } from './nodes.js';` },
    { file: fake, text: `import { types } from '../types.js';` },
    { file: fake, text: `import { X509Certificate } from 'node:crypto';` },
  ]);
  assert.deepEqual(violations, []);
});

/**
 * The lenient `parseXml` silently repairs malformed input, ignores the declared
 * encoding and accepts a DOCTYPE, so remote XML must go through the strict
 * parser. This guard keeps it out of the receipt, signal and lookup paths.
 */
const NODES_MODULE = normalizeExtension(relative(src, join(src, 'xml', 'nodes.ts')).replace(/\\/g, '/'));

function findLenientXmlImports(files: readonly SourceFile[]): string[] {
  const violations: string[] = [];
  for (const { file, text } of files) {
    for (const match of text.matchAll(/\bimport\s+(?:type\s+)?\{([^}]*)\}\s*from\s*['"]([^'"]+)['"]/g)) {
      const names = match[1]!.split(',').map((entry) =>
        entry
          .trim()
          .split(/\s+as\s+/)[0]!
          .trim(),
      );
      if (!names.includes('parseXml')) continue;
      const specifier = match[2]!;
      if (!specifier.startsWith('.')) continue;
      const resolved = normalizeExtension(relative(src, resolve(dirname(file), specifier)).replace(/\\/g, '/'));
      if (resolved === NODES_MODULE) violations.push(`${relative(here, file)} -> ${specifier}`);
    }
  }
  return violations;
}

function remoteXmlFiles(): string[] {
  // `src/lookup` joins this list once its parser is strict (Phase 3).
  return [...walk(join(src, 'receipt')), join(src, 'xml', 'signal.ts')];
}

test('receipt and signal paths do not import the lenient parseXml', () => {
  const violations = findLenientXmlImports(load(remoteXmlFiles()));
  assert.deepEqual(violations, [], `remote XML must not use parseXml:\n${violations.join('\n')}`);
});

test('the lenient-XML guard catches a deliberate violation', () => {
  const fake = join(src, 'lookup', 'fake.ts');
  assert.deepEqual(findLenientXmlImports([{ file: fake, text: `import { parseXml } from '../xml/nodes.js';` }]), [
    `${relative(here, fake)} -> ../xml/nodes.js`,
  ]);
  assert.deepEqual(
    findLenientXmlImports([{ file: fake, text: `import { firstByLocalName } from '../xml/nodes.js';` }]),
    [],
  );
});
