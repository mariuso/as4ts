import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * The receiver will reuse `xml/`, `pki/`, `crypto/` and `profile`. Those must
 * stay direction-neutral, so they must never import from the sender-only
 * modules (`index.ts`, `send.ts`, `http/`, `multipart.ts`, `outcome.ts`). This
 * test fails if one does, which keeps the sender from leaking into the shared
 * building blocks.
 */
const here = dirname(fileURLToPath(import.meta.url));
const src = join(here, '..', 'src');

const SHARED_DIRS = ['xml', 'pki', 'crypto'];
const SHARED_FILES = ['profile.ts'];

const SENDER_ONLY = new Set(['index.ts', 'send.ts', 'multipart.ts', 'outcome.ts']);
const SENDER_ONLY_DIRS = ['http'];

function sharedFiles(): string[] {
  const files: string[] = [];
  for (const dir of SHARED_DIRS) {
    for (const entry of readdirSync(join(src, dir), { withFileTypes: true })) {
      if (entry.isFile() && entry.name.endsWith('.ts')) files.push(join(src, dir, entry.name));
    }
  }
  for (const file of SHARED_FILES) files.push(join(src, file));
  return files;
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

test('xml/, pki/, crypto/ and profile do not import sender-only modules', () => {
  const violations: string[] = [];
  for (const file of sharedFiles()) {
    const text = readFileSync(file, 'utf8');
    for (const specifier of importSpecifiers(text)) {
      if (!specifier.startsWith('.')) continue;
      const resolved = relative(src, resolve(dirname(file), specifier)).replace(/\\/g, '/');
      const [head, ...rest] = resolved.split('/');
      if (head !== undefined && SENDER_ONLY_DIRS.includes(head) && rest.length > 0) {
        violations.push(`${relative(here, file)} -> ${specifier}`);
        continue;
      }
      if (SENDER_ONLY.has(resolved)) violations.push(`${relative(here, file)} -> ${specifier}`);
    }
  }
  assert.deepEqual(violations, [], `shared modules must not import sender-only modules:\n${violations.join('\n')}`);
});
