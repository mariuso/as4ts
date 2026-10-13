// Sync src/version.ts to package.json so the User-Agent constants cannot drift
// from the released version. Wired as the npm `version` lifecycle script, so it
// runs automatically on `npm version` (including with --no-git-tag-version).
//
// It requires exactly one PACKAGE_VERSION declaration: a failed or partial match
// must not be mistaken for "already synchronized".
import { readFileSync, writeFileSync } from 'node:fs';

const pkgUrl = new URL('../package.json', import.meta.url);
const versionUrl = new URL('../src/version.ts', import.meta.url);

const { version } = JSON.parse(readFileSync(pkgUrl, 'utf8'));
const source = readFileSync(versionUrl, 'utf8');

const declaration = /export const PACKAGE_VERSION = '([^']*)';/g;
const matches = [...source.matchAll(declaration)];
if (matches.length !== 1) {
  console.error(
    `expected exactly one "export const PACKAGE_VERSION = '...';" declaration in src/version.ts, found ${matches.length}`,
  );
  process.exit(1);
}

const current = matches[0][1];
if (current === version) {
  console.log(`src/version.ts already reports ${version}`);
} else {
  writeFileSync(versionUrl, source.replace(declaration, `export const PACKAGE_VERSION = '${version}';`));
  console.log(`synced src/version.ts from ${current} to ${version}`);
}
