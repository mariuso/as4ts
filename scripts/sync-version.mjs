// Sync src/version.ts to package.json so the User-Agent constants cannot drift
// from the released version. Wired as the npm `version` lifecycle script, so it
// runs automatically on `npm version` (including with --no-git-tag-version).
import { readFileSync, writeFileSync } from 'node:fs';

const pkgUrl = new URL('../package.json', import.meta.url);
const versionUrl = new URL('../src/version.ts', import.meta.url);

const { version } = JSON.parse(readFileSync(pkgUrl, 'utf8'));
const source = readFileSync(versionUrl, 'utf8');
const updated = source.replace(/(export const PACKAGE_VERSION = ')[^']*(';)/, `$1${version}$2`);

if (updated === source) {
  console.log(`version.ts already reports ${version}`);
} else {
  writeFileSync(versionUrl, updated);
  console.log(`synced src/version.ts to ${version}`);
}
