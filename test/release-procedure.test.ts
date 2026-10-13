import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Exercises the documented release procedure in a throwaway Git repository, and
 * the `version` sync script's failure modes. The supported procedure is:
 *
 *   npm version <version> --no-git-tag-version   # runs the `version` script, which syncs src/version.ts
 *   git add package.json package-lock.json src/version.ts
 *   git commit -m "release: <version>"
 *   git tag -a v<version> -m "as4ts v<version>"
 *
 * The tag must carry matching versions in package.json, package-lock.json and
 * src/version.ts, and the procedure must leave no unintended changes.
 */
const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, '..');

function run(command: string, args: readonly string[], cwd: string): string {
  return execFileSync(command, args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}

function hasTool(command: string): boolean {
  try {
    execFileSync(command, ['--version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

const toolsAvailable = hasTool('git') && hasTool('npm');

function tempRepo(): string {
  const dir = mkdtempSync(join(tmpdir(), 'as4ts-release-'));
  mkdirSync(join(dir, 'src'), { recursive: true });
  mkdirSync(join(dir, 'scripts'), { recursive: true });
  cpSync(join(repo, 'package.json'), join(dir, 'package.json'));
  cpSync(join(repo, 'package-lock.json'), join(dir, 'package-lock.json'));
  cpSync(join(repo, 'src', 'version.ts'), join(dir, 'src', 'version.ts'));
  cpSync(join(repo, 'scripts', 'sync-version.mjs'), join(dir, 'scripts', 'sync-version.mjs'));
  return dir;
}

test('the release procedure leaves matching versions in the tagged commit', (t) => {
  if (!toolsAvailable) return t.skip('git or npm is not available');
  const dir = tempRepo();
  try {
    run('git', ['init', '-q'], dir);
    run('git', ['config', 'user.email', 'test@example.com'], dir);
    run('git', ['config', 'user.name', 'Release Test'], dir);
    run('git', ['add', '-A'], dir);
    run('git', ['commit', '-q', '-m', 'baseline'], dir);

    const version = '1.2.3-rc.1';

    // 1. Bump without git commit/tag; the `version` lifecycle script runs and
    //    rewrites src/version.ts from package.json.
    run('npm', ['version', version, '--no-git-tag-version'], dir);
    assert.match(
      readFileSync(join(dir, 'src', 'version.ts'), 'utf8'),
      new RegExp(`PACKAGE_VERSION = '${version}'`),
      'the version script synced src/version.ts',
    );

    // 2. Stage every version file, commit, and tag the tested commit.
    run('git', ['add', 'package.json', 'package-lock.json', 'src/version.ts'], dir);
    run('git', ['commit', '-q', '-m', `release: ${version}`], dir);
    run('git', ['tag', '-a', `v${version}`, '-m', `as4ts v${version}`], dir);

    // The tag points at the release commit.
    assert.equal(
      run('git', ['rev-parse', `v${version}^{}`], dir).trim(),
      run('git', ['rev-parse', 'HEAD'], dir).trim(),
    );

    // Every version file inside the tag matches.
    const at = (path: string): string => run('git', ['show', `v${version}:${path}`], dir);
    assert.equal((JSON.parse(at('package.json')) as { version: string }).version, version, 'package.json in the tag');
    assert.equal(
      (JSON.parse(at('package-lock.json')) as { version: string }).version,
      version,
      'package-lock.json in the tag',
    );
    assert.equal(
      (JSON.parse(at('package-lock.json')) as { packages: Record<string, { version?: string }> }).packages['']?.version,
      version,
      'package-lock.json root entry in the tag',
    );
    assert.match(at('src/version.ts'), new RegExp(`PACKAGE_VERSION = '${version}'`), 'src/version.ts in the tag');

    // The procedure leaves no unintended changes.
    assert.equal(run('git', ['status', '--porcelain'], dir).trim(), '', 'no unintended changes remain');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the version sync script fails when the declaration is missing or duplicated', (t) => {
  if (!toolsAvailable) return t.skip('git or npm is not available');
  const dir = tempRepo();
  const script = join(dir, 'scripts', 'sync-version.mjs');
  const versionFile = join(dir, 'src', 'version.ts');
  try {
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'as4ts', version: '1.2.3' }));

    // A missing declaration must fail, not masquerade as "already synchronized".
    writeFileSync(versionFile, "export const PACKAGE_NAME = 'as4ts';\n");
    assert.throws(() => run('node', [script], dir), 'missing declaration fails');

    // A duplicated declaration must fail too.
    writeFileSync(versionFile, "export const PACKAGE_VERSION = 'a';\nexport const PACKAGE_VERSION = 'b';\n");
    assert.throws(() => run('node', [script], dir), 'duplicated declaration fails');

    // A stale but unique declaration is rewritten.
    writeFileSync(versionFile, "export const PACKAGE_VERSION = '0.0.0';\n");
    run('node', [script], dir);
    assert.match(readFileSync(versionFile, 'utf8'), /export const PACKAGE_VERSION = '1\.2\.3';/);

    // A current declaration is idempotent.
    const output = run('node', [script], dir);
    assert.match(output, /already reports 1\.2\.3/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
