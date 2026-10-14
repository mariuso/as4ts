/**
 * Item 5 measurement driver.
 *
 * Generates each fixture in its own process (under tsx), bundles the measured
 * child with esbuild, then runs it in a fresh process **under plain `node`** —
 * the contract is about the shipped code, and the tsx loader added ~110 MiB of
 * peak memory in a probe. Each positive configuration runs twice: without, and
 * with, a (never-aborting) `AbortSignal`, because production callers pass one.
 *
 *   npm run measure:receive
 *
 * Env: AS4_MEASURE_SIZES (default 64,256,512), AS4_MEASURE_KINDS (default
 * xml,base64), AS4_MEASURE_CONCURRENCY (default 4), AS4_MEASURE_DIR,
 * AS4_MEASURE_KEEP=1 to retain fixtures, AS4_MEASURE_TIMEOUT_MS.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const MIB = 1024 * 1024;
const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..');
const measurementsDir = join(repoRoot, 'measurements');
const childBundle = join(measurementsDir, 'receive-child.mjs');

const SIZES = (process.env['AS4_MEASURE_SIZES'] ?? '64,256,512').split(',').map(Number);
const KINDS = (process.env['AS4_MEASURE_KINDS'] ?? 'xml,base64').split(',').map((value) => value.trim());
const CONCURRENCY = Number(process.env['AS4_MEASURE_CONCURRENCY'] ?? '4');
const ROOT = process.env['AS4_MEASURE_DIR'] ?? mkdtempSync(join(tmpdir(), 'as4-measure-'));
const KEEP = process.env['AS4_MEASURE_KEEP'] === '1';
const TIMEOUT_MS = Number(process.env['AS4_MEASURE_TIMEOUT_MS'] ?? '1800000');
const LARGEST = Math.max(...SIZES);
const SIGNAL_VARIANTS = [false, true] as const;

/** Provisional host budget. A run above this is reported as a finding, never raised silently. */
const CEILING_MIB = 384;
/** Provisional flatness tolerance between the smallest and largest size, per kind × signal. */
const FLATNESS_MIB = 64;

interface ChildResult {
  readonly fixture: string;
  readonly kind: string;
  readonly sizeMiB: number;
  readonly concurrency: number;
  readonly profile: string;
  readonly signal: boolean;
  readonly recoveredBytes: number;
  readonly wireBytes: number;
  readonly outcomes: ReadonlyArray<{
    readonly ok: boolean;
    readonly stage?: string;
    readonly reason?: string;
    readonly sbdh?: string;
    readonly payloadBytes?: number;
    readonly digestOk?: boolean;
  }>;
  readonly maxRSS: number;
  readonly sampledPeakRss: number;
  readonly sampledPeakHeapUsed: number;
  readonly sampledPeakExternal: number;
  readonly sampledPeakArrayBuffers: number;
  readonly peakSpoolBytes: number;
  readonly spoolEmptyAfterDispose: boolean;
  readonly strayTempEntries: readonly string[];
  readonly wallMs: number;
  readonly node: string;
  readonly platform: string;
  readonly arch: string;
}

const findings: string[] = [];
function finding(message: string): void {
  findings.push(message);
  console.error(`FINDING: ${message}`);
}

function run(
  command: string,
  args: readonly string[],
  env: NodeJS.ProcessEnv,
): { code: number | null; stdout: string; stderr: string } {
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    env: { ...process.env, ...env },
    encoding: 'utf8',
    maxBuffer: 64 * MIB,
    timeout: TIMEOUT_MS,
  });
  return { code: result.status, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
}

/** Bundle the measured child so it runs without the tsx loader. */
async function bundleChild(): Promise<void> {
  mkdirSync(measurementsDir, { recursive: true });
  await build({
    entryPoints: [join(here, 'measure/receive-child.ts')],
    outfile: childBundle,
    bundle: true,
    platform: 'node',
    format: 'esm',
    packages: 'external',
    target: 'node22',
    logLevel: 'warning',
  });
}

function buildFixture(kind: string, sizeMiB: number): void {
  const { code, stdout, stderr } = run(
    process.execPath,
    ['--import', 'tsx', join(here, 'measure/generate-fixtures.ts')],
    {
      AS4_MEASURE_DIR: ROOT,
      AS4_GENERATE_KINDS: kind,
      AS4_GENERATE_SIZES: String(sizeMiB),
    },
  );
  if (stdout.trim()) console.log(stdout.trim());
  if (code !== 0) throw new Error(`fixture generation failed for ${kind}-${sizeMiB}:\n${stderr}`);
}

function runChild(kind: string, sizeMiB: number, profile: 'override' | 'default', signal: boolean): ChildResult {
  const variant = signal ? 'signal' : 'plain';
  const spoolDir = join(ROOT, 'spool', `${kind}-${sizeMiB}-${profile}-${variant}`);
  rmSync(spoolDir, { recursive: true, force: true });
  mkdirSync(spoolDir, { recursive: true });
  const { code, stdout, stderr } = run(process.execPath, [childBundle], {
    AS4_CHILD_FIXTURE: join(ROOT, `${kind}-${sizeMiB}`),
    AS4_CHILD_PKI: join(ROOT, 'pki'),
    AS4_CHILD_SPOOL: spoolDir,
    AS4_CHILD_CONCURRENCY: String(CONCURRENCY),
    AS4_CHILD_PROFILE: profile,
    AS4_CHILD_SIGNAL: signal ? '1' : '0',
  });
  if (stderr.trim()) console.error(stderr.trim());
  const line = stdout.split('\n').find((entry) => entry.startsWith('MEASURE_RESULT '));
  if (code !== 0 || !line)
    throw new Error(`measured child failed for ${kind}-${sizeMiB} (${profile}, ${variant}), code ${code}`);
  return JSON.parse(line.slice('MEASURE_RESULT '.length)) as ChildResult;
}

/** Confirm the byte unit of `maxRSS` on this platform once, with a known allocation. */
function maxRssUnitCheck(): { before: number; after: number; deltaMiB: number; ok: boolean } {
  const script = [
    'const before = process.resourceUsage().maxRSS;',
    `const buffer = Buffer.alloc(256 * 1024 * 1024, 7);`,
    'let sum = 0; for (let i = 0; i < buffer.length; i += 4096) sum += buffer[i];',
    'const after = process.resourceUsage().maxRSS;',
    'process.stdout.write(JSON.stringify({ before, after, sum }));',
  ].join('\n');
  const result = spawnSync(process.execPath, ['-e', script], { encoding: 'utf8', maxBuffer: 8 * MIB });
  if (result.status !== 0 || !result.stdout) throw new Error(`maxRSS unit check failed: ${result.stderr}`);
  const parsed = JSON.parse(result.stdout) as { before: number; after: number };
  const deltaKiB = parsed.after - parsed.before;
  const ok = deltaKiB >= 200_000 && deltaKiB <= 330_000;
  return { before: parsed.before, after: parsed.after, deltaMiB: deltaKiB / 1024, ok };
}

function limitReason(reason: string | undefined): boolean {
  return reason !== undefined && /too-large|part-too-large|too-many/.test(reason);
}

async function main(): Promise<void> {
  console.log(`measure:receive  node ${process.version}  ${process.platform}/${process.arch}`);
  console.log(`fixtures: ${KINDS.join(',')} × ${SIZES.join(',')} MiB  concurrency ${CONCURRENCY}  dir ${ROOT}`);
  await bundleChild();
  console.log(`bundled measured child → ${childBundle}`);

  const unit = maxRssUnitCheck();
  console.log(
    `maxRSS unit check: +${unit.deltaMiB.toFixed(0)} MiB for a 256 MiB Buffer (${unit.ok ? 'ok' : 'UNEXPECTED'})`,
  );
  if (!unit.ok) finding(`maxRSS unit check unexpected: delta ${unit.deltaMiB.toFixed(0)} MiB`);

  const positives: ChildResult[] = [];
  const negatives: ChildResult[] = [];

  for (const kind of KINDS) {
    for (const sizeMiB of SIZES) {
      const fixtureDir = join(ROOT, `${kind}-${sizeMiB}`);
      if (!existsSync(join(fixtureDir, 'body.bin'))) buildFixture(kind, sizeMiB);

      for (const signal of SIGNAL_VARIANTS) {
        const positive = runChild(kind, sizeMiB, 'override', signal);
        positives.push(positive);
        const tag = `${kind}-${sizeMiB}${signal ? '+signal' : ''}`;
        console.log(
          `positive ${tag}: maxRSS ${(positive.maxRSS / 1024).toFixed(0)} MiB, ` +
            `spool peak ${(positive.peakSpoolBytes / MIB).toFixed(0)} MiB, ${(positive.wallMs / 1000).toFixed(1)}s`,
        );
        for (const outcome of positive.outcomes) {
          if (!outcome.ok) finding(`${tag}: positive open failed ${outcome.stage}/${outcome.reason}`);
          else {
            if (outcome.sbdh !== 'consistent') finding(`${tag}: sbdh ${outcome.sbdh}`);
            if (outcome.digestOk !== true) finding(`${tag}: payload digest/bytes mismatch`);
          }
        }
        if (positive.outcomes.length !== CONCURRENCY) finding(`${tag}: expected ${CONCURRENCY} outcomes`);
        if (!positive.spoolEmptyAfterDispose) finding(`${tag}: spool not empty after dispose`);
        if (positive.strayTempEntries.length > 0)
          finding(`${tag}: stray temp entries ${positive.strayTempEntries.join(', ')}`);
        if (positive.maxRSS / 1024 > CEILING_MIB)
          finding(`${tag}: maxRSS ${(positive.maxRSS / 1024).toFixed(0)} MiB exceeds ceiling ${CEILING_MIB} MiB`);
      }

      if (sizeMiB === LARGEST) {
        for (const signal of SIGNAL_VARIANTS) {
          const negative = runChild(kind, sizeMiB, 'default', signal);
          negatives.push(negative);
          const tag = `${kind}-${sizeMiB}${signal ? '+signal' : ''}`;
          const first = negative.outcomes[0];
          console.log(
            `negative ${tag}: ${first?.stage}/${first?.reason}, maxRSS ${(negative.maxRSS / 1024).toFixed(0)} MiB, ` +
              `${(negative.wallMs / 1000).toFixed(1)}s`,
          );
          if (negative.outcomes.some((outcome) => outcome.ok))
            finding(`${tag}: negative control unexpectedly succeeded`);
          if (first && !limitReason(first.reason))
            finding(`${tag}: negative control reason ${first.stage}/${first.reason} is not a size limit`);
          if (!negative.spoolEmptyAfterDispose) finding(`${tag}: negative spool not empty after dispose`);
          if (negative.strayTempEntries.length > 0)
            finding(`${tag}: negative stray temp entries ${negative.strayTempEntries.join(', ')}`);
        }
      }

      if (!KEEP) rmSync(fixtureDir, { recursive: true, force: true });
    }
  }

  // Flatness: per kind × signal, the largest run's peak must not exceed the
  // smallest by more than the tolerance. This is the whole point of the sweep.
  for (const kind of KINDS) {
    for (const signal of SIGNAL_VARIANTS) {
      const runs = positives
        .filter((run) => run.kind === kind && run.signal === signal)
        .sort((a, b) => a.sizeMiB - b.sizeMiB);
      if (runs.length < 2) continue;
      const smallest = runs[0]!;
      const largest = runs[runs.length - 1]!;
      const growthMiB = (largest.maxRSS - smallest.maxRSS) / 1024;
      console.log(
        `flatness ${kind}${signal ? '+signal' : ''}: maxRSS ${smallest.sizeMiB}→${largest.sizeMiB} MiB grows ${growthMiB.toFixed(0)} MiB`,
      );
      if (growthMiB > FLATNESS_MIB)
        finding(
          `${kind}${signal ? '+signal' : ''}: maxRSS grew ${growthMiB.toFixed(0)} MiB with size (tolerance ${FLATNESS_MIB} MiB)`,
        );
    }
  }

  mkdirSync(measurementsDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const record = {
    generatedAt: new Date().toISOString(),
    node: process.version,
    platform: process.platform,
    arch: process.arch,
    childBundledWith: 'esbuild',
    concurrency: CONCURRENCY,
    sizes: SIZES,
    kinds: KINDS,
    maxRssUnitCheck: unit,
    ceilingMiB: CEILING_MIB,
    flatnessMiB: FLATNESS_MIB,
    positives,
    negatives,
    findings,
  };
  writeFileSync(join(measurementsDir, `receive-${stamp}.json`), `${JSON.stringify(record, null, 2)}\n`);

  console.log(
    '\n| kind | MiB | signal | concurrency | maxRSS MiB | spool peak MiB | wall s | sbdh | digest | spool clean |',
  );
  console.log('| --- | --: | --- | --: | --: | --: | --: | --- | --- | --- |');
  for (const run of positives) {
    const outcome = run.outcomes[0];
    console.log(
      `| ${run.kind} | ${run.sizeMiB} | ${run.signal ? 'yes' : 'no'} | ${run.concurrency} | ${(run.maxRSS / 1024).toFixed(0)} | ` +
        `${(run.peakSpoolBytes / MIB).toFixed(0)} | ${(run.wallMs / 1000).toFixed(1)} | ${outcome?.sbdh ?? '-'} | ` +
        `${outcome?.digestOk ? 'ok' : 'FAIL'} | ${run.spoolEmptyAfterDispose ? 'yes' : 'NO'} |`,
    );
  }
  if (negatives.length > 0) {
    console.log('\n| kind | MiB | signal | reason | maxRSS MiB | wall s | spool clean |');
    console.log('| --- | --: | --- | --- | --: | --: | --- |');
    for (const run of negatives) {
      const outcome = run.outcomes[0];
      console.log(
        `| ${run.kind} | ${run.sizeMiB} | ${run.signal ? 'yes' : 'no'} | ${outcome?.stage}/${outcome?.reason} | ` +
          `${(run.maxRSS / 1024).toFixed(0)} | ${(run.wallMs / 1000).toFixed(1)} | ${run.spoolEmptyAfterDispose ? 'yes' : 'NO'} |`,
      );
    }
  }

  if (findings.length > 0) {
    console.error(`\n${findings.length} finding(s):`);
    for (const message of findings) console.error(`  - ${message}`);
    process.exit(1);
  }
  console.log('\nAll Item 5 assertions passed.');
}

await main();
