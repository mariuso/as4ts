/**
 * The measured receiving process for Item 5.
 *
 * It opens `concurrency` copies of one pre-built request body concurrently from
 * disk, reads and verifies every payload, disposes everything, then prints one
 * JSON result line. Peak memory is `process.resourceUsage().maxRSS` — the
 * operating system's own peak counter — read after all opens have finished and
 * been disposed. Interval sampling is for the timeline only.
 *
 * Configuration (env): AS4_CHILD_FIXTURE, AS4_CHILD_PKI, AS4_CHILD_SPOOL,
 * AS4_CHILD_CONCURRENCY, AS4_CHILD_PROFILE (`override` | `default`).
 */
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createReadStream } from 'node:fs';
import { openAs4Message } from '../../src/receive/open.js';
import { holderFromPkiDir, receiverIdentityFromPkiDir, validatorFromPkiDir } from '../helpers/measure.js';

const MIB = 1024 * 1024;

/** The override block the contract documents. */
const OVERRIDE_LIMITS = {
  maxRequestBytes: 1024 * MIB,
  maxPartBytes: 1024 * MIB,
  maxRepresentationBytes: 1024 * MIB,
  maxDecompressedBytes: 1024 * MIB,
  maxAggregateOutputBytes: 1024 * MIB,
  maxXmlBytes: 1024 * MIB,
};

interface FixtureMeta {
  readonly kind: string;
  readonly sizeMiB: number;
  readonly recoveredBytes: number;
  readonly recoveredSha256: string;
  readonly wireBytes: number;
  readonly contentType: string;
  readonly as4MessageId: string;
}

function directorySize(dir: string): number {
  let total = 0;
  const stack = [dir];
  while (stack.length > 0) {
    const current = stack.pop()!;
    let entries;
    try {
      entries = readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const full = join(current, entry.name);
      if (entry.isDirectory()) stack.push(full);
      else if (entry.isFile()) {
        try {
          total += statSync(full).size;
        } catch {
          // raced removal
        }
      }
    }
  }
  return total;
}

function as4TempEntries(): string[] {
  try {
    return readdirSync(tmpdir())
      .filter((name) => name.startsWith('as4-'))
      .sort();
  } catch {
    return [];
  }
}

interface OpenOutcome {
  readonly ok: boolean;
  readonly stage?: string;
  readonly reason?: string;
  readonly sbdh?: string;
  readonly payloadBytes?: number;
  readonly digestOk?: boolean;
}

async function main(): Promise<void> {
  const fixtureDir = process.env['AS4_CHILD_FIXTURE'];
  const pkiDir = process.env['AS4_CHILD_PKI'];
  const spoolDir = process.env['AS4_CHILD_SPOOL'];
  const concurrency = Number(process.env['AS4_CHILD_CONCURRENCY'] ?? '4');
  const profile = process.env['AS4_CHILD_PROFILE'] ?? 'override';
  const useSignal = process.env['AS4_CHILD_SIGNAL'] === '1';
  if (!fixtureDir || !pkiDir || !spoolDir)
    throw new Error('AS4_CHILD_FIXTURE, AS4_CHILD_PKI and AS4_CHILD_SPOOL are required');

  const meta = JSON.parse(readFileSync(join(fixtureDir, 'meta.json'), 'utf8')) as FixtureMeta;
  const bodyPath = join(fixtureDir, 'body.bin');
  const holder = holderFromPkiDir(pkiDir);
  const validateCertificate = validatorFromPkiDir(pkiDir);
  const receiverIdentity = receiverIdentityFromPkiDir(pkiDir);
  const limits = profile === 'override' ? OVERRIDE_LIMITS : undefined;

  const tempBefore = as4TempEntries();
  const timeline: Array<{ rss: number; heapUsed: number; external: number; arrayBuffers: number; spool: number }> = [];
  let peakSpool = directorySize(spoolDir);
  const sampler = setInterval(() => {
    const usage = process.memoryUsage();
    const spool = directorySize(spoolDir);
    if (spool > peakSpool) peakSpool = spool;
    timeline.push({
      rss: usage.rss,
      heapUsed: usage.heapUsed,
      external: usage.external,
      arrayBuffers: usage.arrayBuffers,
      spool,
    });
  }, 250);

  const openOne = async (): Promise<OpenOutcome> => {
    let result;
    try {
      result = await openAs4Message({
        contentType: meta.contentType,
        body: createReadStream(bodyPath),
        keyHolder: holder,
        validateCertificate,
        receiverIdentity,
        spoolDirectory: spoolDir,
        ...(limits ? { limits } : {}),
        // Production callers pass a signal; this one never aborts. It exercises
        // the cancellation path (and, before the fix, its separate retention).
        ...(useSignal ? { signal: new AbortController().signal } : {}),
        now: () => new Date(),
      });
    } catch (err) {
      return { ok: false, stage: 'threw', reason: err instanceof Error ? err.message : String(err) };
    }
    if (!result.ok) return { ok: false, stage: result.stage, reason: result.reason };
    const hash = createHash('sha256');
    let payloadBytes = 0;
    try {
      for await (const chunk of result.payload.read()) {
        payloadBytes += chunk.length;
        hash.update(chunk);
      }
      return {
        ok: true,
        sbdh: result.sbdh.status,
        payloadBytes,
        digestOk: hash.digest('base64') === meta.recoveredSha256,
      };
    } finally {
      await result.dispose();
    }
  };

  const started = Date.now();
  const outcomes = await Promise.all(Array.from({ length: concurrency }, () => openOne()));
  const wallMs = Date.now() - started;

  clearInterval(sampler);
  const maxRSS = process.resourceUsage().maxRSS; // kilobytes
  const spoolAfter = directorySize(spoolDir);
  const tempAfter = as4TempEntries();
  const strayTemp = tempAfter.filter((name) => !tempBefore.includes(name));

  const peak = (key: 'rss' | 'heapUsed' | 'external' | 'arrayBuffers' | 'spool'): number =>
    timeline.length === 0 ? 0 : Math.max(...timeline.map((sample) => sample[key]));

  const result = {
    fixture: `${meta.kind}-${meta.sizeMiB}`,
    kind: meta.kind,
    sizeMiB: meta.sizeMiB,
    concurrency,
    profile,
    signal: useSignal,
    recoveredBytes: meta.recoveredBytes,
    wireBytes: meta.wireBytes,
    contentType: meta.contentType,
    outcomes,
    maxRSS,
    sampledPeakRss: peak('rss'),
    sampledPeakHeapUsed: peak('heapUsed'),
    sampledPeakExternal: peak('external'),
    sampledPeakArrayBuffers: peak('arrayBuffers'),
    peakSpoolBytes: Math.max(peakSpool, spoolAfter),
    spoolEmptyAfterDispose: spoolAfter === 0,
    strayTempEntries: strayTemp,
    wallMs,
    node: process.version,
    platform: process.platform,
    arch: process.arch,
  };
  process.stdout.write(`MEASURE_RESULT ${JSON.stringify(result)}\n`);
}

await main();
