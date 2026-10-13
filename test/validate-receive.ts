/**
 * Phase 6 receiving validation.
 *
 * The ordinary suite skips absent captures so day-to-day work stays green. This
 * command is the release gate: it FAILS unless at least two **independent**
 * captures are present and verify end to end. A local capture proves the harness
 * works but is not independent interoperability evidence, so it is never counted.
 *
 *   npm run validate:receive
 */
import { existsSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadCapture, verifyCapture } from './helpers/capture.js';

const REQUIRED_INDEPENDENT = 2;

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, 'fixtures', 'inbound');

const names = existsSync(fixtures)
  ? readdirSync(fixtures, { withFileTypes: true })
      .filter((entry) => entry.isDirectory() && existsSync(join(fixtures, entry.name, 'metadata.json')))
      .map((entry) => entry.name)
      .sort()
  : [];

const captures = names.map((name) => loadCapture(join(fixtures, name), name));
const independent = captures.filter((capture) => capture.metadata.origin === 'independent');
const local = captures.filter((capture) => capture.metadata.origin === 'local');

console.log(`Phase 6 receiving validation: ${independent.length} independent, ${local.length} local capture(s)`);
for (const capture of local) {
  console.log(`  local       ${capture.name} — not counted as independent evidence`);
}

if (independent.length < REQUIRED_INDEPENDENT) {
  console.error(
    `\nFAILED: ${REQUIRED_INDEPENDENT} independent captures are required, found ${independent.length}.\n` +
      'Record them under test/fixtures/inbound/<name>/ with origin "independent" — see docs/receiving-fixtures.md.\n' +
      'Each needs the unmodified request body, Content-Type, sender implementation/version/configuration,\n' +
      'test receiver credentials, the sender trust chain, the capture time and the expected payload hash.',
  );
  process.exit(1);
}

let failures = 0;
for (const capture of independent) {
  try {
    const facts = await verifyCapture(capture);
    console.log(
      `  independent ${facts.name}: ok (message ${facts.messageId}, ${facts.referenceCount} references, payload ${facts.payloadSha256Base64.slice(0, 12)}…)`,
    );
  } catch (err) {
    failures += 1;
    console.error(`  independent ${capture.name}: FAILED — ${err instanceof Error ? err.message : String(err)}`);
  }
}

if (failures > 0) {
  console.error(`\nFAILED: ${failures} independent capture(s) did not verify.`);
  process.exit(1);
}
console.log('\nPhase 6 receiving validation passed.');
