/**
 * Phase 6 receiving validation.
 *
 * The ordinary suite skips absent captures so day-to-day work stays green. This
 * command is the release gate: it FAILS unless there are successful,
 * receipt-accepted captures from at least two **distinct** sender
 * implementations. A local capture proves the harness works but is not
 * independent interoperability evidence, so it is never counted.
 *
 * Passing this gate is not the coverage-policy freeze and not Peppol Testbed
 * completion; those remain separate.
 *
 *   npm run validate:receive
 */
import { existsSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadCapture, verifyCapture, type CaptureFacts } from './helpers/capture.js';

const REQUIRED_DISTINCT = 2;

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

let failures = 0;
const verified: CaptureFacts[] = [];
for (const capture of independent) {
  try {
    const facts = await verifyCapture(capture);
    verified.push(facts);
    const acceptability = facts.senderAccepted ? 'sender accepted the receipt' : 'sender did NOT accept the receipt';
    console.log(
      `  independent ${facts.name}: ok (${facts.implementation}, ${facts.referenceCount} references, ${acceptability})`,
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

// Only captures whose recorded sender acceptance is positive count, and they
// must come from distinct implementations.
const accepted = verified.filter((facts) => facts.senderAccepted);
const implementations = new Map<string, string[]>();
for (const facts of accepted) {
  implementations.set(facts.implementation, [...(implementations.get(facts.implementation) ?? []), facts.name]);
}
if (implementations.size < REQUIRED_DISTINCT) {
  console.error(
    `\nFAILED: successful, receipt-accepted captures from ${REQUIRED_DISTINCT} distinct sender implementations ` +
      `are required, found ${implementations.size} (${[...implementations.keys()].join(', ') || 'none'}).\n` +
      'Record the unmodified request, the capture metadata, the test receiver credentials and the sender trust chain,\n' +
      'and preserve the sender result / response as evidence — see docs/receiving-fixtures.md.',
  );
  process.exit(1);
}

console.log(
  `\nPhase 6 receiving validation passed: ${implementations.size} distinct implementations ` +
    `(${[...implementations.keys()].join(', ')}).`,
);
