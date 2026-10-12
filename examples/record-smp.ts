#!/usr/bin/env node
/**
 * Record one real SMP `SignedServiceMetadata` response as a fixture. It uses the
 * package's lookup (imported from source) to resolve the participant, then
 * re-fetches the raw SMP bytes and writes them, together with a JSON sidecar of
 * the request facts, into `test/fixtures/smp/` (or `--out`).
 *
 * The owner runs this against the Peppol test network to add captured responses
 * from different SMP implementations. It needs network access.
 *
 *   node --import tsx examples/record-smp.ts \
 *     --participant iso6523-actorid-upis::0192:222222222 \
 *     --doc-type 'urn:oasis:...::Invoice##...::2.1' \
 *     --process 'urn:fdc:peppol.eu:2017:poacc:billing:01:1.0' \
 *     --env test --name oxalis
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { lookupParticipant } from '../src/lookup/index.js';
import { bundledTrust, smlZone, type SmEnv } from './lib/trust.js';

function flags(argv: readonly string[]): Map<string, string> {
  const map = new Map<string, string>();
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i]!;
    if (!token.startsWith('--')) continue;
    const key = token.slice(2);
    const next = argv[i + 1];
    if (next !== undefined && !next.startsWith('--')) {
      map.set(key, next);
      i += 1;
    } else map.set(key, 'true');
  }
  return map;
}

function required(args: Map<string, string>, name: string): string {
  const value = args.get(name);
  if (!value) throw new Error(`missing --${name}`);
  return value;
}

async function main(): Promise<void> {
  const args = flags(process.argv.slice(2));
  if (args.has('help')) {
    console.log(
      'usage: --participant <scheme>::<value> --doc-type VALUE --process VALUE [--env test] [--sml ZONE] [--name NAME] [--out DIR]',
    );
    return;
  }
  const participant = required(args, 'participant');
  const separator = participant.indexOf('::');
  if (separator < 0) throw new Error('--participant must be <scheme>::<value>');
  const env = (args.get('env') ?? 'test') as SmEnv;
  const name = args.get('name') ?? 'capture';
  const outDir = args.get('out') ?? join('test', 'fixtures', 'smp');
  const documentType = { scheme: args.get('doc-type-scheme') ?? 'busdox-docid-qns', value: required(args, 'doc-type') };
  const processId = { scheme: args.get('process-scheme') ?? 'cenbii-procid-ubl', value: required(args, 'process') };
  const sml = args.get('sml') ?? smlZone(env);

  const bundled = bundledTrust(env);
  // Recording must not depend on the signature: the resulting fixture is
  // verified offline later. Accept any recognizable structure.
  const result = await lookupParticipant({
    participant: { scheme: participant.slice(0, separator), value: participant.slice(separator + 2) },
    documentType,
    process: processId,
    sml,
    validateCertificate: async () => ({ ok: true }),
    now: () => new Date(),
  });

  if (result.outcome !== 'found') {
    console.error(`lookup outcome ${result.outcome}: ${JSON.stringify(result)}`);
    process.exit(1);
  }

  const response = await fetch(result.smpUrl, { headers: { Accept: 'text/xml, application/xml' } });
  const body = Buffer.from(await response.arrayBuffer());

  mkdirSync(outDir, { recursive: true });
  const xmlPath = join(outDir, `${name}.signed.xml`);
  const metaPath = join(outDir, `${name}.json`);
  writeFileSync(xmlPath, body);
  writeFileSync(
    metaPath,
    JSON.stringify(
      {
        name,
        env,
        sml,
        participant,
        documentType,
        process: processId,
        smpUrl: result.smpUrl,
        endpointUrl: result.endpointUrl,
      },
      null,
      2,
    ),
  );
  console.log(`wrote ${xmlPath} (${body.length} bytes) and ${metaPath}`);
  console.log(`(trust roots for offline verification: ${bundled.roots.length})`);
}

void main().catch((err) => {
  console.error(`record failed: ${(err as Error).message}`);
  process.exit(1);
});
