#!/usr/bin/env node
/**
 * SMP lookup for one participant. Read-only: resolves the SML, queries SMP and
 * prints the AS4 endpoint, transport profile and receiver certificate.
 *
 *   node --import tsx examples/smp-lookup.ts --participant 0192:222222222 --env test
 *   node --import tsx examples/smp-lookup.ts --value 222222222 --scheme 0192 --env test --document-type Invoice-2 --out ./lookup
 *
 * This file is an example, not part of the published package. It does NOT verify
 * the XML signature on the SMP response: it trusts whatever the SMP serves. Do
 * not treat its output as authenticated. The sender library deliberately does no
 * discovery; it belongs to the calling platform. This is caller-side tooling.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { X509Certificate } from 'node:crypto';
import { lookupParticipant, type SmEnv } from './lib/smp.js';

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

function participantFrom(args: Map<string, string>): string {
  const full = args.get('participant');
  if (full) return full;
  const scheme = args.get('scheme') ?? 'iso6523-actorid-upis';
  const value = args.get('value');
  if (!value) throw new Error('need --participant <scheme>::<value> or --value <value>');
  return `${scheme}::${value}`;
}

async function main(): Promise<void> {
  const args = flags(process.argv.slice(2));
  if (args.has('help')) {
    console.log('usage: --participant <scheme>::<value> [--env test|prod] [--document-type SUBSTR] [--out DIR]');
    return;
  }
  const env = (args.get('env') ?? 'test') as SmEnv;
  const participant = participantFrom(args);
  const documentType = args.get('document-type');
  const info = await lookupParticipant({
    participant,
    env,
    ...(documentType ? { documentType } : {}),
  });

  console.log(`SML resolved SMP base: ${info.smpBase}`);
  console.log(`service metadata references: ${info.references.length}`);
  for (const ref of info.references) console.log(`  - ${ref}`);
  console.log('');
  console.log(`document identifier: ${info.documentIdentifier} (scheme ${info.documentScheme})`);
  console.log(`process identifier:  ${info.processIdentifier} (scheme ${info.processScheme})`);
  console.log(`transport profile:   ${info.transportProfile}`);
  console.log(`endpoint URL:        ${info.endpointUrl}`);
  console.log(`receiver cert CN:    ${certCn(info.certificatePem)}`);

  const outDir = args.get('out');
  if (outDir) {
    mkdirSync(outDir, { recursive: true });
    if (info.certificatePem) writeFileSync(join(outDir, 'receiver-ap.pem'), info.certificatePem);
    writeFileSync(join(outDir, 'smp.json'), JSON.stringify(info, null, 2));
    console.log(`wrote ${join(outDir, 'receiver-ap.pem')}`);
  }
}

function certCn(pem: string | null): string {
  if (!pem) return '(none)';
  try {
    return new X509Certificate(pem).subject.replace(/\n/g, ', ');
  } catch {
    return '(unreadable)';
  }
}

void main().catch((err) => {
  console.error(`lookup failed: ${(err as Error).message}`);
  process.exit(1);
});
