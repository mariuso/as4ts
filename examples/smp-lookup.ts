#!/usr/bin/env node
/**
 * SMP lookup for one participant, using the package's `as4ts/lookup` entry point
 * (here imported from source). It performs one discovery and prints the facts:
 * the AS4 endpoint, transport profile, receiver certificate and whether the SMP
 * response's signature verified. Unlike the old example, it verifies the SMP
 * response signature with an injected certificate validator.
 *
 *   node --import tsx examples/smp-lookup.ts --participant 0192:222222222 --env test
 *   node --import tsx examples/smp-lookup.ts --value 222222222 --scheme 0192 --env test --out ./lookup
 *
 * This file is an example, not part of the published package.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import { join } from 'node:path';
import { createCertificateValidator, defaultRevocationPolicy } from '../src/certificate-validator.js';
import { lookupParticipant } from '../src/lookup/index.js';
import type { ParticipantId } from '../src/types.js';
import { bundledTrust, smlZone, type SmEnv } from './lib/trust.js';

const DEFAULT_DOC_TYPE =
  'urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice##urn:cen.eu:en16931:2017#compliant#urn:fdc:peppol.eu:2017:poacc:billing:3.0::2.1';
const DEFAULT_PROCESS = 'urn:fdc:peppol.eu:2017:poacc:billing:01:1.0';

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

function participantFrom(args: Map<string, string>): ParticipantId {
  const full = args.get('participant');
  if (full) {
    const separator = full.indexOf('::');
    if (separator < 0) throw new Error('--participant must be <scheme>::<value>');
    return { scheme: full.slice(0, separator), value: full.slice(separator + 2) };
  }
  const value = args.get('value');
  if (!value) throw new Error('need --participant <scheme>::<value> or --value <value>');
  return { scheme: args.get('scheme') ?? 'iso6523-actorid-upis', value };
}

function certCn(pem: string): string {
  try {
    return new X509Certificate(pem).subject.replace(/\n/g, ', ');
  } catch {
    return '(unreadable)';
  }
}

async function main(): Promise<void> {
  const args = flags(process.argv.slice(2));
  if (args.has('help')) {
    console.log(
      'usage: --participant <scheme>::<value> | --scheme S --value V ' +
        '[--env test|prod] [--sml ZONE] [--doc-type VALUE] [--doc-type-scheme S] ' +
        '[--process VALUE] [--process-scheme S] [--transport-profile ID] [--out DIR]',
    );
    return;
  }
  const env = (args.get('env') ?? 'test') as SmEnv;
  const participant = participantFrom(args);
  const documentType = {
    scheme: args.get('doc-type-scheme') ?? 'busdox-docid-qns',
    value: args.get('doc-type') ?? DEFAULT_DOC_TYPE,
  };
  const processId = {
    scheme: args.get('process-scheme') ?? 'cenbii-procid-ubl',
    value: args.get('process') ?? DEFAULT_PROCESS,
  };

  const bundled = bundledTrust(env);
  const validator = createCertificateValidator({
    roots: bundled.roots,
    intermediates: bundled.intermediates,
    intermediatesByPurpose: { 'smp-signer': bundled.smpIntermediates },
    revocation: defaultRevocationPolicy(),
  });

  const result = await lookupParticipant({
    participant,
    documentType,
    process: processId,
    ...(args.get('transport-profile') ? { transportProfile: args.get('transport-profile')! } : {}),
    sml: args.get('sml') ?? smlZone(env),
    validateCertificate: (input) => validator.validate(input),
    now: () => new Date(),
  });

  console.log(`outcome: ${result.outcome}`);
  if (result.outcome === 'found') {
    console.log(`endpoint URL:        ${result.endpointUrl}`);
    console.log(`transport profile:   ${result.transportProfile}`);
    console.log(`SMP URL:             ${result.smpUrl}`);
    console.log(`receiver cert CN:    ${certCn(result.receiverCertificate)}`);
    console.log(`SMP signer cert CN:  ${certCn(result.signerCertificate)}`);
    if (result.serviceActivationDate) console.log(`activated:           ${result.serviceActivationDate}`);
    if (result.serviceExpirationDate) console.log(`expires:             ${result.serviceExpirationDate}`);
  } else {
    console.log(JSON.stringify(result, null, 2));
  }

  const outDir = args.get('out');
  if (outDir && result.outcome === 'found') {
    mkdirSync(outDir, { recursive: true });
    writeFileSync(join(outDir, 'receiver-ap.pem'), result.receiverCertificate);
    writeFileSync(join(outDir, 'lookup.json'), JSON.stringify(result, null, 2));
    console.log(`wrote ${join(outDir, 'receiver-ap.pem')}`);
  }
}

void main().catch((err) => {
  console.error(`lookup failed: ${(err as Error).message}`);
  process.exit(1);
});
