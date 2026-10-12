#!/usr/bin/env node
/**
 * Example: send one real file to one real AS4 endpoint.
 *
 * This file is an example, not part of the published package. The receiver's
 * endpoint, transport profile, certificate and business identifiers are
 * resolved from SMP when not given. The library itself never does SMP lookup;
 * this example does it at the caller boundary.
 *
 *   node --import tsx examples/send-one.ts \
 *     --file invoice.sbdh.xml \
 *     --sender-p12 our-ap.p12 --p12-passphrase '...' \
 *     --trust-roots peppol-test-root.pem \
 *     --sender-participant-scheme iso6523-actorid-upis --sender-participant-value 0192:111111111 \
 *     --receiver-participant-scheme iso6523-actorid-upis --receiver-participant-value 0192:222222222 \
 *     --sml-env test --document-type Invoice-2 \
 *     --out ./evidence
 */
import { randomUUID, X509Certificate } from 'node:crypto';
import { createReadStream, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { sendAs4, signerFromKey, peppolProfile, type SendAs4Input, type SendAs4Result } from '../src/index.js';
import { createCertificateValidator, defaultRevocationPolicy } from '../src/certificate-validator.js';
import { classify } from '../src/classifier.js';
import {
  loadSigningMaterialFromPem,
  loadSigningMaterialFromP12,
  type SigningMaterial,
} from './lib/load-credentials.js';
import { lookupParticipant, type SmEnv, type SmpServiceInfo } from './lib/smp.js';
import { bundledTrust } from './lib/trust.js';
import { redactArgv, redactMessage } from './lib/redact.js';

interface Args {
  readonly flags: Map<string, string>;
}

function parseArgs(argv: readonly string[]): Args {
  const flags = new Map<string, string>();
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i]!;
    if (!token.startsWith('--')) continue;
    const eq = token.indexOf('=');
    if (eq >= 0) {
      flags.set(token.slice(2, eq), token.slice(eq + 1));
      continue;
    }
    const key = token.slice(2);
    const next = argv[i + 1];
    if (next !== undefined && !next.startsWith('--')) {
      flags.set(key, next);
      i += 1;
    } else {
      flags.set(key, 'true');
    }
  }
  return { flags };
}

function required(args: Args, name: string): string {
  const value = args.flags.get(name);
  if (!value) {
    console.error(`missing required --${name}`);
    console.error('run with --help for usage');
    process.exit(2);
  }
  return value;
}

function fail(message: string): never {
  console.error(message);
  process.exit(2);
}

function help(): never {
  console.error(`send-one: perform one AS4 send attempt and report the outcome.

Required:
  --file PATH                     SBDH + business document to send
  --sender-participant-scheme S   e.g. iso6523-actorid-upis
  --sender-participant-value V    e.g. 0192:111111111
  --receiver-participant-scheme S
  --receiver-participant-value V

Sender credentials — give EITHER a PKCS#12 OR a cert+key pair:
  --sender-p12 PATH               PKCS#12 (.p12/.pfx) with key + cert (+ chain)
  --p12-passphrase PASS           passphrase for --sender-p12 (default empty)
  --p12-passphrase-file PATH      read the passphrase from a file (keeps it out of argv)
  (or set the AS4_P12_PASSPHRASE environment variable)
  --sender-cert PATH              our AP certificate (PEM)   } PEM mode
  --sender-key PATH               our AP private key (PEM)   }

Discovery — resolved from SMP when omitted (needs the receiver participant):
  --endpoint URL                  receiver AS4 endpoint (https)
  --receiver-cert PATH            receiver AP certificate (PEM)
  --transport-profile ID          default peppol-transport-as4-v2_0
  --doc-type-scheme S / --doc-type-value V
  --process-scheme S / --process-value V
  --sml-env test|prod             SML used for discovery (default test)
  --document-type SUBSTR          SMP hint to pick between document types, e.g. Invoice-2

Optional:
  --trust-roots PATH              override the bundled Peppol root (PEM)
  --trust-intermediates PATH      override the bundled Peppol AP CA (PEM)
  --message-id ID                 default a generated uuid@<endpoint host>
  --revocation strict|soft        default strict
  --connect-timeout-ms N          default 10000
  --total-timeout-ms N            default 120000
  --tls-ca PATH                   pin the receiver's TLS certificate (testing)
  --dry-run                       resolve inputs and print them, do not send
  --out DIR                       write raw signal evidence here
`);
  process.exit(0);
}

function loadCert(path: string): string {
  return readFileSync(path, 'utf8');
}

function certificateCommonName(pem: string): string {
  try {
    const match = /(?:^|\n)\s*CN=([^\n]+)/.exec(new X509Certificate(pem).subject);
    return match?.[1]?.trim() ?? '(unreadable)';
  } catch {
    return '(unreadable)';
  }
}

function resolvePassphrase(args: Args): string {
  const direct = args.flags.get('p12-passphrase');
  if (direct !== undefined) return direct;
  const file = args.flags.get('p12-passphrase-file');
  if (file) return (readFileSync(file, 'utf8').split(/\r?\n/)[0] ?? '').trim();
  return process.env['AS4_P12_PASSPHRASE'] ?? '';
}

function resolveSigningMaterial(args: Args): SigningMaterial {
  const p12 = args.flags.get('sender-p12');
  if (p12) {
    return loadSigningMaterialFromP12(p12, resolvePassphrase(args));
  }
  return loadSigningMaterialFromPem(required(args, 'sender-cert'), required(args, 'sender-key'));
}

async function main(): Promise<void> {
  const rawArgv = process.argv.slice(2);
  const args = parseArgs(rawArgv);
  if (args.flags.has('help')) help();

  // Audit line: the invocation with key material and passphrases masked, so logs
  // and evidence never carry them.
  process.stderr.write(`command: ${redactArgv(rawArgv)}\n`);

  const participant = `${required(args, 'receiver-participant-scheme')}::${required(args, 'receiver-participant-value')}`;
  const env = (args.flags.get('sml-env') ?? 'test') as SmEnv;
  const needLookup =
    !args.flags.has('receiver-cert') ||
    !args.flags.has('endpoint') ||
    !args.flags.has('transport-profile') ||
    !args.flags.has('doc-type-value') ||
    !args.flags.has('process-value');

  let smp: SmpServiceInfo | null = null;
  if (needLookup) {
    const hint = args.flags.get('document-type');
    process.stderr.write(`resolving ${participant} in the ${env} SML...\n`);
    smp = await lookupParticipant({ participant, env, ...(hint ? { documentType: hint } : {}) });
  }

  const endpoint = args.flags.get('endpoint') ?? smp?.endpointUrl ?? fail('no --endpoint and SMP published none');
  const receiverCertificate = args.flags.has('receiver-cert')
    ? loadCert(required(args, 'receiver-cert'))
    : (smp?.certificatePem ?? fail('no --receiver-cert and SMP published none'));
  const transportProfile = args.flags.get('transport-profile') ?? smp?.transportProfile ?? 'peppol-transport-as4-v2_0';
  const documentType = {
    scheme: args.flags.get('doc-type-scheme') ?? smp?.documentScheme ?? fail('no document type scheme'),
    value: args.flags.get('doc-type-value') ?? smp?.documentIdentifier ?? fail('no document type value'),
  };
  const processId = {
    scheme: args.flags.get('process-scheme') ?? smp?.processScheme ?? fail('no process scheme'),
    value: args.flags.get('process-value') ?? smp?.processIdentifier ?? fail('no process value'),
  };

  if (args.flags.has('dry-run')) {
    console.log(
      JSON.stringify(
        {
          endpoint,
          transportProfile,
          receiverCertificateCN: certificateCommonName(receiverCertificate),
          documentType,
          process: processId,
        },
        null,
        2,
      ),
    );
    return;
  }

  const endpointHost = (() => {
    try {
      return new URL(endpoint).hostname;
    } catch {
      return 'as4';
    }
  })();

  const signing = resolveSigningMaterial(args);
  const bundled = bundledTrust(env);
  const roots = args.flags.has('trust-roots') ? [loadCert(required(args, 'trust-roots'))] : [...bundled.roots];
  const intermediates = args.flags.has('trust-intermediates')
    ? [loadCert(required(args, 'trust-intermediates'))]
    : [...bundled.intermediates];
  const revocation = defaultRevocationPolicy({
    unreachable: (args.flags.get('revocation') as 'strict' | 'soft' | undefined) ?? 'strict',
  });
  const validator = createCertificateValidator({ roots, intermediates, revocation });

  const input: SendAs4Input = {
    payload: createReadStream(required(args, 'file')),
    endpointUrl: endpoint,
    transportProfile,
    receiverCertificate,
    senderParticipant: {
      scheme: required(args, 'sender-participant-scheme'),
      value: required(args, 'sender-participant-value'),
    },
    receiverParticipant: {
      scheme: required(args, 'receiver-participant-scheme'),
      value: required(args, 'receiver-participant-value'),
    },
    documentType,
    process: processId,
    as4MessageId: args.flags.get('message-id') ?? `${randomUUID()}@${endpointHost}`,
    signer: signerFromKey(signing.signingKey, signing.signingCertificate),
    validateCertificate: (v) => validator.validate(v),
    profile: peppolProfile,
    http: {
      connectMs: Number(args.flags.get('connect-timeout-ms') ?? 10_000),
      totalMs: Number(args.flags.get('total-timeout-ms') ?? 120_000),
      ...(args.flags.has('tls-ca') ? { ca: [loadCert(required(args, 'tls-ca'))] } : {}),
    },
    now: () => new Date(),
  };

  const result = await sendAs4(input);
  report(result, args.flags.get('out'));

  process.exit(classify(result) === 'accepted' ? 0 : 1);
}

function report(result: SendAs4Result, outDir: string | undefined): void {
  console.log(`outcome:        ${result.outcome}`);
  console.log(`class:          ${classify(result)}`);
  console.log(`as4MessageId:   ${result.as4MessageId}`);
  console.log(`sentAt:         ${result.sentAt ?? '(not sent)'}`);
  console.log(`receiver CN:    ${result.receiverCertificateCommonName}`);
  console.log(`transport:      ${result.transportProfile}`);
  if (result.outcome === 'no-signal') console.log(`http:           ${result.status} (bodyEmpty=${result.bodyEmpty})`);
  if (result.outcome === 'transport-failure')
    console.log(
      `transport:      ${result.errorCode ?? '(none)'} (requestBytesWritten=${result.requestBytesWritten}, aborted=${result.aborted})`,
    );
  if (result.outcome === 'receipt-verified') {
    console.log(`receipt at:     ${result.receipt.timestamp}`);
    console.log(`receipt signer is SMP cert: ${result.receipt.signerMatchesSmPCertificate}`);
  }
  if (result.outcome === 'receipt-unverified') console.log(`receipt reason: ${result.reason}`);
  if (result.outcome === 'not-sent') {
    console.log(`not sent:       ${result.reason}`);
    if (result.detail) console.log(`detail:         ${result.detail}`);
  }
  if (result.outcome === 'error-signal') {
    for (const error of result.errors) {
      console.log(`ebMS error:     ${error.code} (${error.severity})`);
      if (error.shortDescription) console.log(`error text:     ${error.shortDescription}`);
      if (error.detail) console.log(`error detail:   ${error.detail}`);
    }
  }
  console.log('');
  console.log(JSON.stringify(result, jsonReplacer, 2));

  if (outDir) {
    mkdirSync(outDir, { recursive: true });
    const raw = rawSignal(result);
    if (raw) {
      const name = result.outcome === 'receipt-verified' ? 'receipt.xml' : 'signal.xml';
      writeFileSync(join(outDir, name), Buffer.from(raw));
      console.log(`\nwrote ${join(outDir, name)}`);
    }
    writeFileSync(join(outDir, 'result.json'), JSON.stringify(result, jsonReplacer, 2));
  }
}

function rawSignal(result: SendAs4Result): Uint8Array | undefined {
  switch (result.outcome) {
    case 'receipt-verified':
      return result.receipt.raw;
    case 'receipt-unverified':
    case 'error-signal':
      return result.raw;
    default:
      return undefined;
  }
}

function jsonReplacer(_key: string, value: unknown): unknown {
  // Buffer has a toJSON() that runs before this replacer, turning the bytes into
  // { type: 'Buffer', data: [...] }. Collapse that (and any Uint8Array) to a
  // size summary; the raw bytes are written to files with --out.
  if (
    value !== null &&
    typeof value === 'object' &&
    (value as { type?: unknown }).type === 'Buffer' &&
    Array.isArray((value as { data?: unknown }).data)
  ) {
    return `[${(value as { data: unknown[] }).data.length} bytes]`;
  }
  if (value instanceof Uint8Array) return `[${value.byteLength} bytes]`;
  return value;
}

void main().catch((err: unknown) => {
  const message = redactMessage(err instanceof Error ? err.message : String(err), process.argv.slice(2));
  console.error(`send failed: ${message}`);
  process.exit(1);
});
