/**
 * Build the Item 5 measurement fixtures.
 *
 * Each fixture is a complete, signed `multipart/related` AS4 request written to
 * disk (`body.bin`) with a `meta.json` describing it. Building a 512 MiB message
 * (gzip + encryption) is heavy, so it runs in this separate process and never
 * counts towards the measured receiver's memory.
 *
 *   AS4_MEASURE_DIR=<dir> AS4_GENERATE_KINDS=xml,base64 AS4_GENERATE_SIZES=64,256,512 \
 *     node --import tsx test/measure/generate-fixtures.ts
 *
 * A fixture that already exists is skipped unless `AS4_MEASURE_FORCE=1`.
 */
import { createHash, createPrivateKey } from 'node:crypto';
import { createWriteStream, existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { signerFromKey } from '../../src/index.js';
import { defaultEntropy, prepareAs4Internal } from '../../src/internal.js';
import { buildMultipartBody } from '../../src/multipart.js';
import {
  holderFromPkiDir,
  pkiExists,
  persistPki,
  receiverCertificateFromPkiDir,
  senderSignerFromPkiDir,
  validatorFromPkiDir,
} from '../helpers/measure.js';
import { createTestPki } from '../helpers/pki.js';
import {
  DOCUMENT_TYPE,
  PROCESS_ID,
  RECEIVER_PARTICIPANT,
  SENDER_PARTICIPANT,
  payloadChunks,
  type Kind,
} from './payload.js';

const MIB = 1024 * 1024;

export interface FixtureMeta {
  readonly kind: Kind;
  readonly sizeMiB: number;
  readonly targetRecoveredBytes: number;
  readonly recoveredBytes: number;
  readonly recoveredSha256: string;
  readonly wireBytes: number;
  readonly contentType: string;
  readonly as4MessageId: string;
}

function parseList(value: string | undefined, fallback: string): string[] {
  return (value ?? fallback)
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
}

async function main(): Promise<void> {
  const root = process.env['AS4_MEASURE_DIR'];
  if (!root) throw new Error('AS4_MEASURE_DIR must be set to the fixture root');
  const kinds = parseList(process.env['AS4_GENERATE_KINDS'], 'xml,base64') as Kind[];
  const sizes = parseList(process.env['AS4_GENERATE_SIZES'], '64,256,512').map(Number);
  const force = process.env['AS4_MEASURE_FORCE'] === '1';

  const pkiDir = join(root, 'pki');
  if (!pkiExists(pkiDir)) {
    persistPki(createTestPki(), pkiDir);
    console.log(`persisted test PKI at ${pkiDir}`);
  }
  // Touch the holder so a broken key export fails here, not in the child.
  holderFromPkiDir(pkiDir);

  const signerInfo = senderSignerFromPkiDir(pkiDir);
  const signer = signerFromKey(createPrivateKey(signerInfo.keyPem), signerInfo.certificate);
  const receiverCertificate = receiverCertificateFromPkiDir(pkiDir);
  const validateCertificate = validatorFromPkiDir(pkiDir);
  mkdirSync(join(root, 'work'), { recursive: true });

  for (const kind of kinds) {
    for (const sizeMiB of sizes) {
      const name = `${kind}-${sizeMiB}`;
      const dir = join(root, name);
      const bodyPath = join(dir, 'body.bin');
      if (existsSync(bodyPath) && !force) {
        console.log(`skip ${name} (exists)`);
        continue;
      }
      if (existsSync(dir)) rmSync(dir, { recursive: true, force: true });
      mkdirSync(dir, { recursive: true });
      const started = Date.now();

      const targetRecoveredBytes = sizeMiB * MIB;
      const hash = createHash('sha256');
      let recoveredBytes = 0;
      const counter = new Transform({
        transform(chunk: Buffer, _encoding, callback) {
          recoveredBytes += chunk.length;
          hash.update(chunk);
          callback(null, chunk);
        },
      });
      const payload = Readable.from(payloadChunks(kind, targetRecoveredBytes)).pipe(counter);

      const as4MessageId = `measure-${name}@as4-measure`;
      const prepared = await prepareAs4Internal(
        {
          payload,
          endpointUrl: 'https://ap.example/as4',
          transportProfile: 'peppol-transport-as4-v2_0',
          receiverCertificate,
          senderParticipant: SENDER_PARTICIPANT,
          receiverParticipant: RECEIVER_PARTICIPANT,
          documentType: DOCUMENT_TYPE,
          process: PROCESS_ID,
          as4MessageId,
          signer,
          validateCertificate,
          artifactDirectory: join(root, 'work'),
          now: () => new Date(),
        },
        defaultEntropy(),
      );
      if (prepared.outcome !== 'prepared') {
        throw new Error(`preparing ${name} failed: ${JSON.stringify(prepared)}`);
      }
      const message = prepared.message;
      try {
        const multipart = buildMultipartBody({
          soapXml: message.soapXml,
          attachmentHref: message.attachmentHref,
          attachmentFilePath: join(message.directory, 'attachment.bin'),
          attachmentByteLength: message.attachmentByteLength,
          boundary: message.boundary,
          soapContentId: message.soapContentId,
        });
        let wireBytes = 0;
        await pipeline(
          multipart.stream,
          new Transform({
            transform(chunk: Buffer, _encoding, callback) {
              wireBytes += chunk.length;
              callback(null, chunk);
            },
          }),
          createWriteStream(bodyPath),
        );
        const meta: FixtureMeta = {
          kind,
          sizeMiB,
          targetRecoveredBytes,
          recoveredBytes,
          recoveredSha256: hash.digest('base64'),
          wireBytes,
          contentType: multipart.contentType,
          as4MessageId,
        };
        writeFileSync(join(dir, 'meta.json'), `${JSON.stringify(meta, null, 2)}\n`);
        const ratio = recoveredBytes / wireBytes;
        console.log(
          `built ${name}: recovered ${recoveredBytes} B, wire ${wireBytes} B, ratio ${ratio.toFixed(2)}x, ` +
            `${((Date.now() - started) / 1000).toFixed(1)}s`,
        );
      } finally {
        await message.dispose();
      }
    }
  }
  if (!process.env['AS4_MEASURE_KEEP_WORK']) rmSync(join(root, 'work'), { recursive: true, force: true });
}

await main();
