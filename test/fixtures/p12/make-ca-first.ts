/**
 * Produce `ca-first.p12` from the committed PKCS#12 material. OpenSSL's
 * `pkcs12 -export` always writes the key-matching certificate first, so a
 * container that lists the CA first cannot be made with a plain OpenSSL command;
 * this reorders the same leaf/CA with the test PKCS#12 builder instead.
 *
 * Regenerate with:  node --import tsx test/fixtures/p12/make-ca-first.ts
 *
 * `modern.p12`, `legacy.p12`, the leaf key/cert and the CA cert were produced by
 * OpenSSL 3.6; see NOTICE.md for the exact commands.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createP12 } from '../../helpers/p12.js';

const here = dirname(fileURLToPath(import.meta.url));
const read = (name: string): string => readFileSync(join(here, name), 'utf8');

writeFileSync(
  join(here, 'ca-first.p12'),
  await createP12({
    keyPem: read('leaf-key.pem'),
    certPem: read('ca-cert.pem'),
    chainPem: [read('leaf-cert.pem')],
    passphrase: 'secret',
  }),
);
process.stdout.write('wrote ca-first.p12\n');
