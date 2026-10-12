#!/usr/bin/env node
/**
 * Local end-to-end test send. No external inputs.
 *
 * Generates a throwaway test PKI and TLS certificate, starts a fake receiver
 * that decrypts, decompresses and verifies the signature and returns a signed
 * receipt, then performs one real AS4 send over TLS to it.
 *
 *   npm run selftest
 *
 * It also writes the generated PEM files to ./.example-output so you can inspect
 * them or reuse the same command shape as examples/send-one.ts.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createTestPki, createTlsServerCert } from '../test/helpers/pki.js';
import { startFakeReceiver } from '../test/helpers/fake-receiver.js';
import { baseInput } from '../test/helpers/input.js';
import { sendAs4 } from '../src/index.js';

async function main(): Promise<void> {
  const outDir = join(process.cwd(), '.example-output');
  mkdirSync(outDir, { recursive: true });

  const pki = createTestPki();
  const tls = createTlsServerCert();

  writeFileSync(join(outDir, 'receiver-ap.pem'), pki.receiver.certPem);
  writeFileSync(join(outDir, 'sender-ap.pem'), pki.sender.certPem);
  writeFileSync(join(outDir, 'sender-ap.key'), pki.sender.keyPem);
  writeFileSync(join(outDir, 'peppol-root.pem'), pki.root.certPem);
  writeFileSync(join(outDir, 'peppol-ap-ca.pem'), pki.intermediate.certPem);
  console.log(`wrote test PEMs to ${outDir}`);

  const receiver = await startFakeReceiver({ receiver: pki.receiver, tlsCertPem: tls.certPem, tlsKeyPem: tls.keyPem });
  try {
    const result = await sendAs4(baseInput(pki, receiver.url, tls.caPem, { as4MessageId: 'selftest@as4-sender' }));
    console.log(`outcome:  ${result.outcome}`);
    console.log(`remote:   ${receiver.url}`);
    if (result.outcome === 'receipt-verified') {
      console.log(`receipt:  signer matches SMP cert = ${result.receipt.signerMatchesSmPCertificate}`);
      console.log(
        `payload:  receiver decrypted and verified ${receiver.received[0]?.payload.length ?? 0} bytes; signature valid = ${receiver.received[0]?.signatureValid}`,
      );
    }
    process.exit(result.outcome === 'receipt-verified' ? 0 : 1);
  } finally {
    await receiver.close();
  }
}

void main();
