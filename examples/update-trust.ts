#!/usr/bin/env node
/**
 * Refresh the bundled Peppol trust anchors in assets/trust from DigiCert, which
 * hosts the OpenPEPPOL PKI certificate repository. Run when validation starts
 * failing with "no trusted issuer" (the access-point intermediate rotates).
 *
 *   npm run trust:update
 */
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { trustDir } from './lib/trust.js';

const SOURCES: Record<string, string> = {
  'prod-root.pem': 'http://cacerts.one.nl.digicert.com/PEPPOLRootCA-G3.crt',
  'prod-apca.pem': 'http://cacerts.one.nl.digicert.com/PEPPOLAccessPointCA-G3.crt',
  'prod-smpca.pem': 'http://cacerts.one.nl.digicert.com/PEPPOLServiceMetadataPublisherCA-G3.crt',
  'test-root.pem': 'http://cacerts.one.nl.digicert.com/PEPPOLRootTESTCA-G3.crt',
  'test-apca.pem': 'http://cacerts.one.nl.digicert.com/PEPPOLACCESSPOINTTESTCA-G3.crt',
  'test-smpca.pem': 'http://cacerts.one.nl.digicert.com/PEPPOLServiceMetadataPublisherTESTCA-G3.crt',
};

async function main(): Promise<void> {
  for (const [name, url] of Object.entries(SOURCES)) {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`GET ${url} -> HTTP ${res.status}`);
    const der = Buffer.from(await res.arrayBuffer());
    writeFileSync(join(trustDir(), name), derToPem(der));
    console.log(`${name} <- ${url}`);
  }
}

function derToPem(der: Buffer): string {
  const wrapped = (der.toString('base64').match(/.{1,64}/g) ?? []).join('\n');
  return `-----BEGIN CERTIFICATE-----\n${wrapped}\n-----END CERTIFICATE-----\n`;
}

void main().catch((err) => {
  console.error(`trust update failed: ${(err as Error).message}`);
  process.exit(1);
});
