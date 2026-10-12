/**
 * Regenerate the committed golden fixtures. Run with:
 *
 *   node --import tsx test/golden/generate.ts
 *
 * The fixtures are throwaway test material: a self-signed sender key pair and a
 * receiver certificate, so the envelope builder can be pinned without a live
 * PKI. They are not secrets and are never used outside the golden test.
 */
import { createPrivateKey } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { signerFromKey } from '../../src/index.js';
import { buildEnvelope } from '../../src/xml/envelope.js';
import { buildMultipartBody } from '../../src/multipart.js';
import { peppolProfile } from '../../src/profile.js';
import { AS4_COMPRESSION_TYPE } from '../../src/constants.js';
import { fixedEntropy } from '../helpers/entropy.js';
import { createSelfSignedCert } from '../helpers/pki.js';

const here = dirname(fileURLToPath(import.meta.url));

function selfSigned(commonName: string): { certPem: string; keyPem: string } {
  const cert = createSelfSignedCert(commonName, new Date('2026-01-01T00:00:00Z'));
  return { certPem: cert.certPem, keyPem: cert.keyPem };
}

async function main(): Promise<void> {
  mkdirSync(here, { recursive: true });

  const sender = selfSigned('POP000001');
  const receiver = selfSigned('POP000002');
  writeFileSync(join(here, 'sender-cert.pem'), sender.certPem);
  writeFileSync(join(here, 'sender-key.pem'), sender.keyPem);
  writeFileSync(join(here, 'receiver-cert.pem'), receiver.certPem);

  const wrappedKey = Buffer.alloc(256);
  for (let i = 0; i < wrappedKey.length; i += 1) wrappedKey[i] = i;
  writeFileSync(join(here, 'wrapped-key.bin'), wrappedKey);

  const attachment = Buffer.from('golden attachment bytes\r\n\x00\x01\x02\xfe\xff', 'latin1');
  writeFileSync(join(here, 'attachment.bin'), attachment);

  const signer = signerFromKey(createPrivateKey(sender.keyPem), sender.certPem);
  const built = await buildEnvelope({
    userMessage: {
      messageId: 'golden-message@as4-sender.test',
      timestamp: '2026-10-12T09:07:36.000Z',
      fromPartyId: 'POP000001',
      toPartyId: 'POP000002',
      profile: peppolProfile,
      service: { scheme: 'cenbii-procid-ubl', value: 'urn:www.cenbii.eu:profile:bii05:ver2.0' },
      action: 'busdox-docid-qns::urn:example:invoice::2.1',
      originalSender: { scheme: 'iso6523-actorid-upis', value: '0192:111111111' },
      finalRecipient: { scheme: 'iso6523-actorid-upis', value: '0192:222222222' },
      payloadHref: 'cid:11111111-2222-4333-8444-555555555555@golden.example',
      compressionType: AS4_COMPRESSION_TYPE,
    },
    signer,
    receiverCertificatePem: receiver.certPem,
    wrappedKey,
    attachmentDigestBase64: 'GOLDENATTACHMENTDIGEST=',
    entropy: fixedEntropy(),
  });
  writeFileSync(join(here, 'envelope.xml'), built.xml);

  const multipart = buildMultipartBody({
    soapXml: built.xml,
    attachmentHref: 'cid:11111111-2222-4333-8444-555555555555@golden.example',
    attachmentFilePath: join(here, 'attachment.bin'),
    attachmentByteLength: attachment.length,
    entropy: fixedEntropy(),
  });
  const chunks: Buffer[] = [];
  for await (const chunk of multipart.stream) chunks.push(chunk as Buffer);
  writeFileSync(join(here, 'multipart.bin'), Buffer.concat(chunks));
  writeFileSync(join(here, 'multipart.content-type.txt'), multipart.contentType);

  process.stdout.write(`wrote golden fixtures to ${here}\n`);
}

void main();
