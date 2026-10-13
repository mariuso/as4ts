import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { PEPPOL_PARTY_ID_TYPE } from '../src/constants.js';
import { signerFromKey } from '../src/index.js';
import { defaultEntropy, prepareAs4Internal } from '../src/internal.js';
import { buildMultipartBody } from '../src/multipart.js';
import { keyHolderFromKey } from '../src/receive/key-holder.js';
import { openAs4Message } from '../src/receive/open.js';
import { respondAs4Message } from '../src/receive/respond.js';
import { PACKAGE_VERSION } from '../src/version.js';
import { parseXml } from '../src/xml/nodes.js';
import { verifyWsSecuritySignature } from '../src/xml/ws-security.js';
import type { CaptureMetadata, CaptureReference } from './helpers/capture.js';
import { loadCapture, splitPemCertificates, verifyCapture } from './helpers/capture.js';
import { createTestPki } from './helpers/pki.js';
import { testValidator } from './helpers/input.js';

/**
 * A locally generated capture: the same layout as an independent capture, but
 * `origin: "local"`. It exercises the whole capture harness (open, decrypt,
 * signer validation, payload-hash, process/document-type/part and reference
 * comparison, sender-acceptance evidence, disposal) without committing any
 * credential and without claiming interoperability evidence. The Phase 6
 * validation command does not count local captures.
 */
const SENDER = { scheme: 'iso6523-actorid-upis', value: '0192:111111111' };
const RECEIVER = { scheme: 'iso6523-actorid-upis', value: '0192:222222222' };
const DOC_TYPE = {
  scheme: 'busdox-docid-qns',
  value: 'urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice##urn:cen.eu:en16931:2017::2.1',
};
const PROCESS = { scheme: 'cenbii-procid-ubl', value: 'urn:fdc:peppol.eu:2017:poacc:billing:01:1.0' };
const PAYLOAD = Buffer.from(
  '<?xml version="1.0" encoding="UTF-8"?>' +
    '<StandardBusinessDocument xmlns="http://www.unece.org/cefact/namespaces/StandardBusinessDocumentHeader">' +
    '<StandardBusinessDocumentHeader><HeaderVersion>1.0</HeaderVersion></StandardBusinessDocumentHeader>' +
    '</StandardBusinessDocument>',
  'utf8',
);

async function collect(stream: NodeJS.ReadableStream): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(Buffer.from(chunk as Uint8Array));
  return Buffer.concat(chunks);
}

/** Build a local capture (request + metadata + credentials + acceptance evidence). */
async function writeLocalCapture(dir: string, as4MessageId: string): Promise<void> {
  const now = new Date();
  const pki = createTestPki({ now });
  const capturedAt = now.toISOString();
  const workspace = await mkdtemp(join(tmpdir(), 'as4-local-capture-src-'));
  try {
    const prepared = await prepareAs4Internal(
      {
        payload: Readable.from(PAYLOAD),
        endpointUrl: 'https://ap.example/as4',
        transportProfile: 'peppol-transport-as4-v2_0',
        receiverCertificate: pki.receiver.certPem,
        senderParticipant: SENDER,
        receiverParticipant: RECEIVER,
        documentType: DOC_TYPE,
        process: PROCESS,
        as4MessageId,
        signer: signerFromKey(pki.sender.keyObject, pki.sender.certPem),
        validateCertificate: testValidator(pki),
        artifactDirectory: workspace,
        now: () => now,
      },
      defaultEntropy(),
    );
    assert.equal(prepared.outcome, 'prepared', JSON.stringify(prepared));
    if (prepared.outcome !== 'prepared') throw new Error('unreachable');
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
      const body = await collect(multipart.stream);

      // Record the reference semantics the sender actually produced, from the
      // sender's own signed envelope (independent of openAs4Message).
      const verification = verifyWsSecuritySignature(parseXml(message.soapXml));
      assert.equal(verification.ok, true, verification.ok ? '' : verification.detail);
      if (!verification.ok) throw new Error('unreachable');
      const references: CaptureReference[] = verification.signature.references.map((reference) => ({
        uri: reference.uri,
        digest: reference.digest,
        digestMethod: reference.digestMethod,
        transforms: reference.transforms.map((transform) => ({
          algorithm: transform.algorithm,
          inclusivePrefixes: [...transform.inclusivePrefixes],
        })),
      }));

      const metadata: CaptureMetadata = {
        schema: 1,
        origin: 'local',
        capturedAt,
        contentType: multipart.contentType,
        sender: { implementation: 'as4ts', version: PACKAGE_VERSION },
        transportProfile: 'peppol-transport-as4-v2_0',
        senderParticipant: { scheme: PEPPOL_PARTY_ID_TYPE, value: pki.sender.commonName },
        receiverParticipant: { scheme: PEPPOL_PARTY_ID_TYPE, value: pki.receiver.commonName },
        originalSender: SENDER,
        finalRecipient: RECEIVER,
        documentType: DOC_TYPE,
        process: PROCESS,
        expectedParts: 2,
        expectedCoverage: { messaging: true, body: true },
        expectedPayloadSha256Base64: createHash('sha256').update(PAYLOAD).digest('base64'),
        expectedSignedReferences: references,
        senderAcceptance: { accepted: true, evidenceFile: 'sender-acceptance.json' },
      };

      await mkdir(dir, { recursive: true });
      await writeFile(join(dir, 'request.bin'), body);
      await writeFile(join(dir, 'metadata.json'), JSON.stringify(metadata, null, 2));
      await writeFile(join(dir, 'receiver-cert.pem'), pki.receiver.certPem);
      await writeFile(join(dir, 'receiver-key.pem'), pki.receiver.keyPem);
      await writeFile(join(dir, 'trust-roots.pem'), pki.root.certPem);
      await writeFile(join(dir, 'trust-intermediates.pem'), pki.intermediate.certPem);

      // Record real acceptance evidence: open the capture and generate the
      // receipt, storing the exact response bytes and its hash.
      const opened = await openAs4Message({
        contentType: multipart.contentType,
        body: (async function* () {
          yield body;
        })(),
        keyHolder: keyHolderFromKey(pki.receiver.keyObject, pki.receiver.certPem),
        validateCertificate: testValidator(pki),
        receiverIdentity: { scheme: PEPPOL_PARTY_ID_TYPE, value: pki.receiver.commonName },
        now: () => now,
      });
      assert.equal(opened.ok, true, JSON.stringify(opened));
      if (!opened.ok) throw new Error('unreachable');
      try {
        const receipt = await respondAs4Message({
          kind: 'accepted',
          receipt: opened.receipt,
          decision: 'committed',
          signer: signerFromKey(pki.receiver.keyObject, pki.receiver.certPem),
          now: () => now,
        });
        assert.equal(receipt.ok, true, JSON.stringify(receipt));
        if (!receipt.ok) throw new Error('unreachable');
        await writeFile(join(dir, 'sender-acceptance-response.bin'), receipt.body);
        await writeFile(
          join(dir, 'sender-acceptance.json'),
          JSON.stringify(
            {
              implementation: 'as4ts',
              version: PACKAGE_VERSION,
              accepted: true,
              refToMessageId: opened.messageId,
              recordedAt: capturedAt,
              responseFile: 'sender-acceptance-response.bin',
              responseSha256Base64: createHash('sha256').update(receipt.body).digest('base64'),
            },
            null,
            2,
          ),
        );
      } finally {
        await opened.dispose();
      }
    } finally {
      await message.dispose();
    }
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
}

async function withCapture<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), 'as4-local-capture-'));
  try {
    await writeLocalCapture(dir, 'local-capture@as4-sender');
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test('a locally generated capture verifies end to end through openAs4Message', async () => {
  await withCapture(async (dir) => {
    const capture = loadCapture(dir, 'local');
    assert.equal(capture.metadata.origin, 'local');
    const facts = await verifyCapture(capture);
    assert.equal(facts.origin, 'local');
    assert.equal(facts.implementation, 'as4ts');
    assert.equal(facts.senderAccepted, true);
    assert.equal(facts.messageId, 'local-capture@as4-sender');
    assert.equal(facts.senderId, capture.metadata.senderParticipant.value);
    assert.equal(facts.receiverId, capture.metadata.receiverParticipant.value);
    assert.equal(facts.referenceCount, 3);
    assert.equal(facts.payloadSha256Base64, capture.metadata.expectedPayloadSha256Base64);
  });
});

test('a tampered capture is rejected before any success fact', async () => {
  await withCapture(async (dir) => {
    const capture = loadCapture(dir, 'local-tampered');
    const body = Buffer.from(capture.body);
    // Flip a byte inside the encrypted attachment (after the second boundary).
    const boundary = /boundary="?([^";]+)"?/.exec(capture.metadata.contentType);
    assert.ok(boundary?.[1], 'the capture has a boundary');
    const marker = Buffer.from(`--${boundary![1]}`, 'latin1');
    const second = body.indexOf(marker, body.indexOf(marker) + marker.length);
    assert.ok(second >= 0, 'the capture has a second part');
    body[second + 200] = body[second + 200]! ^ 0xff;
    await writeFile(join(dir, 'request.bin'), body);
    await assert.rejects(verifyCapture(loadCapture(dir, 'local-tampered')));
  });
});

test('a trust bundle whose required root is not the first block still verifies', async () => {
  await withCapture(async (dir) => {
    const decoy = createTestPki();
    const realRoot = readFileSync(join(dir, 'trust-roots.pem'), 'utf8');
    await writeFile(join(dir, 'trust-roots.pem'), `${decoy.root.certPem}\n${realRoot}`);
    const capture = loadCapture(dir, 'local-bundle');
    assert.equal(capture.roots.length, 2, 'both root certificates are loaded');
    const facts = await verifyCapture(capture);
    assert.equal(facts.senderAccepted, true);
  });
});

test('splitPemCertificates keeps every block and rejects a malformed one', () => {
  const first = createTestPki();
  const second = createTestPki();
  const blocks = splitPemCertificates(`${first.root.certPem}\n${second.root.certPem}`);
  assert.equal(blocks.length, 2);
  assert.notEqual(blocks[0], blocks[1]);
  assert.throws(() => splitPemCertificates('-----BEGIN CERTIFICATE-----\nbm90LWEtY2VydA==\n-----END CERTIFICATE-----'));
});
