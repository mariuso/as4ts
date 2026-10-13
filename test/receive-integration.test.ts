import test from 'node:test';
import assert from 'node:assert/strict';
import { constants, privateDecrypt } from 'node:crypto';
import { existsSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { PEPPOL_PARTY_ID_TYPE } from '../src/constants.js';
import { signerFromKey } from '../src/index.js';
import { defaultEntropy, prepareAs4Internal } from '../src/internal.js';
import { buildMultipartBody } from '../src/multipart.js';
import { openAs4Message } from '../src/receive/open.js';
import { multipartHooks } from '../src/receive/multipart.js';
import { payloadHooks } from '../src/receive/payload-hooks.js';
import type { InboundKeyHolder, OpenAs4MessageInput } from '../src/receive/types.js';
import { createTestPki } from './helpers/pki.js';
import { testValidator } from './helpers/input.js';

/**
 * Integration: `open` uses the incremental MIME parser, transfers the ciphertext
 * spool into recovery's workspace with a single rename (no second copy), and owns
 * cleanup across the transfer boundary — the parser before the rename, recovery
 * afterwards.
 */
const pki = createTestPki();
const SENDER = { scheme: 'iso6523-actorid-upis', value: '0192:111111111' };
const RECEIVER = { scheme: 'iso6523-actorid-upis', value: '0192:222222222' };
const DOC_TYPE = {
  scheme: 'busdox-docid-qns',
  value: 'urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice##urn:cen.eu:en16931:2017::2.1',
};
const PROCESS = { scheme: 'cenbii-procid-ubl', value: 'urn:fdc:peppol.eu:2017:poacc:billing:01:1.0' };

const holder: InboundKeyHolder = {
  certificate: pki.receiver.certPem,
  async unwrap(wrapped) {
    return privateDecrypt(
      { key: pki.receiver.keyObject, oaepHash: 'sha256', padding: constants.RSA_PKCS1_OAEP_PADDING },
      Buffer.from(wrapped),
    );
  },
};

function sbdhDocument(senderIdentifier: string): Buffer {
  return Buffer.from(
    '<?xml version="1.0" encoding="UTF-8"?>' +
      '<StandardBusinessDocument xmlns="http://www.unece.org/cefact/namespaces/StandardBusinessDocumentHeader">' +
      '<StandardBusinessDocumentHeader><HeaderVersion>1.0</HeaderVersion>' +
      `<Sender><Identifier Authority="${SENDER.scheme}">${senderIdentifier}</Identifier></Sender>` +
      `<Receiver><Identifier Authority="${RECEIVER.scheme}">${RECEIVER.value}</Identifier></Receiver>` +
      '<DocumentIdentification><Standard>urn:oasis</Standard><Type>Invoice</Type></DocumentIdentification>' +
      '<BusinessScope>' +
      `<Scope><Type>PROCESSID</Type><InstanceIdentifier>${PROCESS.value}</InstanceIdentifier><Identifier>${PROCESS.scheme}</Identifier></Scope>` +
      `<Scope><Type>DOCUMENTID</Type><InstanceIdentifier>${DOC_TYPE.value}</InstanceIdentifier><Identifier>${DOC_TYPE.scheme}</Identifier></Scope>` +
      '</BusinessScope>' +
      '</StandardBusinessDocumentHeader>' +
      '</StandardBusinessDocument>',
    'utf8',
  );
}

async function buildRequest(payload: Buffer, dir: string): Promise<{ contentType: string; body: Buffer }> {
  const prepared = await prepareAs4Internal(
    {
      payload: Readable.from(payload),
      endpointUrl: 'https://ap.example/as4',
      transportProfile: 'peppol-transport-as4-v2_0',
      receiverCertificate: pki.receiver.certPem,
      senderParticipant: SENDER,
      receiverParticipant: RECEIVER,
      documentType: DOC_TYPE,
      process: PROCESS,
      as4MessageId: 'integration@as4-sender',
      signer: signerFromKey(pki.sender.keyObject, pki.sender.certPem),
      validateCertificate: testValidator(pki),
      artifactDirectory: dir,
      now: () => new Date(),
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
    const chunks: Buffer[] = [];
    for await (const chunk of multipart.stream) chunks.push(chunk as Buffer);
    return { contentType: multipart.contentType, body: Buffer.concat(chunks) };
  } finally {
    await message.dispose();
  }
}

function openInput(
  request: { contentType: string; body: Buffer },
  overrides: Partial<OpenAs4MessageInput> = {},
): OpenAs4MessageInput {
  return {
    contentType: request.contentType,
    body: (async function* () {
      yield request.body;
    })(),
    keyHolder: [holder],
    validateCertificate: testValidator(pki),
    receiverIdentity: { scheme: PEPPOL_PARTY_ID_TYPE, value: pki.receiver.commonName },
    now: () => new Date(),
    ...overrides,
  };
}

async function withRequest<T>(fn: (request: { contentType: string; body: Buffer }) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), 'as4-integration-'));
  try {
    return await fn(await buildRequest(sbdhDocument(SENDER.value), dir));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

async function collect(stream: NodeJS.ReadableStream): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(Buffer.from(chunk as Uint8Array));
  return Buffer.concat(chunks);
}

test('open transfers the ciphertext spool without a second copy', async () => {
  await withRequest(async (request) => {
    const ciphertextWrites: string[] = [];
    const transfers: Array<[string, string]> = [];
    let workspace: string | null = null;
    payloadHooks.onWriteStream = (path) => {
      if (path.endsWith('ciphertext.bin')) ciphertextWrites.push(path);
    };
    payloadHooks.onSpoolTransfer = (from, to) => transfers.push([from, to]);
    payloadHooks.onWorkspace = (dir) => {
      workspace = dir;
    };
    try {
      const result = await openAs4Message(openInput(request));
      assert.equal(result.ok, true, JSON.stringify(result));
      if (result.ok) await result.dispose();
      assert.equal(transfers.length, 1, 'exactly one transfer happened');
      assert.deepEqual(ciphertextWrites, [], 'the ciphertext was moved, not written again');
      assert.ok(
        workspace !== null && transfers[0]![1].startsWith(workspace),
        'the destination is the recovery workspace',
      );
      assert.equal(existsSync(transfers[0]![0]), false, 'the parser spool is gone after the move');
    } finally {
      delete payloadHooks.onWriteStream;
      delete payloadHooks.onSpoolTransfer;
      delete payloadHooks.onWorkspace;
    }
  });
});

test('a pre-transfer failure removes parser-owned spools', async () => {
  await withRequest(async (request) => {
    let parserDir: string | null = null;
    multipartHooks.onDirectory = (dir) => {
      parserDir = dir;
    };
    try {
      // A wrong recipient fails at identity binding, before recovery.
      const result = await openAs4Message(
        openInput(request, { receiverIdentity: { scheme: PEPPOL_PARTY_ID_TYPE, value: 'POP999999' } }),
      );
      assert.equal(result.ok, false);
      if (!result.ok) assert.equal(result.reason, 'addressing.party-mismatch');
      assert.ok(parserDir !== null, 'the parser created a private spool directory');
      assert.equal(existsSync(parserDir!), false, 'the parser removed its directory on failure');
    } finally {
      delete multipartHooks.onDirectory;
    }
  });
});

test('a post-transfer failure removes recovery-owned files', async () => {
  await withRequest(async (request) => {
    // Tamper the ciphertext so GCM authentication fails after the transfer.
    const boundary = /boundary="?([^";]+)"?/.exec(request.contentType)?.[1];
    assert.ok(boundary, 'the request has a boundary');
    const marker = Buffer.from(`--${boundary}`, 'latin1');
    const body = Buffer.from(request.body);
    const second = body.indexOf(marker, body.indexOf(marker) + marker.length);
    body[second + 200] = body[second + 200]! ^ 0xff;

    let workspace: string | null = null;
    payloadHooks.onWorkspace = (dir) => {
      workspace = dir;
    };
    try {
      const result = await openAs4Message(openInput({ ...request, body }));
      assert.equal(result.ok, false);
      if (!result.ok) assert.equal(result.stage, 'decrypt');
      assert.ok(workspace !== null, 'recovery created its workspace');
      assert.equal(existsSync(workspace!), false, 'recovery removed its workspace after the failure');
    } finally {
      delete payloadHooks.onWorkspace;
    }
  });
});

test('parser disposal leaves the returned payload and representation handles usable', async () => {
  await withRequest(async (request) => {
    const document = sbdhDocument(SENDER.value);
    const result = await openAs4Message(openInput(request));
    assert.equal(result.ok, true, JSON.stringify(result));
    if (!result.ok) return;
    try {
      // open already disposed the MIME parser; the recovery-owned handles remain.
      assert.deepEqual(await collect(result.payload.read()), document);
      assert.ok(result.representation.byteLength > 0, 'the authenticated representation is readable');
      assert.ok((await collect(result.representation.read())).length > 0);
    } finally {
      await result.dispose();
    }
  });
});

test('the configured spool root is used by MIME parsing and recovery', async () => {
  const root = mkdtempSync(join(tmpdir(), 'as4-spoolroot-'));
  try {
    await withRequest(async (request) => {
      const parserDirs: string[] = [];
      const workspaces: string[] = [];
      const transfers: Array<[string, string]> = [];
      multipartHooks.onDirectory = (dir) => parserDirs.push(dir);
      payloadHooks.onWorkspace = (dir) => workspaces.push(dir);
      payloadHooks.onSpoolTransfer = (from, to) => {
        transfers.push([from, to]);
      };
      try {
        const result = await openAs4Message(openInput(request, { spoolDirectory: root }));
        assert.equal(result.ok, true, JSON.stringify(result));
        if (result.ok) await result.dispose();
        assert.equal(parserDirs.length, 1, 'the parser created a spool directory');
        assert.ok(parserDirs[0]!.startsWith(root), `parser dir ${parserDirs[0]} is under the configured root`);
        assert.equal(workspaces.length, 1, 'recovery created a workspace');
        assert.ok(workspaces[0]!.startsWith(root), `workspace ${workspaces[0]} is under the configured root`);
        assert.equal(transfers.length, 1, 'one transfer happened');
        assert.ok(
          transfers[0]![0].startsWith(root) && transfers[0]![1].startsWith(root),
          'the rename stays within the configured root (same filesystem)',
        );
        assert.deepEqual(readdirSync(root), [], 'the configured root is left clean');
      } finally {
        delete multipartHooks.onDirectory;
        delete payloadHooks.onWorkspace;
        delete payloadHooks.onSpoolTransfer;
      }
    });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
