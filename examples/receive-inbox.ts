#!/usr/bin/env node
/**
 * Example: a durable AS4 inbox with lost-response recovery.
 *
 * This file is an example, not part of the published package. It shows the
 * receiving contract end to end against a local sender:
 *
 *   openAs4Message     verify and unpack one inbound message (never stores, never acks)
 *   commit             the caller durably stores payload, evidence and inbox record
 *   respondAs4Message  produce the exact signed receipt bytes
 *   persist            store those bytes, then write the HTTP response
 *
 * A second delivery of the same message plays the stored receipt back
 * byte-for-byte instead of delivering the document twice. If the process
 * committed the record but crashed before persisting the response, the receipt
 * is regenerated from the retained evidence with `decision: 'already-committed'`
 * and no second business delivery.
 *
 *   npm run examples:receive
 */
import { createHash } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { createServer, request as httpsRequest } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pipeline } from 'node:stream/promises';
import { prepareAs4, transmitAs4, type PreparedMessage, type SendAs4Result } from '../src/index.js';
import {
  defaultInboundLimits,
  ebmsErrorFor,
  keyHolderFromKey,
  openAs4Message,
  respondAs4Message,
  signerFromKey,
  type InboundFailure,
  type OpenSuccess,
  type ReceiptContext,
  type RespondSuccess,
} from '../src/receive/index.js';
import { baseInput, testValidator } from '../test/helpers/input.js';
import { createTestPki, createTlsServerCert } from '../test/helpers/pki.js';

const DEADLINE_MS = 15_000;
const RECEIVER_IDENTITY_SCHEME = 'urn:fdc:peppol.eu:2017:identifiers:ap';

/** A persisted inbox record: the durable acceptance a receipt attests to. */
interface InboxRecord {
  readonly schema: 1;
  readonly messageId: string;
  readonly senderId: string;
  readonly receiverId: string;
  /** Stable identity of the verified signed content (not a hash of the wire bytes). */
  readonly contentKey: string;
  readonly receipt: ReceiptContext;
  readonly committedAt: string;
}

/**
 * Bind a duplicate to the *verified* signed content: the authenticated
 * references and their digests, not the MIME packing or ciphertext, which differ
 * across legitimate retransmissions.
 */
function signedContentKey(receipt: ReceiptContext): string {
  const hash = createHash('sha256');
  for (const reference of [...receipt.signedReferences].sort((a, b) => a.uri.localeCompare(b.uri))) {
    hash.update(reference.uri).update('\u0000').update(reference.digest).update('\u0000');
    for (const transform of reference.transforms) {
      hash.update(transform.algorithm).update(' ').update(transform.inclusivePrefixes.join(' ')).update('\u0000');
    }
    hash.update('\n');
  }
  return hash.digest('base64');
}

/**
 * A minimal durable inbox: payload, evidence, receipt context and the exact
 * response bytes on disk, with an in-memory index rebuilt from disk on restart.
 * The message id is hashed to a directory name so a hostile id cannot escape the
 * root.
 */
class DurableInbox {
  private readonly index = new Map<string, InboxRecord>();
  deliveries = 0;

  constructor(private readonly root: string) {}

  private dir(messageId: string): string {
    return join(this.root, createHash('sha256').update(messageId).digest('hex'));
  }

  get(messageId: string): InboxRecord | undefined {
    return this.index.get(messageId);
  }

  /** Rebuild the index from committed records (crash/restart recovery). */
  async load(): Promise<void> {
    const entries = await readdir(this.root, { withFileTypes: true }).catch(() => []);
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      try {
        const record = JSON.parse(await readFile(join(this.root, entry.name, 'inbox.json'), 'utf8')) as InboxRecord;
        this.index.set(record.messageId, record);
      } catch {
        // Partial or unrelated directory: not a committed record.
      }
    }
  }

  async commit(opened: OpenSuccess, contentKey: string): Promise<InboxRecord> {
    const dir = this.dir(opened.messageId);
    await mkdir(dir, { recursive: true });
    await pipeline(opened.payload.read(), createWriteStream(join(dir, 'payload.bin'), { mode: 0o600 }));
    await writeFile(join(dir, 'envelope.bin'), opened.evidence.envelopeBytes);
    await writeFile(join(dir, 'signer.pem'), opened.evidence.signerCertificate, { mode: 0o600 });
    const record: InboxRecord = {
      schema: 1,
      messageId: opened.messageId,
      senderId: opened.senderId,
      receiverId: opened.receiverId,
      contentKey,
      receipt: opened.receipt,
      committedAt: new Date().toISOString(),
    };
    await writeFile(join(dir, 'inbox.json'), JSON.stringify(record, null, 2));
    this.index.set(record.messageId, record);
    this.deliveries += 1;
    return record;
  }

  async saveResponse(messageId: string, response: RespondSuccess): Promise<void> {
    const dir = this.dir(messageId);
    await writeFile(join(dir, 'response.body'), response.body, { mode: 0o600 });
    await writeFile(
      join(dir, 'response.json'),
      JSON.stringify({ status: response.status, contentType: response.contentType, headers: response.headers }),
    );
  }

  async response(
    messageId: string,
  ): Promise<{ status: number; contentType: string; headers: Record<string, string>; body: Buffer } | null> {
    try {
      const meta = JSON.parse(await readFile(join(this.dir(messageId), 'response.json'), 'utf8')) as {
        status: number;
        contentType: string;
        headers: Record<string, string>;
      };
      const body = await readFile(join(this.dir(messageId), 'response.body'));
      return { ...meta, body };
    } catch {
      return null;
    }
  }

  /** Simulate losing the persisted response (e.g. a crash between respond and write). */
  async forgetResponse(messageId: string): Promise<void> {
    await rm(join(this.dir(messageId), 'response.body'), { force: true });
    await rm(join(this.dir(messageId), 'response.json'), { force: true });
  }
}

interface Deps {
  readonly inbox: DurableInbox;
  readonly keyHolder: ReturnType<typeof keyHolderFromKey>;
  readonly validateCertificate: ReturnType<typeof testValidator>;
  readonly signer: ReturnType<typeof signerFromKey>;
  readonly receiverIdentity: { scheme: string; value: string };
}

async function handle(req: IncomingMessage, res: ServerResponse, deps: Deps): Promise<void> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DEADLINE_MS);
  try {
    const contentType = req.headers['content-type'];
    const opened = await openAs4Message({
      contentType: typeof contentType === 'string' ? contentType : undefined,
      body: req,
      keyHolder: deps.keyHolder,
      validateCertificate: deps.validateCertificate,
      receiverIdentity: deps.receiverIdentity,
      limits: defaultInboundLimits,
      signal: controller.signal,
      now: () => new Date(),
    });
    if (!opened.ok) return reject(res, opened, deps);
    await accept(res, opened, deps);
  } finally {
    clearTimeout(timer);
  }
}

/** Answer a failed open: a signed ebMS error when trustworthy correlation exists. */
async function reject(res: ServerResponse, failure: InboundFailure, deps: Deps): Promise<void> {
  if (failure.answerable && failure.correlation) {
    const response = await respondAs4Message({
      kind: 'rejected',
      correlation: failure.correlation,
      error: ebmsErrorFor(failure),
      signer: deps.signer,
      now: () => new Date(),
    });
    if (response.ok) return write(res, response);
  }
  // No trustworthy correlation: a transport rejection, never an invented ebMS error.
  send(res, 400, `rejected: ${failure.stage}/${failure.reason}`);
}

async function accept(res: ServerResponse, opened: OpenSuccess, deps: Deps): Promise<void> {
  const contentKey = signedContentKey(opened.receipt);
  const existing = deps.inbox.get(opened.messageId);

  if (existing) {
    await opened.dispose();
    if (existing.contentKey !== contentKey) {
      // Same id, different verified content: reject the conflicting reuse and do
      // not substitute the earlier receipt.
      return send(res, 409, `conflicting reuse of ${opened.messageId}`);
    }
    const stored = await deps.inbox.response(opened.messageId);
    if (stored) {
      res.writeHead(stored.status, { 'content-type': stored.contentType, ...stored.headers });
      res.end(stored.body);
      return;
    }
    // Committed, but the response was lost before it was persisted: regenerate a
    // receipt from the retained evidence, with no second delivery.
    const regenerated = await respondAs4Message({
      kind: 'accepted',
      receipt: existing.receipt,
      decision: 'already-committed',
      signer: deps.signer,
      now: () => new Date(),
    });
    if (!regenerated.ok) return send(res, 500, `receipt recovery failed: ${regenerated.reason}`);
    await deps.inbox.saveResponse(opened.messageId, regenerated);
    return write(res, regenerated);
  }

  // New message: commit before acknowledging, then acknowledge, then persist the
  // exact response bytes before writing them.
  const record = await deps.inbox.commit(opened, contentKey);
  const response = await respondAs4Message({
    kind: 'accepted',
    receipt: record.receipt,
    decision: 'committed',
    signer: deps.signer,
    now: () => new Date(),
  });
  await opened.dispose();
  if (!response.ok) return send(res, 500, `receipt generation failed: ${response.reason}`);
  await deps.inbox.saveResponse(opened.messageId, response);
  write(res, response);
}

function write(res: ServerResponse, response: RespondSuccess): void {
  res.writeHead(response.status, { 'content-type': response.contentType, ...response.headers });
  res.end(Buffer.from(response.body));
}

function send(res: ServerResponse, status: number, text: string): void {
  res.writeHead(status, { 'content-type': 'text/plain; charset=utf-8' });
  res.end(text);
}

function listen(server: ReturnType<typeof createServer>): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, () => {
      const address = server.address();
      if (address && typeof address === 'object') resolve(address.port);
      else reject(new Error('no server address'));
    });
  });
}

function transmit(
  message: PreparedMessage,
  pki: ReturnType<typeof createTestPki>,
  caPem: string,
): Promise<SendAs4Result> {
  return transmitAs4({
    message,
    validateCertificate: testValidator(pki),
    http: { connectMs: 5_000, totalMs: DEADLINE_MS, ca: [caPem] },
    now: () => new Date(),
  });
}

/** POST a non-AS4 body so the endpoint returns a transport rejection. */
function postRaw(url: string, caPem: string, contentType: string, body: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const target = new URL(url);
    const request = httpsRequest(
      {
        hostname: target.hostname,
        port: target.port,
        path: target.pathname,
        method: 'POST',
        ca: [caPem],
        headers: { 'content-type': contentType, 'content-length': Buffer.byteLength(body) },
      },
      (res) => {
        res.resume();
        resolve(res.statusCode ?? 0);
      },
    );
    request.on('error', reject);
    request.end(body);
  });
}

async function main(): Promise<void> {
  const pki = createTestPki();
  const tls = createTlsServerCert();
  const root = await mkdtemp(join(tmpdir(), 'as4-inbox-'));

  await mkdir(join(root, 'inbox'), { recursive: true });
  const inbox = new DurableInbox(join(root, 'inbox'));
  await inbox.load();

  const deps: Deps = {
    inbox,
    keyHolder: keyHolderFromKey(pki.receiver.keyObject, pki.receiver.certPem),
    validateCertificate: testValidator(pki),
    signer: signerFromKey(pki.receiver.keyObject, pki.receiver.certPem),
    receiverIdentity: { scheme: RECEIVER_IDENTITY_SCHEME, value: pki.receiver.commonName },
  };

  const server = createServer({ cert: tls.certPem, key: tls.keyPem }, (req, res) => {
    handle(req, res, deps).catch((err: unknown) => send(res, 500, String(err)));
  });
  const port = await listen(server);
  const url = `https://localhost:${port}/as4`;
  console.log(`durable inbox listening on ${url}`);

  const prepared = await prepareAs4(baseInput(pki, url, tls.caPem, { as4MessageId: 'inbox-demo@as4-sender' }));
  if (prepared.outcome !== 'prepared') {
    console.error(`prepare failed: ${prepared.outcome} ${prepared.reason}`);
    server.close();
    await rm(root, { recursive: true, force: true });
    process.exit(1);
  }

  try {
    // 1. First delivery: verify, commit, respond, persist.
    const first = await transmit(prepared.message, pki, tls.caPem);
    console.log(`first delivery:   ${first.outcome}  (deliveries=${inbox.deliveries})`);

    // 2. Same message again: the stored receipt is replayed byte-for-byte.
    const second = await transmit(prepared.message, pki, tls.caPem);
    const replayed =
      first.outcome === 'receipt-verified' &&
      second.outcome === 'receipt-verified' &&
      Buffer.from(first.receipt.raw).equals(Buffer.from(second.receipt.raw));
    console.log(`duplicate:        ${second.outcome}  replay=${replayed}  (deliveries=${inbox.deliveries})`);

    // 3. Committed but response lost: regenerate from retained evidence.
    await inbox.forgetResponse(prepared.message.as4MessageId);
    const third = await transmit(prepared.message, pki, tls.caPem);
    console.log(`lost response:    ${third.outcome}  recovered  (deliveries=${inbox.deliveries})`);

    // 4. A malformed request is a transport rejection, not an invented ebMS error.
    const malformedStatus = await postRaw(url, tls.caPem, 'text/plain', 'not as4');
    console.log(`malformed upload: HTTP ${malformedStatus}`);

    const ok = replayed && inbox.deliveries === 1 && malformedStatus === 400;
    await prepared.message.dispose();
    server.close();
    await rm(root, { recursive: true, force: true });
    process.exit(ok ? 0 : 1);
  } catch (err) {
    await prepared.message.dispose().catch(() => {});
    server.close();
    await rm(root, { recursive: true, force: true });
    throw err;
  }
}

await main();
