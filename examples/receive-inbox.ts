#!/usr/bin/env node
/**
 * Example: a durable AS4 inbox with duplicate suppression and lost-response
 * recovery.
 *
 * This file is an example, not part of the published package. It shows the
 * receiving contract end to end against a local sender:
 *
 *   openAs4Message     verify and unpack one inbound message (never stores, never acks)
 *   commit             the caller durably stores payload, evidence and inbox record
 *   respondAs4Message  produce the exact signed receipt bytes
 *   persist            store those bytes, then write the HTTP response
 *
 * The inbox demonstrates: commit before acknowledging; atomic, fsynced
 * publication of the committed record and the response; per-MessageId
 * serialization so a concurrent duplicate is delivered once; rejection of
 * conflicting reuse of an id; replay of the stored receipt on a duplicate; and
 * regeneration from retained evidence when the response was lost — including
 * rebuilding the index from disk as a restart would.
 *
 *   npm run examples:receive
 */
import { createHash, randomUUID } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import { mkdir, mkdtemp, open, readFile, readdir, rename, rm } from 'node:fs/promises';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { createServer, request as httpsRequest } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import type { Readable as ReadableStream } from 'node:stream';
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

/** The authenticated compressed/original representation metadata retained as evidence. */
interface RepresentationFacts {
  readonly mediaType: string;
  readonly byteLength: number;
  readonly rawDigestBase64: string;
  readonly transformDigestBase64: string;
}

/** A persisted inbox record: the durable acceptance a receipt attests to. */
interface InboxRecord {
  readonly schema: 1;
  readonly messageId: string;
  readonly senderId: string;
  readonly receiverId: string;
  /** Stable identity of the verified signed content (not a hash of the wire bytes). */
  readonly contentKey: string;
  readonly representation: RepresentationFacts;
  readonly receipt: ReceiptContext;
  readonly committedAt: string;
}

interface StoredResponse {
  readonly status: number;
  readonly contentType: string;
  readonly headers: Record<string, string>;
  readonly body: Buffer;
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

/** Write bytes to a fresh file, fsync its contents, then close it. */
async function durableWrite(path: string, data: string | Uint8Array): Promise<void> {
  const handle = await open(path, 'w', 0o600);
  try {
    await handle.writeFile(data);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

/** Stream a source into `dir/name`, fsync its contents, then close it. */
async function durableStream(dir: string, name: string, source: ReadableStream): Promise<void> {
  const path = join(dir, name);
  await pipeline(source, createWriteStream(path, { mode: 0o600 }));
  const handle = await open(path, 'r');
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

/** fsync a directory so a rename survives a crash. Best-effort across platforms. */
async function syncDir(path: string): Promise<void> {
  try {
    const handle = await open(path, 'r');
    try {
      await handle.sync();
    } finally {
      await handle.close();
    }
  } catch {
    // Some platforms/filesystems do not permit fsync on a directory handle.
  }
}

/**
 * A durable inbox: payload, representation, evidence, receipt context and the
 * exact response bytes on disk, published atomically, with an in-memory index
 * rebuilt from disk on restart. The message id is hashed to a directory name so
 * a hostile id cannot escape the root.
 */
class DurableInbox {
  private readonly index = new Map<string, InboxRecord>();
  private readonly locks = new Map<string, Promise<void>>();
  deliveries = 0;
  conflicts = 0;

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

  /** Drop the in-memory index and rebuild it from disk, as after a process restart. */
  async reload(): Promise<void> {
    this.index.clear();
    await this.load();
  }

  /**
   * Serialize all work for one MessageId so lookup -> commit -> response
   * persistence is atomic with respect to concurrent deliveries of the same
   * message. A production store must also enforce a transactional unique
   * constraint on the authenticated id.
   */
  async run<T>(messageId: string, task: () => Promise<T>): Promise<T> {
    const key = this.dir(messageId);
    const prior = this.locks.get(key) ?? Promise.resolve();
    const result = prior.then(() => task());
    const tail = result.then(
      () => undefined,
      () => undefined,
    );
    this.locks.set(key, tail);
    try {
      return await result;
    } finally {
      if (this.locks.get(key) === tail) this.locks.delete(key);
    }
  }

  /**
   * Stage the whole record, fsync it, then publish it with a single atomic
   * rename and fsync the parent. The record only becomes visible to a restart
   * once every byte it references is durable.
   */
  async commit(opened: OpenSuccess, contentKey: string): Promise<InboxRecord> {
    const dir = this.dir(opened.messageId);
    const staging = `${dir}.staging-${randomUUID()}`;
    await mkdir(staging, { recursive: true });
    await durableStream(staging, 'payload.bin', opened.payload.read());
    // The signature authenticates these bytes; recompressing the payload cannot
    // reproduce them, so retain the original representation verbatim.
    await durableStream(staging, 'representation.bin', opened.representation.read());
    await durableWrite(join(staging, 'envelope.bin'), opened.evidence.envelopeBytes);
    await durableWrite(join(staging, 'signer.pem'), opened.evidence.signerCertificate);
    const record: InboxRecord = {
      schema: 1,
      messageId: opened.messageId,
      senderId: opened.senderId,
      receiverId: opened.receiverId,
      contentKey,
      representation: {
        mediaType: opened.representation.mediaType,
        byteLength: opened.representation.byteLength,
        rawDigestBase64: opened.representation.rawDigestBase64,
        transformDigestBase64: opened.representation.transformDigestBase64,
      },
      receipt: opened.receipt,
      committedAt: new Date().toISOString(),
    };
    await durableWrite(join(staging, 'inbox.json'), JSON.stringify(record, null, 2));
    await syncDir(staging);
    await rename(staging, dir);
    await syncDir(this.root);
    this.index.set(record.messageId, record);
    this.deliveries += 1;
    return record;
  }

  /** Publish the exact response bytes as one atomic file, fsynced. */
  async saveResponse(messageId: string, response: RespondSuccess): Promise<void> {
    const dir = this.dir(messageId);
    const staging = `${dir}.response-${randomUUID()}`;
    await mkdir(staging, { recursive: true });
    const published = JSON.stringify({
      status: response.status,
      contentType: response.contentType,
      headers: response.headers,
      bodyBase64: Buffer.from(response.body).toString('base64'),
    });
    await durableWrite(join(staging, 'response.json'), published);
    await syncDir(staging);
    await rename(join(staging, 'response.json'), join(dir, 'response.json'));
    await syncDir(dir);
    await rm(staging, { recursive: true, force: true });
  }

  async response(messageId: string): Promise<StoredResponse | null> {
    try {
      const parsed = JSON.parse(await readFile(join(this.dir(messageId), 'response.json'), 'utf8')) as {
        status: number;
        contentType: string;
        headers: Record<string, string>;
        bodyBase64: string;
      };
      return {
        status: parsed.status,
        contentType: parsed.contentType,
        headers: parsed.headers,
        body: Buffer.from(parsed.bodyBase64, 'base64'),
      };
    } catch {
      return null;
    }
  }

  /** Simulate losing the persisted response (e.g. a crash between respond and write). */
  async forgetResponse(messageId: string): Promise<void> {
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
  const messageId = opened.messageId;
  const contentKey = signedContentKey(opened.receipt);
  try {
    await deps.inbox.run(messageId, async () => {
      const existing = deps.inbox.get(messageId);
      if (existing) {
        if (existing.contentKey !== contentKey) {
          // Same id, different verified content: reject the conflicting reuse and
          // do not substitute the earlier receipt.
          deps.inbox.conflicts += 1;
          send(res, 409, `conflicting reuse of ${messageId}`);
          return;
        }
        const stored = await deps.inbox.response(messageId);
        if (stored) {
          res.writeHead(stored.status, { 'content-type': stored.contentType, ...stored.headers });
          res.end(stored.body);
          return;
        }
        // Committed, but the response was lost before it was persisted: regenerate
        // from the retained evidence, with no second delivery.
        const regenerated = await respondAs4Message({
          kind: 'accepted',
          receipt: existing.receipt,
          decision: 'already-committed',
          signer: deps.signer,
          now: () => new Date(),
        });
        if (!regenerated.ok) return send(res, 500, `receipt recovery failed: ${regenerated.reason}`);
        await deps.inbox.saveResponse(messageId, regenerated);
        return write(res, regenerated);
      }

      // New message: commit before acknowledging, then acknowledge, then persist
      // the exact response bytes before writing them.
      const record = await deps.inbox.commit(opened, contentKey);
      const generated = await respondAs4Message({
        kind: 'accepted',
        receipt: record.receipt,
        decision: 'committed',
        signer: deps.signer,
        now: () => new Date(),
      });
      if (!generated.ok) return send(res, 500, `receipt generation failed: ${generated.reason}`);
      await deps.inbox.saveResponse(messageId, generated);
      write(res, generated);
    });
  } finally {
    // Every acceptance path — including a rejected commit or a conflict — releases
    // the opened handles.
    await opened.dispose();
  }
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

function receiptBytes(result: SendAs4Result): Buffer | null {
  return result.outcome === 'receipt-verified' ? Buffer.from(result.receipt.raw) : null;
}

async function prepare(
  pki: ReturnType<typeof createTestPki>,
  url: string,
  caPem: string,
  as4MessageId: string,
  payloadXml: string,
): Promise<PreparedMessage> {
  const prepared = await prepareAs4(
    baseInput(pki, url, caPem, { as4MessageId, payload: Readable.from(Buffer.from(payloadXml, 'utf8')) }),
  );
  if (prepared.outcome !== 'prepared') throw new Error(`prepare failed: ${prepared.outcome} ${prepared.reason}`);
  return prepared.message;
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

  const messages: PreparedMessage[] = [];
  let ok = false;
  try {
    const a = await prepare(pki, url, tls.caPem, 'inbox-demo@as4-sender', '<?xml version="1.0"?><doc>a</doc>');
    messages.push(a);

    // 1. First delivery: verify, commit, respond, persist.
    const first = await transmit(a, pki, tls.caPem);
    console.log(`first delivery:   ${first.outcome}  (deliveries=${inbox.deliveries})`);

    // 2. Same message again: the stored receipt is replayed byte-for-byte.
    const second = await transmit(a, pki, tls.caPem);
    const firstBytes = receiptBytes(first);
    const replayed = firstBytes !== null && firstBytes.equals(receiptBytes(second) ?? Buffer.alloc(0));
    console.log(`duplicate:        ${second.outcome}  replay=${replayed}  (deliveries=${inbox.deliveries})`);

    // 3. Restart + lost response: rebuild the index from disk and regenerate the
    // receipt from retained evidence. Two concurrent deliveries must still
    // deliver once and replay the same recovered receipt.
    await inbox.forgetResponse(a.as4MessageId);
    await inbox.reload();
    const recovered = await Promise.all([transmit(a, pki, tls.caPem), transmit(a, pki, tls.caPem)]);
    const recoveredBytes = recovered.map(receiptBytes);
    const recoveryOk = recoveredBytes.every((bytes) => bytes !== null) && recoveredBytes[0]!.equals(recoveredBytes[1]!);
    console.log(
      `lost response:    ${recovered[0]!.outcome}/${recovered[1]!.outcome}  concurrent-recovery=${recoveryOk}  (deliveries=${inbox.deliveries})`,
    );

    // 4. Concurrent first delivery of a new message: serialized to one commit.
    const b = await prepare(pki, url, tls.caPem, 'concurrent@as4-sender', '<?xml version="1.0"?><doc>b</doc>');
    messages.push(b);
    const concurrent = await Promise.all([transmit(b, pki, tls.caPem), transmit(b, pki, tls.caPem)]);
    const concurrentBytes = concurrent.map(receiptBytes);
    const concurrentOk =
      concurrentBytes.every((bytes) => bytes !== null) && concurrentBytes[0]!.equals(concurrentBytes[1]!);
    console.log(
      `concurrent new:   ${concurrent[0]!.outcome}/${concurrent[1]!.outcome}  single-delivery=${concurrentOk}  (deliveries=${inbox.deliveries})`,
    );

    // 5. Concurrent conflicting reuse of an id with different signed content: the
    // first commitment wins and the other is rejected.
    const c1 = await prepare(pki, url, tls.caPem, 'conflict@as4-sender', '<?xml version="1.0"?><doc>one</doc>');
    const c2 = await prepare(pki, url, tls.caPem, 'conflict@as4-sender', '<?xml version="1.0"?><doc>two</doc>');
    messages.push(c1, c2);
    await Promise.all([transmit(c1, pki, tls.caPem), transmit(c2, pki, tls.caPem)]);
    console.log(`conflict:         rejected=${inbox.conflicts === 1}  (deliveries=${inbox.deliveries})`);

    // 6. A malformed upload is a transport rejection, not an invented ebMS error.
    const malformedStatus = await postRaw(url, tls.caPem, 'text/plain', 'not as4');
    console.log(`malformed upload: HTTP ${malformedStatus}`);

    ok =
      replayed &&
      recoveryOk &&
      concurrentOk &&
      inbox.deliveries === 3 &&
      inbox.conflicts === 1 &&
      malformedStatus === 400;
  } finally {
    for (const message of messages) await message.dispose().catch(() => {});
    server.close();
    await rm(root, { recursive: true, force: true });
  }
  process.exit(ok ? 0 : 1);
}

await main();
