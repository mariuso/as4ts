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
 * Durability model
 * ----------------
 * A message is committed by staging every file, fsyncing the file contents and
 * the staging directory, then publishing the record directory with a single
 * atomic rename and fsyncing the parent. The response is published the same way,
 * and only then is a separate confirmation marker written and synced. A
 * directory-sync failure is an error: `commit` and `saveResponse` only report
 * success once the durability step has succeeded, so a receipt cannot be issued
 * for bytes that are not yet durable.
 *
 * "Published, durability unconfirmed" is an explicit recoverable state. A
 * response is replayed only once its confirmation marker exists; visibility of
 * the response file alone never establishes durability, so a retry after a
 * failed response sync regenerates and re-syncs rather than replaying the
 * unconfirmed bytes. If a commit renamed the record directory but failed the
 * parent sync, a retry reconciles the already-published record — validating its
 * identity and content, retrying the sync, then indexing it — instead of
 * overwriting it (which would fail with ENOTEMPTY).
 *
 * On a filesystem that cannot fsync a directory, construct the inbox with
 * `{ directorySync: 'none' }` to select an explicitly weaker mode (documented as
 * such); the default is `'fsync'`. On restart, `load` indexes only canonical
 * published directories whose name is the hash of the record's MessageId;
 * staging directories from an interrupted commit are never treated as committed,
 * and `sweepStaging` removes them.
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
const CANONICAL_DIR = /^[0-9a-f]{64}$/;

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

/** Seams for the example's crash/failure scenarios. Production code has no hooks. */
interface InboxHooks {
  /** Runs after staging is fsynced but before the atomic rename (crash simulation). */
  readonly beforePublish?: () => void | Promise<void>;
  /** Runs before each directory fsync, to inject a sync failure. */
  readonly beforeDirectorySync?: (path: string) => void | Promise<void>;
}

interface InboxOptions {
  /**
   * `fsync` (default) propagates directory-sync failures. `none` skips directory
   * fsync entirely: an explicitly weaker durability mode for filesystems that
   * cannot fsync a directory.
   */
  readonly directorySync?: 'fsync' | 'none';
  readonly hooks?: InboxHooks;
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

/**
 * A durable inbox: payload, representation, evidence, receipt context and the
 * exact response bytes on disk, published atomically, with an in-memory index
 * rebuilt from disk on restart. The message id is hashed to a directory name so
 * a hostile id cannot escape the root.
 */
class DurableInbox {
  private readonly index = new Map<string, InboxRecord>();
  private readonly locks = new Map<string, Promise<void>>();
  /** Message ids whose persisted response has had its durability confirmed. */
  private readonly confirmedResponses = new Set<string>();
  private readonly directorySync: 'fsync' | 'none';
  private readonly hooks: InboxHooks;
  deliveries = 0;
  conflicts = 0;

  constructor(
    private readonly root: string,
    options: InboxOptions = {},
  ) {
    this.directorySync = options.directorySync ?? 'fsync';
    this.hooks = options.hooks ?? {};
  }

  private dir(messageId: string): string {
    return join(this.root, createHash('sha256').update(messageId).digest('hex'));
  }

  get(messageId: string): InboxRecord | undefined {
    return this.index.get(messageId);
  }

  /**
   * Rebuild the index from committed records (crash/restart recovery). Only
   * canonical published directories are considered, and a record is indexed only
   * when its directory name is the hash of its own MessageId — an interrupted
   * staging directory is never mistaken for a committed record. A persisted
   * response is replayed only when its separate confirmation marker is present,
   * so the mere visibility of `response.json` never establishes durability.
   */
  async load(): Promise<void> {
    const entries = await readdir(this.root, { withFileTypes: true }).catch(() => []);
    for (const entry of entries) {
      if (!entry.isDirectory() || !CANONICAL_DIR.test(entry.name)) continue;
      try {
        const record = JSON.parse(await readFile(join(this.root, entry.name, 'inbox.json'), 'utf8')) as InboxRecord;
        if (this.dir(record.messageId) !== join(this.root, entry.name)) continue;
        this.index.set(record.messageId, record);
        await readFile(join(this.root, entry.name, 'response.confirmed'));
        this.confirmedResponses.add(record.messageId);
      } catch {
        // Partial, unrelated or unconfirmed directory: not a replayable record.
      }
    }
  }

  /** Rebuild the in-memory index from disk, as after a process restart. */
  async reload(): Promise<void> {
    this.index.clear();
    this.confirmedResponses.clear();
    await this.load();
  }

  /** Remove abandoned staging directories left by an interrupted commit. */
  async sweepStaging(): Promise<void> {
    const entries = await readdir(this.root, { withFileTypes: true }).catch(() => []);
    for (const entry of entries) {
      if (!entry.isDirectory() || CANONICAL_DIR.test(entry.name)) continue;
      await rm(join(this.root, entry.name), { recursive: true, force: true });
    }
  }

  /** fsync a directory so a rename survives a crash. Failures propagate. */
  private async syncDir(path: string): Promise<void> {
    if (this.directorySync === 'none') return; // explicitly weaker durability mode
    await this.hooks.beforeDirectorySync?.(path);
    const handle = await open(path, 'r');
    try {
      await handle.sync();
    } finally {
      await handle.close();
    }
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

  /** Read a published record directory, or null when it does not exist yet. */
  private async readPublished(dir: string): Promise<InboxRecord | null> {
    try {
      return JSON.parse(await readFile(join(dir, 'inbox.json'), 'utf8')) as InboxRecord;
    } catch {
      return null;
    }
  }

  /**
   * Stage the whole record, fsync it, then publish it with a single atomic
   * rename and fsync the parent.
   *
   * If a previous attempt already published this message's directory but failed
   * the parent sync, the record is reconciled under the per-message lock: its
   * identity and content are validated, the required sync is retried, and it is
   * indexed. The published directory is never overwritten with another staged
   * copy (which would fail with ENOTEMPTY).
   */
  async commit(opened: OpenSuccess, contentKey: string): Promise<InboxRecord> {
    const dir = this.dir(opened.messageId);
    const alreadyPublished = await this.readPublished(dir);
    if (alreadyPublished) {
      if (this.dir(alreadyPublished.messageId) !== dir || alreadyPublished.contentKey !== contentKey) {
        throw new Error(`published record for ${opened.messageId} does not match this content`);
      }
      await this.syncDir(this.root);
      this.index.set(alreadyPublished.messageId, alreadyPublished);
      this.deliveries += 1;
      return alreadyPublished;
    }

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
    await this.syncDir(staging);
    await this.hooks.beforePublish?.();
    await rename(staging, dir);
    await this.syncDir(this.root);
    this.index.set(record.messageId, record);
    this.deliveries += 1;
    return record;
  }

  /**
   * Publish the exact response bytes as one atomic file, then confirm its
   * durability with a separate marker. Until that second sync succeeds the
   * response is "published, durability unconfirmed" and must not be replayed.
   */
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
    await this.syncDir(staging);
    await rename(join(staging, 'response.json'), join(dir, 'response.json'));
    await this.syncDir(dir);
    await rm(staging, { recursive: true, force: true });
    // Confirmation marker: created only after the payload directory sync, then
    // itself synced. If that fails the response stays unconfirmed.
    try {
      await durableWrite(join(dir, 'response.confirmed'), '1');
      await this.syncDir(dir);
    } catch (err) {
      await rm(join(dir, 'response.confirmed'), { force: true }).catch(() => {});
      this.confirmedResponses.delete(messageId);
      throw err;
    }
    this.confirmedResponses.add(messageId);
  }

  /** A stored response is returned only once its durability was confirmed. */
  async response(messageId: string): Promise<StoredResponse | null> {
    if (!this.confirmedResponses.has(messageId)) return null;
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
    await rm(join(this.dir(messageId), 'response.confirmed'), { force: true });
    this.confirmedResponses.delete(messageId);
  }
}

interface Deps {
  /** Swapped by the example's crash/failure scenarios. */
  inbox: DurableInbox;
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

/** The canonical published directory name for a message id (hash of the id). */
function recordDir(root: string, messageId: string): string {
  return join(root, createHash('sha256').update(messageId).digest('hex'));
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
  const inboxRoot = join(root, 'inbox');

  await mkdir(inboxRoot, { recursive: true });
  // Failure injection for the probes below: a path whose directory sync always
  // fails, and a path whose sync fails exactly once. Both are toggled around the
  // scenarios; the inbox instance is shared so deliveries stay comparable.
  let persistentSyncFailure: string | null = null;
  let transientSyncFailure: string | null = null;
  const syncLog: string[] = [];
  const inbox = new DurableInbox(inboxRoot, {
    hooks: {
      beforeDirectorySync: (path) => {
        syncLog.push(path);
        if (path === persistentSyncFailure) throw new Error('simulated persistent EIO');
        if (path === transientSyncFailure) {
          transientSyncFailure = null;
          throw new Error('simulated transient EIO');
        }
      },
    },
  });
  await inbox.sweepStaging();
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

    // 6. Crash immediately before the commit rename: the staged record must not be
    // loaded as committed on restart, and must be swept as abandoned. A retry
    // then commits normally.
    const d = await prepare(pki, url, tls.caPem, 'interrupt@as4-sender', '<?xml version="1.0"?><doc>d</doc>');
    messages.push(d);
    const crashing = new DurableInbox(inboxRoot, {
      hooks: {
        beforePublish: () => {
          throw new Error('simulated crash before rename');
        },
      },
    });
    const previousInbox = deps.inbox;
    deps.inbox = crashing;
    const crashed = await transmit(d, pki, tls.caPem);
    deps.inbox = previousInbox;
    const restart = new DurableInbox(inboxRoot);
    await restart.load();
    const notCommitted = restart.get(d.as4MessageId) === undefined;
    await restart.sweepStaging();
    const stagingSwept = (await readdir(inboxRoot)).every((name) => CANONICAL_DIR.test(name));
    const retried = await transmit(d, pki, tls.caPem);
    const crashOk =
      receiptBytes(crashed) === null && notCommitted && stagingSwept && retried.outcome === 'receipt-verified';
    console.log(
      `crash pre-rename: no-receipt=${receiptBytes(crashed) === null}  not-committed=${notCommitted}  staging-swept=${stagingSwept}  retry=${retried.outcome}  (deliveries=${inbox.deliveries})`,
    );

    // 7. A persistent response-directory sync failure: the response is published
    // but its durability is never confirmed, so it is never replayed and no
    // receipt is ever produced — even though the message is committed once.
    const f = await prepare(pki, url, tls.caPem, 'persistent-fsync@as4-sender', '<?xml version="1.0"?><doc>f</doc>');
    messages.push(f);
    persistentSyncFailure = recordDir(inboxRoot, f.as4MessageId);
    const fFirst = await transmit(f, pki, tls.caPem);
    const fRetry = await transmit(f, pki, tls.caPem);
    persistentSyncFailure = null;
    const persistentOk = receiptBytes(fFirst) === null && receiptBytes(fRetry) === null;
    console.log(
      `persistent fsync:  first=${receiptBytes(fFirst) === null ? 'no-receipt' : 'receipt'}  retry=${receiptBytes(fRetry) === null ? 'no-receipt' : 'receipt'}  (deliveries=${inbox.deliveries})`,
    );

    // 8. A transient response-directory sync failure recovers on retry: the
    // unconfirmed response is regenerated rather than replayed, with no second
    // business delivery.
    const h = await prepare(
      pki,
      url,
      tls.caPem,
      'transient-response-fsync@as4-sender',
      '<?xml version="1.0"?><doc>h</doc>',
    );
    messages.push(h);
    const deliveriesBeforeH = inbox.deliveries;
    const hDir = recordDir(inboxRoot, h.as4MessageId);
    transientSyncFailure = hDir;
    const hFirst = await transmit(h, pki, tls.caPem);
    const hDirSyncsBeforeRetry = syncLog.filter((path) => path === hDir).length;
    const hRetry = await transmit(h, pki, tls.caPem);
    const hDirSyncsAfterRetry = syncLog.filter((path) => path === hDir).length;
    const responseTransientOk =
      receiptBytes(hFirst) === null &&
      hRetry.outcome === 'receipt-verified' &&
      inbox.deliveries === deliveriesBeforeH + 1 &&
      // The retry must re-attempt durability, not replay the unconfirmed bytes.
      hDirSyncsAfterRetry > hDirSyncsBeforeRetry;
    console.log(
      `transient resp:    first=${receiptBytes(hFirst) === null ? 'no-receipt' : 'receipt'}  retry=${hRetry.outcome}  (deliveries=${inbox.deliveries})`,
    );

    // 9. A transient commit-parent sync failure recovers without overwriting the
    // published directory (no ENOTEMPTY) and without a second business delivery.
    const g = await prepare(
      pki,
      url,
      tls.caPem,
      'transient-commit-fsync@as4-sender',
      '<?xml version="1.0"?><doc>g</doc>',
    );
    messages.push(g);
    const deliveriesBeforeG = inbox.deliveries;
    transientSyncFailure = inboxRoot;
    const gFirst = await transmit(g, pki, tls.caPem);
    const gRetry = await transmit(g, pki, tls.caPem);
    const commitTransientOk =
      receiptBytes(gFirst) === null &&
      gRetry.outcome === 'receipt-verified' &&
      inbox.deliveries === deliveriesBeforeG + 1;
    console.log(
      `transient commit:  first=${receiptBytes(gFirst) === null ? 'no-receipt' : 'receipt'}  retry=${gRetry.outcome}  (deliveries=${inbox.deliveries})`,
    );

    // 10. A malformed upload is a transport rejection, not an invented ebMS error.
    const malformedStatus = await postRaw(url, tls.caPem, 'text/plain', 'not as4');
    console.log(`malformed upload: HTTP ${malformedStatus}`);

    ok =
      replayed &&
      recoveryOk &&
      concurrentOk &&
      crashOk &&
      persistentOk &&
      responseTransientOk &&
      commitTransientOk &&
      inbox.deliveries === 7 &&
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
