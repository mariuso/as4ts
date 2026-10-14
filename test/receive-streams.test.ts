import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import v8 from 'node:v8';
import { Readable } from 'node:stream';
import { abortableStream, isAbortError } from '../src/receive/streams.js';

/**
 * `abortableStream` is used on every inbound stream. A per-step cancellation
 * listener must not retain consumed chunks, or a large request body would be
 * held in memory for the life of the stream (the leak this file guards against).
 */
function forceGc(): () => void {
  v8.setFlagsFromString('--expose-gc');
  return vm.runInNewContext('gc') as () => void;
}

async function collectGarbage(gc: () => void, rounds = 5): Promise<void> {
  for (let i = 0; i < rounds; i += 1) {
    gc();
    await new Promise((resolve) => setImmediate(resolve));
  }
}

function alive(refs: readonly WeakRef<Uint8Array>[]): number {
  return refs.filter((ref) => ref.deref() !== undefined).length;
}

test('abortableStream does not retain consumed chunks', async () => {
  const gc = forceGc();
  const chunks = 200;
  const refs: WeakRef<Uint8Array>[] = [];
  let seen = 0;
  let midLoopAlive = Number.POSITIVE_INFINITY;

  async function* source(): AsyncGenerator<Buffer> {
    for (let i = 0; i < chunks; i += 1) yield Buffer.alloc(1024 * 1024);
  }

  for await (const chunk of abortableStream(source(), new AbortController().signal)) {
    refs.push(new WeakRef(chunk));
    seen += 1;
    if (seen === 150) {
      await collectGarbage(gc);
      midLoopAlive = alive(refs);
    }
  }

  await collectGarbage(gc);
  assert.equal(seen, chunks);
  assert.ok(
    midLoopAlive <= 8,
    `mid-loop retention: ${midLoopAlive} of 150 consumed chunks were still alive (expected <= 8)`,
  );
  assert.ok(alive(refs) <= 8, `end retention: ${alive(refs)} of ${chunks} chunks were still alive`);
});

test('abortableStream rejects an abort while waiting and closes the source', async () => {
  let closed = false;
  const source: AsyncIterable<Uint8Array> = {
    [Symbol.asyncIterator]() {
      return {
        next(): Promise<IteratorResult<Uint8Array>> {
          return new Promise(() => {}); // never settles: the stream waits forever
        },
        async return(): Promise<IteratorResult<Uint8Array>> {
          closed = true;
          return { done: true, value: undefined };
        },
      };
    },
  };
  const controller = new AbortController();
  const stream = abortableStream(source, controller.signal);
  const pending = stream.next();
  controller.abort();
  await assert.rejects(pending, (err) => isAbortError(err));
  assert.equal(closed, true, 'the source iterator was told to stop');
});

test('abortableStream rejects before the first chunk when already aborted', async () => {
  const controller = new AbortController();
  controller.abort();
  const stream = abortableStream(Readable.from([Buffer.from('x')]), controller.signal);
  await assert.rejects(stream.next(), (err) => isAbortError(err));
});

test('abortableStream without a signal passes every chunk through in order', async () => {
  const chunks = [Buffer.from('a'), Buffer.from('b'), Buffer.from('c')];
  const received: string[] = [];
  for await (const chunk of abortableStream(Readable.from(chunks), undefined)) {
    received.push(Buffer.from(chunk).toString('utf8'));
  }
  assert.deepEqual(received, ['a', 'b', 'c']);
});
