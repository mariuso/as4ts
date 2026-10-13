/**
 * Shared streaming helpers for inbound processing (Phase 2/3).
 *
 * `abortableStream` is the one cancellation adapter: it stops a read as soon as
 * `signal` aborts, and on every early exit it signals the producer's `return()`
 * **without awaiting it** — an external iterator's cleanup may stall or throw,
 * and neither must be able to hang recovery.
 */
export function abortError(): Error {
  const error = new Error('aborted');
  error.name = 'AbortError';
  (error as NodeJS.ErrnoException).code = 'ABORT_ERR';
  return error;
}

export function isAbortError(err: unknown): boolean {
  return err instanceof Error && (err.name === 'AbortError' || (err as NodeJS.ErrnoException).code === 'ABORT_ERR');
}

export async function* abortableStream(
  source: AsyncIterable<Uint8Array>,
  signal: AbortSignal | undefined,
): AsyncGenerator<Uint8Array> {
  const iterator = source[Symbol.asyncIterator]();
  let onAbort: (() => void) | null = null;
  const abortPromise = signal
    ? new Promise<never>((_resolve, reject) => {
        const fail = (): void => reject(abortError());
        if (signal.aborted) fail();
        else {
          onAbort = fail;
          signal.addEventListener('abort', fail, { once: true });
        }
      })
    : null;
  try {
    for (;;) {
      const result = abortPromise ? await Promise.race([iterator.next(), abortPromise]) : await iterator.next();
      if (result.done) break;
      yield result.value;
    }
  } finally {
    if (onAbort && signal) signal.removeEventListener('abort', onAbort);
    // Non-blocking on every early-exit path: signal the producer to stop, but do
    // not wait for its cleanup, and guard a synchronous throw.
    let returned: unknown;
    try {
      returned = iterator.return?.();
    } catch {
      returned = null;
    }
    if (returned) void Promise.resolve(returned).catch(() => {});
  }
}
