export interface HttpGetResponse {
  readonly status: number;
  readonly url: string;
  readonly body: Buffer;
  readonly contentType: string | null;
  readonly location: string | null;
}

export type HttpGetOutcome =
  | { readonly ok: true; readonly response: HttpGetResponse }
  | { readonly ok: false; readonly reason: string; readonly retryable: boolean };

export interface HttpGetOptions {
  readonly fetch: typeof fetch;
  readonly signal?: AbortSignal;
  readonly timeoutMs: number;
}

function isAbort(err: unknown): boolean {
  return err instanceof Error && (err.name === 'AbortError' || (err as NodeJS.ErrnoException).code === 'ABORT_ERR');
}

/**
 * One HTTP GET with a timeout and the caller's abort signal, never disabling TLS
 * verification. HTTP redirects are not followed (the SMP `Redirect` element is
 * the redirect mechanism; SMP v1.4.0 §5.1 says clients need not follow HTTP 3xx).
 */
export async function httpGet(url: string, options: HttpGetOptions): Promise<HttpGetOutcome> {
  const controller = new AbortController();
  const onAbort = (): void => controller.abort();
  if (options.signal?.aborted) controller.abort();
  options.signal?.addEventListener('abort', onAbort, { once: true });
  const timer = setTimeout(() => controller.abort(), options.timeoutMs);
  try {
    const response = await options.fetch(url, {
      method: 'GET',
      headers: { Accept: 'text/xml, application/xml;q=0.9, */*;q=0.1' },
      redirect: 'manual',
      signal: controller.signal,
    });
    const body = Buffer.from(await response.arrayBuffer());
    return {
      ok: true,
      response: {
        status: response.status,
        url,
        body,
        contentType: response.headers.get('content-type'),
        location: response.headers.get('location'),
      },
    };
  } catch (err) {
    if (options.signal?.aborted) return { ok: false, reason: 'aborted', retryable: true };
    if (isAbort(err)) return { ok: false, reason: `request to ${url} timed out`, retryable: true };
    return { ok: false, reason: `${url}: ${(err as Error).message}`, retryable: true };
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener('abort', onAbort);
  }
}
