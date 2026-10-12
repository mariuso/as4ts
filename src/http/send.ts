import { request as httpsRequest, Agent, type RequestOptions } from 'node:https';
import type { ClientRequest } from 'node:http';
import type { Socket } from 'node:net';
import type { Readable } from 'node:stream';
import type { HttpOptions } from '../types.js';
import { TransportError } from '../errors.js';
import { PACKAGE_NAME, PACKAGE_VERSION } from '../version.js';

export interface SendHttpInput {
  readonly endpointUrl: string;
  readonly contentType: string;
  readonly contentLength: number;
  readonly body: Readable;
  readonly http: HttpOptions;
  readonly signal?: AbortSignal;
}

export interface SendHttpResult {
  readonly status: number;
  readonly statusText: string;
  readonly headers: Record<string, string>;
  readonly body: Buffer;
  readonly requestBytesWritten: boolean;
}

/** Signals are small; refuse to buffer an unbounded response. */
const MAX_RESPONSE_BYTES = 16 * 1024 * 1024;

/**
 * One HTTPS POST. TLS 1.2 is the floor and certificate verification can never
 * be disabled ([CEFEAS4] §3.2.6, [PEPPOL-TS-POL]). The receiver's TLS
 * certificate is an ordinary web certificate, so the system trust store is used
 * unless the caller pins `ca`.
 *
 * A dedicated no-keep-alive agent is always used (a caller-supplied one is not
 * accepted, since it could disable verification), so `secureConnect` always
 * fires and "request bytes written" is reliable on repeat sends to the same
 * host. Any failure destroys the request so an in-flight upload cannot continue
 * after the result is returned.
 *
 * Resolves for any HTTP response (including 4xx/5xx) as long as a full response
 * was read. Rejects with a {@link TransportError} (carrying whether any request
 * byte was written) only when no complete response was obtained.
 */
export function sendHttp(input: SendHttpInput): Promise<SendHttpResult> {
  return new Promise<SendHttpResult>((resolve, reject) => {
    const url = new URL(input.endpointUrl);
    if (url.protocol !== 'https:') {
      reject(
        new TransportError('endpoint is not https', {
          requestBytesWritten: false,
          responseStarted: false,
          aborted: false,
        }),
      );
      return;
    }

    // Always use our own no-keep-alive agent. A caller-supplied agent is
    // deliberately not accepted: an https.Agent can carry
    // rejectUnauthorized:false (or a custom createConnection), which would
    // disable the TLS verification this sender guarantees.
    const agent = new Agent({ keepAlive: false, maxSockets: 1 });
    let connected = false;
    let responseStarted = false;
    let settled = false;
    let req: ClientRequest | null = null;

    const cleanup = () => {
      clearTimeout(connectTimer);
      clearTimeout(totalTimer);
      input.signal?.removeEventListener('abort', onAbort);
      agent.destroy();
    };

    const fail = (err: unknown, code?: string, aborted = false) => {
      if (settled) return;
      settled = true;
      cleanup();
      const nodeCode = code ?? (err as NodeJS.ErrnoException | undefined)?.code;
      // HTTP request bytes only reach the server after the TLS handshake.
      const wroteRequest = connected || responseStarted;
      try {
        req?.destroy();
      } catch {
        // already gone
      }
      try {
        input.body.destroy();
      } catch {
        // already gone
      }
      reject(
        new TransportError(err instanceof Error ? err.message : String(err), {
          ...(nodeCode ? { code: nodeCode } : {}),
          requestBytesWritten: wroteRequest,
          responseStarted,
          aborted,
        }),
      );
    };

    const onAbort = () => fail(new Error('aborted'), 'ABORT_ERR', true);

    const connectTimer = setTimeout(() => {
      if (!connected) fail(new Error('connect timeout'), 'ETIMEDOUT');
    }, input.http.connectMs);
    const totalTimer = setTimeout(() => fail(new Error('total timeout'), 'ETIMEDOUT'), input.http.totalMs);

    const options: RequestOptions = {
      method: 'POST',
      hostname: url.hostname,
      port: url.port ? Number(url.port) : 443,
      path: `${url.pathname}${url.search}`,
      headers: {
        'Content-Type': input.contentType,
        'Content-Length': String(input.contentLength),
        'User-Agent': `${PACKAGE_NAME}/${PACKAGE_VERSION}`,
        Accept: '*/*',
      },
      minVersion: 'TLSv1.2',
      rejectUnauthorized: true,
      agent,
    };
    if (input.http.ca && input.http.ca.length > 0) options.ca = [...input.http.ca];
    if (input.http.serverName) options.servername = input.http.serverName;

    if (input.signal?.aborted) {
      fail(new Error('aborted'), 'ABORT_ERR', true);
      return;
    }

    req = httpsRequest(options, (res) => {
      responseStarted = true;
      const chunks: Buffer[] = [];
      let size = 0;
      res.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (size > MAX_RESPONSE_BYTES) {
          res.destroy(new Error('response too large'));
          return;
        }
        chunks.push(chunk);
      });
      res.on('error', (err) => fail(err));
      res.on('end', () => {
        if (settled) return;
        settled = true;
        cleanup();
        // Stop reading the source and close the socket even if the server
        // answered before consuming the whole body.
        try {
          input.body.destroy();
        } catch {
          // already gone
        }
        const headers: Record<string, string> = {};
        for (const [key, value] of Object.entries(res.headers)) {
          if (typeof value === 'string') headers[key.toLowerCase()] = value;
          else if (Array.isArray(value)) headers[key.toLowerCase()] = value.join(', ');
        }
        resolve({
          status: res.statusCode ?? 0,
          statusText: res.statusMessage ?? '',
          headers,
          body: Buffer.concat(chunks),
          requestBytesWritten: connected,
        });
      });
    });

    req.on('socket', (socket: Socket) => {
      const markConnected = () => {
        connected = true;
      };
      if (socket.connecting) socket.once('secureConnect', markConnected);
      else markConnected();
    });
    req.on('error', (err: Error) => fail(err));
    input.body.on('error', (err: Error) => fail(err));
    input.signal?.addEventListener('abort', onAbort, { once: true });
    input.body.pipe(req);
  });
}
