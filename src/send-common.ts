import type {
  CertificateValidation,
  CertificateValidationInput,
  NotSentReason,
  OnEvent,
  SendEvent,
  SendPhase,
} from './types.js';
import { safeMessage } from './util.js';

/** Time a phase and report it to `onEvent`. */
export async function timed<T>(onEvent: OnEvent | undefined, phase: SendPhase, fn: () => Promise<T>): Promise<T> {
  const start = performance.now();
  try {
    return await fn();
  } finally {
    emit(onEvent, { phase, durationMs: performance.now() - start });
  }
}

/** Observation only: exceptions from the hook are swallowed. */
export function emit(onEvent: OnEvent | undefined, event: SendEvent): void {
  if (!onEvent) return;
  try {
    onEvent(event);
  } catch {
    // observe only
  }
}

export function isAbortError(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  return err.name === 'AbortError' || (err as NodeJS.ErrnoException).code === 'ABORT_ERR';
}

/** Filesystem errno codes that mean a local spool/preparation failure. */
const FILE_SYSTEM_ERROR_CODES: ReadonlySet<string> = new Set([
  'EACCES',
  'EPERM',
  'EROFS',
  'ENOSPC',
  'EDQUOT',
  'EIO',
  'EMFILE',
  'ENFILE',
  'EEXIST',
  'ENOENT',
  'ENOTDIR',
  'EISDIR',
  'ELOOP',
  'ENAMETOOLONG',
  'EBUSY',
  'ENODEV',
  'ENXIO',
]);

/** True when the error is a local filesystem failure, not a network/protocol one. */
export function isFileSystemError(err: unknown): boolean {
  if (typeof err !== 'object' || err === null) return false;
  const code = (err as NodeJS.ErrnoException).code;
  return typeof code === 'string' && FILE_SYSTEM_ERROR_CODES.has(code);
}

/** Call the required validator. A missing or throwing validator never sends. */
export async function callValidator(
  validate: ((input: CertificateValidationInput) => Promise<CertificateValidation>) | undefined,
  argument: CertificateValidationInput,
): Promise<CertificateValidation> {
  if (typeof validate !== 'function') {
    return { ok: false, status: 'unavailable', reason: 'no certificate validator configured' };
  }
  try {
    return await validate(argument);
  } catch (err) {
    if (isAbortError(err)) throw err;
    return { ok: false, status: 'unavailable', reason: safeMessage(err) };
  }
}

export function mapSenderFault(reason: string): NotSentReason {
  switch (reason) {
    case 'signature.mismatch':
      return 'signature.mismatch';
    case 'signer.unusable':
      return 'signer.unusable';
    default:
      return 'signer.unusable';
  }
}

export function endpointHost(endpointUrl: string): string {
  try {
    return new URL(endpointUrl).hostname || 'as4.local';
  } catch {
    return 'as4.local';
  }
}
