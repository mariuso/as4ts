import type { X509Certificate } from 'node:crypto';
import { AS4_COMPRESSION_TYPE } from './constants.js';
import type { Entropy } from './entropy.js';
import { SenderFault, TransportError } from './errors.js';
import { preparePayload } from './crypto/payload.js';
import { wrapSessionKey } from './crypto/session-key.js';
import { buildEnvelope, type BuiltEnvelope } from './xml/envelope.js';
import { buildMultipartBody } from './multipart.js';
import { sendHttp } from './http/send.js';
import { extractSoapEnvelope, parseSignal, type ParsedSignal } from './xml/signal.js';
import { verifyReceipt, type SignedReference } from './receipt/verify.js';
import { createTempWorkspace, type TempWorkspace, type TempWorkspaceOptions } from './temp-file.js';
import { commonNameOf, isValidMessageId, parseCertificate, safeMessage } from './util.js';
import { peppolProfile } from './profile.js';
import type {
  CertificateValidation,
  CertificateValidationInput,
  EbmsErrorEvidence,
  ErrorCorrelation,
  NotSentReason,
  SendAs4Input,
  SendAs4Result,
  SendEvent,
  SendPhase,
  ValidateCertificate,
} from './types.js';

/**
 * The send core. Not part of the package surface: the entropy source is
 * internal so a caller cannot pin the session key and IV (which would break
 * encryption). `sendAs4` in index.ts calls this with the cryptographic RNG;
 * tests reach it through `src/internal.ts`.
 */
export async function sendAs4Internal(
  input: SendAs4Input,
  entropy: Entropy,
  createWorkspace: (options: TempWorkspaceOptions) => Promise<TempWorkspace> = createTempWorkspace,
): Promise<SendAs4Result> {
  const profile = input.profile ?? peppolProfile;
  const abort = input.signal;
  const onEvent = input.onEvent;
  let sentAt = '';
  let receiverCertificateCommonName = '';
  let receiverCertificate: X509Certificate | null = null;
  try {
    receiverCertificate = parseCertificate(input.receiverCertificate);
    receiverCertificateCommonName = commonNameOf(receiverCertificate);
  } catch {
    receiverCertificate = null;
  }

  const base = (): ResultCommon => ({
    as4MessageId: input.as4MessageId,
    ...(sentAt ? { sentAt } : {}),
    receiverCertificateCommonName,
    transportProfile: input.transportProfile,
  });
  const notSent = (reason: NotSentReason, detail?: string): SendAs4Result => ({
    ...base(),
    outcome: 'not-sent',
    reason,
    ...(detail ? { detail } : {}),
  });

  if (!isValidMessageId(input.as4MessageId)) return notSent('message-id.invalid');
  if (!receiverCertificate) return notSent('certificate.refused', 'receiver certificate is not readable');
  if (abort?.aborted) return notSent('aborted');

  let workspace: TempWorkspace | null = null;
  let transmissionStarted = false;
  try {
    // [CEF] §3.2.2 before anything else: the receiver certificate must validate.
    const receiverValidation = await timed(onEvent, 'validate-receiver', () =>
      callValidator(input.validateCertificate, {
        certificatePem: input.receiverCertificate,
        purpose: 'receiver-encryption',
        now: input.now(),
        ...(abort ? { signal: abort } : {}),
      }),
    );
    if (!receiverValidation.ok) {
      if (receiverValidation.status === 'unavailable')
        return notSent('certificate.unavailable', receiverValidation.reason);
      return notSent('certificate.refused', receiverValidation.reason);
    }
    if (abort?.aborted) return notSent('aborted');

    workspace = await createWorkspace({
      ...(input.spoolDirectory ? { directory: input.spoolDirectory } : {}),
    });

    const { sessionKey, wrappedKey } = wrapSessionKey(receiverCertificate.publicKey, entropy);
    const payload = await timed(onEvent, 'prepare-payload', () =>
      preparePayload({
        source: input.payload,
        sessionKey,
        wrappedKey,
        filePath: workspace!.path('payload.enc'),
        entropy,
        ...(abort ? { signal: abort } : {}),
      }),
    );

    // §7: the message timestamp is taken immediately before the envelope is
    // built, after certificate validation and payload spooling.
    sentAt = input.now().toISOString();

    const attachmentHref = `cid:${entropy.uuid()}@${endpointHost(input.endpointUrl)}`;
    const fromPartyId = commonNameOf(parseCertificate(input.signer.certificate));
    const built = await timed(onEvent, 'sign', () =>
      buildEnvelope({
        userMessage: {
          messageId: input.as4MessageId,
          timestamp: sentAt,
          fromPartyId,
          toPartyId: receiverCertificateCommonName,
          profile,
          service: input.process,
          action: `${input.documentType.scheme}::${input.documentType.value}`,
          originalSender: input.senderParticipant,
          finalRecipient: input.receiverParticipant,
          payloadHref: attachmentHref,
          compressionType: AS4_COMPRESSION_TYPE,
        },
        signer: input.signer,
        receiverCertificatePem: input.receiverCertificate,
        wrappedKey,
        attachmentDigestBase64: payload.compressedDigestBase64,
        entropy,
      }),
    );

    const multipart = buildMultipartBody({
      soapXml: built.xml,
      attachmentHref,
      attachmentFilePath: payload.filePath,
      attachmentByteLength: payload.byteLength,
      entropy,
    });

    transmissionStarted = true;
    const response = await timed(onEvent, 'http', () =>
      sendHttp({
        endpointUrl: input.endpointUrl,
        contentType: multipart.contentType,
        contentLength: multipart.contentLength,
        body: multipart.stream,
        http: input.http,
        ...(abort ? { signal: abort } : {}),
      }),
    );

    return await classifyResponse({
      input,
      base,
      response,
      built,
      attachmentHref,
      attachmentDigest: payload.compressedDigestBase64,
      abort,
      onEvent,
    });
  } catch (err) {
    if (err instanceof TransportError) {
      return {
        ...base(),
        outcome: 'transport-failure',
        ...(err.info.code ? { errorCode: err.info.code } : {}),
        requestMayHaveBeenSent: err.info.requestMayHaveBeenSent,
        aborted: err.info.aborted,
      };
    }
    if (err instanceof SenderFault) {
      return notSent(mapSenderFault(err.reason), err.message);
    }
    if (isAbortError(err)) return notSent('aborted', 'aborted while spooling the payload');
    // A filesystem failure while preparing the payload (creating the workspace or
    // spooling ciphertext) is deliberate and safe to retry: no HTTP request has
    // started at this point.
    if (!transmissionStarted && isFileSystemError(err)) return notSent('spool.failed', safeMessage(err));
    return notSent('internal.error', safeMessage(err));
  } finally {
    if (workspace) await cleanupWorkspace(workspace, onEvent);
  }
}

interface ResultCommon {
  readonly as4MessageId: string;
  readonly sentAt?: string;
  readonly receiverCertificateCommonName: string;
  readonly transportProfile: string;
}

interface ClassifyArgs {
  readonly input: SendAs4Input;
  readonly base: () => ResultCommon;
  readonly response: Awaited<ReturnType<typeof sendHttp>>;
  readonly built: BuiltEnvelope;
  readonly attachmentHref: string;
  readonly attachmentDigest: string;
  readonly abort: AbortSignal | undefined;
  readonly onEvent: SendAs4Input['onEvent'];
}

async function classifyResponse(args: ClassifyArgs): Promise<SendAs4Result> {
  const { response } = args;
  const soap = extractSoapEnvelope(response.headers['content-type'], response.body);

  if (soap) {
    const signal = parseSignal(soap);
    if (signal) {
      if (signal.kind === 'error') {
        const refToMessageId = signal.refToMessageId;
        const correlation: ErrorCorrelation =
          refToMessageId === null ? 'absent' : refToMessageId === args.input.as4MessageId ? 'matches' : 'mismatched';
        return {
          ...args.base(),
          outcome: 'error-signal',
          errors: toErrorEvidence(signal),
          raw: signal.raw,
          refToMessageId,
          correlation,
        };
      }
      if (signal.kind === 'receipt') {
        return verifyReceiptResult(args, signal);
      }
    }
  }

  return {
    ...args.base(),
    outcome: 'no-signal',
    status: response.status,
    bodyEmpty: response.body.length === 0,
  };
}

async function verifyReceiptResult(args: ClassifyArgs, signal: ParsedSignal): Promise<SendAs4Result> {
  const { input, built, abort } = args;
  const signedReferences: SignedReference[] = [
    { uri: `#${built.bodyId}`, digest: built.bodyDigest },
    { uri: `#${built.messagingId}`, digest: built.messagingDigest },
    { uri: args.attachmentHref, digest: args.attachmentDigest },
  ];
  try {
    const check = await timed(args.onEvent, 'verify-receipt', () =>
      verifyReceipt({
        signal,
        as4MessageId: input.as4MessageId,
        receiverCertificatePem: input.receiverCertificate,
        signedReferences,
        validateCertificate: input.validateCertificate,
        now: input.now,
        ...(abort ? { abort } : {}),
      }),
    );
    if (check.ok) {
      return { ...args.base(), outcome: 'receipt-verified', receipt: check.receipt };
    }
    return { ...args.base(), outcome: 'receipt-unverified', reason: check.reason, raw: signal.raw };
  } catch (err) {
    // The message was already sent and a response was received, so this can
    // never be reported as not-sent: return the raw signal as unverified.
    return {
      ...args.base(),
      outcome: 'receipt-unverified',
      reason: isAbortError(err) ? 'receipt.aborted' : 'receipt.untrusted-signer',
      raw: signal.raw,
    };
  }
}

function toErrorEvidence(signal: ParsedSignal): EbmsErrorEvidence[] {
  return signal.errors.map((error) => ({
    code: error.code,
    severity: error.severity,
    ...(error.shortDescription ? { shortDescription: error.shortDescription } : {}),
    ...(error.description ? { description: error.description } : {}),
    ...(error.detail ? { detail: error.detail } : {}),
    raw: signal.raw,
  }));
}

/** Call the required validator. A missing or throwing validator never sends. */
async function callValidator(
  validate: ValidateCertificate | undefined,
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

function mapSenderFault(reason: string): NotSentReason {
  switch (reason) {
    case 'signature.mismatch':
      return 'signature.mismatch';
    case 'signer.unusable':
      return 'signer.unusable';
    default:
      return 'signer.unusable';
  }
}

function isAbortError(err: unknown): boolean {
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
function isFileSystemError(err: unknown): boolean {
  if (typeof err !== 'object' || err === null) return false;
  const code = (err as NodeJS.ErrnoException).code;
  return typeof code === 'string' && FILE_SYSTEM_ERROR_CODES.has(code);
}

async function timed<T>(onEvent: SendAs4Input['onEvent'], phase: SendPhase, fn: () => Promise<T>): Promise<T> {
  const start = performance.now();
  try {
    return await fn();
  } finally {
    emit(onEvent, { phase, durationMs: performance.now() - start });
  }
}

/** Observation only: exceptions from the hook are swallowed. */
function emit(onEvent: SendAs4Input['onEvent'], event: SendEvent): void {
  if (!onEvent) return;
  try {
    onEvent(event);
  } catch {
    // observe only
  }
}

/**
 * Remove the spool workspace without letting a cleanup failure mask an
 * already-computed result. If removal fails the workspace is left on disk, and a
 * `cleanup` event carries a secret-free reason so the caller can retry later; the
 * send's own outcome is unaffected either way.
 */
async function cleanupWorkspace(workspace: TempWorkspace, onEvent: SendAs4Input['onEvent']): Promise<void> {
  const start = performance.now();
  try {
    await workspace.cleanup();
  } catch (err) {
    emit(onEvent, { phase: 'cleanup', durationMs: performance.now() - start, error: safeMessage(err) });
  }
}

function endpointHost(endpointUrl: string): string {
  try {
    return new URL(endpointUrl).hostname || 'as4.local';
  } catch {
    return 'as4.local';
  }
}
