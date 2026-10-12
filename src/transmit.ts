import { buildMultipartBody } from './multipart.js';
import { sendHttp } from './http/send.js';
import { extractSoapEnvelope, parseSignal, type ParsedSignal } from './xml/signal.js';
import { verifyReceipt } from './receipt/verify.js';
import { TransportError } from './errors.js';
import { attachmentPathOf } from './artifact.js';
import { safeMessage } from './util.js';
import { isAbortError, timed } from './send-common.js';
import type {
  EbmsErrorEvidence,
  ErrorCorrelation,
  NotSentReason,
  OnEvent,
  PreparedMessage,
  SendAs4Result,
  TransmitAs4Input,
} from './types.js';

interface ResultCommon {
  readonly as4MessageId: string;
  readonly sentAt?: string;
  readonly receiverCertificateCommonName: string;
  readonly transportProfile: string;
}

/**
 * Perform exactly one transmission of a prepared message. It never rebuilds or
 * re-signs anything: the envelope, ciphertext, multipart framing and signed
 * references all come from the artifact, so a retry is byte-identical to the
 * original attempt and receipt verification uses the original signed references.
 */
export async function transmitAs4(input: TransmitAs4Input): Promise<SendAs4Result> {
  const { message, onEvent } = input;
  const abort = input.signal;
  const base = (): ResultCommon => ({
    as4MessageId: message.as4MessageId,
    sentAt: message.sentAt,
    receiverCertificateCommonName: message.receiverCertificateCommonName,
    transportProfile: message.transportProfile,
  });
  const notSent = (reason: NotSentReason, detail?: string): SendAs4Result => ({
    ...base(),
    outcome: 'not-sent',
    reason,
    ...(detail ? { detail } : {}),
  });

  if (abort?.aborted) return notSent('aborted');

  try {
    const multipart = buildMultipartBody({
      soapXml: message.soapXml,
      attachmentHref: message.attachmentHref,
      attachmentFilePath: attachmentPathOf(message),
      attachmentByteLength: message.attachmentByteLength,
      boundary: message.boundary,
      soapContentId: message.soapContentId,
    });

    const response = await timed(onEvent, 'http', () =>
      sendHttp({
        endpointUrl: message.endpointUrl,
        contentType: multipart.contentType,
        contentLength: multipart.contentLength,
        body: multipart.stream,
        http: input.http,
        ...(abort ? { signal: abort } : {}),
      }),
    );

    return await classifyResponse({ input, base, response, message, abort, onEvent });
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
    if (isAbortError(err)) return notSent('aborted', 'aborted before the request was sent');
    return notSent('internal.error', safeMessage(err));
  }
}

interface ClassifyArgs {
  readonly input: TransmitAs4Input;
  readonly base: () => ResultCommon;
  readonly response: Awaited<ReturnType<typeof sendHttp>>;
  readonly message: PreparedMessage;
  readonly abort: AbortSignal | undefined;
  readonly onEvent: OnEvent | undefined;
}

async function classifyResponse(args: ClassifyArgs): Promise<SendAs4Result> {
  const { response, message } = args;
  const soap = extractSoapEnvelope(response.headers['content-type'], response.body);

  if (soap) {
    const signal = parseSignal(soap);
    if (signal) {
      if (signal.kind === 'error') {
        const refToMessageId = signal.refToMessageId;
        const correlation: ErrorCorrelation =
          refToMessageId === null ? 'absent' : refToMessageId === message.as4MessageId ? 'matches' : 'mismatched';
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
  const { input, message, abort } = args;
  try {
    const check = await timed(args.onEvent, 'verify-receipt', () =>
      verifyReceipt({
        signal,
        as4MessageId: message.as4MessageId,
        receiverCertificatePem: message.receiverCertificate,
        // The original signed references, not a rebuild.
        signedReferences: message.signedReferences,
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
