import type { X509Certificate } from 'node:crypto';
import { AS4_COMPRESSION_TYPE } from './constants.js';
import type { Entropy } from './entropy.js';
import { SenderFault } from './errors.js';
import { preparePayload } from './crypto/payload.js';
import { wrapSessionKey } from './crypto/session-key.js';
import { buildEnvelope } from './xml/envelope.js';
import { buildMultipartBody } from './multipart.js';
import { writePreparedMessage } from './artifact.js';
import { createTempWorkspace, type TempWorkspace, type TempWorkspaceOptions } from './temp-file.js';
import { commonNameOf, isValidMessageId, parseCertificate, safeMessage } from './util.js';
import { peppolProfile } from './profile.js';
import {
  callValidator,
  cleanupQuietly,
  endpointHost,
  isAbortError,
  isFileSystemError,
  mapSenderFault,
  timed,
} from './send-common.js';
import type { NotSentReason, PrepareAs4Input, PrepareAs4Result } from './types.js';
import type { SignedReference } from './xml/ws-security.js';

/**
 * The preparation core (internal; takes the entropy seam). It validates the
 * receiver certificate, spools the encrypted payload, builds and signs the
 * envelope, and writes a replayable artifact. `prepareAs4` in index.ts calls
 * this with the cryptographic RNG; tests reach it through `src/internal.ts`.
 */
export async function prepareAs4Internal(
  input: PrepareAs4Input,
  entropy: Entropy,
  createWorkspace: (options: TempWorkspaceOptions) => Promise<TempWorkspace> = createTempWorkspace,
): Promise<PrepareAs4Result> {
  const profile = input.profile ?? peppolProfile;
  const abort = input.signal;
  const onEvent = input.onEvent;
  const notPrepared = (reason: NotSentReason, detail?: string): PrepareAs4Result => ({
    outcome: 'not-prepared',
    reason,
    ...(detail ? { detail } : {}),
  });

  if (!isValidMessageId(input.as4MessageId)) return notPrepared('message-id.invalid');

  let receiverCertificate: X509Certificate;
  try {
    receiverCertificate = parseCertificate(input.receiverCertificate);
  } catch {
    return notPrepared('certificate.refused', 'receiver certificate is not readable');
  }
  if (abort?.aborted) return notPrepared('aborted');

  let workspace: TempWorkspace | null = null;
  let keep = false;
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
        return notPrepared('certificate.unavailable', receiverValidation.reason);
      return notPrepared('certificate.refused', receiverValidation.reason);
    }
    if (abort?.aborted) return notPrepared('aborted');

    workspace = await createWorkspace({
      ...(input.artifactDirectory ? { directory: input.artifactDirectory } : {}),
    });

    const { sessionKey, wrappedKey } = wrapSessionKey(receiverCertificate.publicKey, entropy);
    const payload = await timed(onEvent, 'prepare-payload', () =>
      preparePayload({
        source: input.payload,
        sessionKey,
        wrappedKey,
        filePath: workspace!.path('attachment.bin'),
        entropy,
        ...(abort ? { signal: abort } : {}),
      }),
    );

    // Stop starting new phases once the caller has cancelled.
    if (abort?.aborted) return notPrepared('aborted');

    // §7: the message timestamp is taken immediately before the envelope is
    // built, after certificate validation and payload spooling.
    const sentAt = input.now().toISOString();
    const attachmentHref = `cid:${entropy.uuid()}@${endpointHost(input.endpointUrl)}`;
    const fromPartyId = commonNameOf(parseCertificate(input.signer.certificate));
    const built = await timed(onEvent, 'sign', () =>
      buildEnvelope({
        userMessage: {
          messageId: input.as4MessageId,
          timestamp: sentAt,
          fromPartyId,
          toPartyId: commonNameOf(receiverCertificate),
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
        ...(abort ? { signal: abort } : {}),
      }),
    );

    const multipart = buildMultipartBody({
      soapXml: built.xml,
      attachmentHref,
      attachmentFilePath: payload.filePath,
      attachmentByteLength: payload.byteLength,
      entropy,
    });

    // The exact references the signature covers. They are stored verbatim and
    // reused on every transmission, so a retry keeps the signed representation.
    const signedReferences: SignedReference[] = [
      { uri: `#${built.bodyId}`, digest: built.bodyDigest },
      { uri: `#${built.messagingId}`, digest: built.messagingDigest },
      { uri: attachmentHref, digest: payload.compressedDigestBase64 },
    ];

    const message = await writePreparedMessage(workspace, {
      as4MessageId: input.as4MessageId,
      sentAt,
      endpointUrl: input.endpointUrl,
      transportProfile: input.transportProfile,
      receiverCertificateCommonName: commonNameOf(receiverCertificate),
      receiverCertificate: input.receiverCertificate,
      documentType: input.documentType,
      process: input.process,
      soapXml: built.xml,
      attachmentHref,
      boundary: multipart.boundary,
      soapContentId: multipart.soapContentId,
      attachmentByteLength: payload.byteLength,
      signedReferences,
    });
    keep = true;
    return { outcome: 'prepared', message };
  } catch (err) {
    if (err instanceof SenderFault) return notPrepared(mapSenderFault(err.reason), err.message);
    if (isAbortError(err)) return notPrepared('aborted', 'aborted while spooling the payload');
    if (isFileSystemError(err)) return notPrepared('spool.failed', safeMessage(err));
    return notPrepared('internal.error', safeMessage(err));
  } finally {
    // A failed preparation leaves nothing behind; a success hands the workspace to
    // the caller, which owns disposal. A failed cleanup is reported, never thrown.
    const ws = workspace;
    if (ws && !keep) await cleanupQuietly(() => ws.cleanup(), onEvent);
  }
}
