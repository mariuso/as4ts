import { prepareAs4Internal } from './prepare.js';
import { transmitAs4 } from './transmit.js';
import { createTempWorkspace, type TempWorkspace, type TempWorkspaceOptions } from './temp-file.js';
import { emit } from './send-common.js';
import { commonNameOf, parseCertificate, safeMessage } from './util.js';
import type { Entropy } from './entropy.js';
import type { NotSentReason, OnEvent, PreparedMessage, SendAs4Input, SendAs4Result } from './types.js';

/**
 * The one-shot send core: prepare once, transmit once, dispose. It is the
 * convenience path over `prepareAs4` + `transmitAs4` and keeps the historical
 * `sendAs4` contract. Not part of the package surface (the entropy seam is
 * internal); `sendAs4` in index.ts calls this, and tests reach it through
 * `src/internal.ts`.
 */
export async function sendAs4Internal(
  input: SendAs4Input,
  entropy: Entropy,
  createWorkspace: (options: TempWorkspaceOptions) => Promise<TempWorkspace> = createTempWorkspace,
): Promise<SendAs4Result> {
  let receiverCertificateCommonName = '';
  try {
    receiverCertificateCommonName = commonNameOf(parseCertificate(input.receiverCertificate));
  } catch {
    // unreadable receiver certificate; the preparation will refuse it
  }
  const base = (): {
    as4MessageId: string;
    receiverCertificateCommonName: string;
    transportProfile: string;
  } => ({
    as4MessageId: input.as4MessageId,
    receiverCertificateCommonName,
    transportProfile: input.transportProfile,
  });
  const notSent = (reason: NotSentReason, detail?: string): SendAs4Result => ({
    ...base(),
    outcome: 'not-sent',
    reason,
    ...(detail ? { detail } : {}),
  });

  const prepared = await prepareAs4Internal(
    {
      payload: input.payload,
      endpointUrl: input.endpointUrl,
      transportProfile: input.transportProfile,
      receiverCertificate: input.receiverCertificate,
      senderParticipant: input.senderParticipant,
      receiverParticipant: input.receiverParticipant,
      documentType: input.documentType,
      process: input.process,
      as4MessageId: input.as4MessageId,
      signer: input.signer,
      validateCertificate: input.validateCertificate,
      ...(input.profile ? { profile: input.profile } : {}),
      ...(input.signal ? { signal: input.signal } : {}),
      ...(input.spoolDirectory ? { artifactDirectory: input.spoolDirectory } : {}),
      ...(input.onEvent ? { onEvent: input.onEvent } : {}),
      now: input.now,
    },
    entropy,
    createWorkspace,
  );

  if (prepared.outcome !== 'prepared') return notSent(prepared.reason, prepared.detail);

  try {
    return await transmitAs4({
      message: prepared.message,
      validateCertificate: input.validateCertificate,
      http: input.http,
      ...(input.signal ? { signal: input.signal } : {}),
      ...(input.onEvent ? { onEvent: input.onEvent } : {}),
      now: input.now,
    });
  } finally {
    await cleanupMessage(prepared.message, input.onEvent);
  }
}

/**
 * Remove the artifact without letting a cleanup failure mask an already-computed
 * result. A `cleanup` event carries a secret-free reason so the caller can retry.
 */
async function cleanupMessage(message: PreparedMessage, onEvent: OnEvent | undefined): Promise<void> {
  const start = performance.now();
  try {
    await message.dispose();
  } catch (err) {
    emit(onEvent, { phase: 'cleanup', durationMs: performance.now() - start, error: safeMessage(err) });
  }
}
