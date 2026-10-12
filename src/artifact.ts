import { createReadStream } from 'node:fs';
import { readFile, rm, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { PreparedMessage, ScopedId } from './types.js';
import type { TempWorkspace } from './temp-file.js';
import type { SignedReference } from './xml/ws-security.js';

/** Artifact format version, written into `metadata.json` and checked on load. */
const ARTIFACT_VERSION = 1;
const METADATA_FILE = 'metadata.json';
const ATTACHMENT_FILE = 'attachment.bin';

/** The fields of a prepared message that are persisted to disk. */
export interface PreparedMessageFields {
  readonly as4MessageId: string;
  readonly sentAt: string;
  readonly endpointUrl: string;
  readonly transportProfile: string;
  readonly receiverCertificateCommonName: string;
  readonly receiverCertificate: string;
  readonly documentType: ScopedId;
  readonly process: ScopedId;
  readonly soapXml: string;
  readonly attachmentHref: string;
  readonly boundary: string;
  readonly soapContentId: string;
  readonly attachmentByteLength: number;
  readonly signedReferences: readonly SignedReference[];
}

interface ArtifactMetadata extends PreparedMessageFields {
  readonly version: number;
  readonly attachmentFile: string;
}

/**
 * Write the artifact metadata for an already-spooled attachment and return the
 * message value. The encrypted attachment must already exist at
 * `<directory>/attachment.bin`; this never removes it.
 */
export async function writePreparedMessage(
  workspace: TempWorkspace,
  fields: PreparedMessageFields,
): Promise<PreparedMessage> {
  const metadata: ArtifactMetadata = { version: ARTIFACT_VERSION, attachmentFile: ATTACHMENT_FILE, ...fields };
  await writeFile(join(workspace.dir, METADATA_FILE), JSON.stringify(metadata), { mode: 0o600 });
  return messageFrom(workspace.dir, metadata, () => workspace.cleanup());
}

/** Artifact fields that must be present, non-empty strings. */
const REQUIRED_STRING_FIELDS = [
  'as4MessageId',
  'sentAt',
  'endpointUrl',
  'transportProfile',
  'receiverCertificateCommonName',
  'receiverCertificate',
  'soapXml',
  'attachmentHref',
  'boundary',
  'soapContentId',
] as const;

/**
 * Reload a persisted artifact from `directory`. Every required field is
 * validated, the attachment name is pinned to the v1 layout, and the attachment
 * must be a regular file of the recorded size — an incomplete artifact is
 * rejected before it can be transmitted.
 */
export async function loadPreparedMessage(directory: string): Promise<PreparedMessage> {
  let metadata: ArtifactMetadata;
  try {
    metadata = JSON.parse(await readFile(join(directory, METADATA_FILE), 'utf8')) as ArtifactMetadata;
  } catch {
    throw new Error(`not an as4ts artifact: ${directory}`);
  }
  if (metadata.version !== ARTIFACT_VERSION) {
    throw new Error(`unsupported as4ts artifact version ${metadata.version}`);
  }
  // The v1 layout has a single attachment; a different name would make
  // readAttachment() and transmission read different files.
  if (metadata.attachmentFile !== ATTACHMENT_FILE) {
    throw new Error(`unsupported artifact attachment name ${String(metadata.attachmentFile)}`);
  }
  for (const key of REQUIRED_STRING_FIELDS) {
    if (typeof metadata[key] !== 'string' || metadata[key] === '') {
      throw new Error(`artifact metadata is missing ${key}`);
    }
  }
  if (!isScopedId(metadata.documentType) || !isScopedId(metadata.process)) {
    throw new Error('artifact metadata has an invalid document type or process');
  }
  if (
    typeof metadata.attachmentByteLength !== 'number' ||
    !Number.isInteger(metadata.attachmentByteLength) ||
    metadata.attachmentByteLength < 0
  ) {
    throw new Error('artifact metadata has an invalid attachment length');
  }
  if (!isSignedReferenceList(metadata.signedReferences)) {
    throw new Error('artifact metadata has invalid signed references');
  }
  const attachmentPath = join(directory, ATTACHMENT_FILE);
  const info = await stat(attachmentPath).catch(() => null);
  if (!info || !info.isFile()) throw new Error('artifact attachment is missing');
  if (info.size !== metadata.attachmentByteLength) {
    throw new Error('artifact attachment does not match its metadata');
  }
  return messageFrom(directory, metadata, () => rm(directory, { recursive: true, force: true }));
}

function isScopedId(value: unknown): value is ScopedId {
  if (typeof value !== 'object' || value === null) return false;
  const candidate = value as Partial<ScopedId>;
  return typeof candidate.scheme === 'string' && typeof candidate.value === 'string';
}

function isSignedReferenceList(value: unknown): value is SignedReference[] {
  return (
    Array.isArray(value) &&
    value.length > 0 &&
    value.every(
      (reference) =>
        typeof reference === 'object' &&
        reference !== null &&
        typeof (reference as SignedReference).uri === 'string' &&
        typeof (reference as SignedReference).digest === 'string',
    )
  );
}

/** Absolute path of the encrypted attachment for a prepared message (v1 layout). */
export function attachmentPathOf(message: PreparedMessage): string {
  return join(message.directory, ATTACHMENT_FILE);
}

function messageFrom(directory: string, metadata: ArtifactMetadata, dispose: () => Promise<void>): PreparedMessage {
  const attachmentPath = join(directory, metadata.attachmentFile ?? ATTACHMENT_FILE);
  return {
    as4MessageId: metadata.as4MessageId,
    sentAt: metadata.sentAt,
    endpointUrl: metadata.endpointUrl,
    transportProfile: metadata.transportProfile,
    receiverCertificateCommonName: metadata.receiverCertificateCommonName,
    receiverCertificate: metadata.receiverCertificate,
    documentType: metadata.documentType,
    process: metadata.process,
    soapXml: metadata.soapXml,
    attachmentHref: metadata.attachmentHref,
    boundary: metadata.boundary,
    soapContentId: metadata.soapContentId,
    attachmentByteLength: metadata.attachmentByteLength,
    signedReferences: metadata.signedReferences,
    directory,
    readAttachment: () => createReadStream(attachmentPath),
    dispose,
  };
}
