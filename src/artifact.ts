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

/**
 * Reload a persisted artifact from `directory`. Throws when the metadata is
 * missing/unsupported or the attachment is absent or the wrong size.
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
  for (const key of ['as4MessageId', 'soapXml', 'attachmentHref', 'boundary', 'soapContentId'] as const) {
    if (typeof metadata[key] !== 'string' || metadata[key] === '') {
      throw new Error(`artifact metadata is missing ${key}`);
    }
  }
  const attachmentPath = join(directory, metadata.attachmentFile ?? ATTACHMENT_FILE);
  const info = await stat(attachmentPath).catch(() => null);
  if (!info) throw new Error('artifact attachment is missing');
  if (info.size !== metadata.attachmentByteLength) {
    throw new Error('artifact attachment does not match its metadata');
  }
  return messageFrom(directory, metadata, () => rm(directory, { recursive: true, force: true }));
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
