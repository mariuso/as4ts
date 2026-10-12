import { createReadStream } from 'node:fs';
import { Readable } from 'node:stream';
import { OCTET_STREAM_MEDIA_TYPE, SOAP_XML_MEDIA_TYPE } from './constants.js';
import { defaultEntropy, hexToken, type Entropy } from './entropy.js';

export interface MultipartInput {
  /** Serialized SOAP envelope. Must not contain an XML declaration. */
  readonly soapXml: string;
  /** `cid:` href used in the envelope PartInfo; e.g. `cid:abc@example`. */
  readonly attachmentHref: string;
  readonly attachmentFilePath: string;
  readonly attachmentByteLength: number;
  /** Test-only, pins the boundary and the SOAP part Content-ID. */
  readonly entropy?: Entropy;
}

export interface MultipartBody {
  readonly stream: Readable;
  readonly contentLength: number;
  readonly contentType: string;
  readonly boundary: string;
  readonly soapContentId: string;
}

const CRLF = '\r\n';

/**
 * Build a `multipart/related` body as a stream so a payload of any size is
 * never held in memory. The SOAP envelope is always the first part and the
 * encrypted payload the second ([PEPPOLAS4] §4.10, [AS4PROFILE] §5.2). The
 * payload part uses `binary` transfer encoding, so the ciphertext bytes go on
 * the wire as-is (no base64 inflation) and can be streamed from disk.
 */
export function buildMultipartBody(input: MultipartInput): MultipartBody {
  const entropy = input.entropy ?? defaultEntropy();
  const boundary = `----=_Part_${hexToken(entropy, 12)}`;
  const soapContentId = `soap-${hexToken(entropy, 12)}@as4-sender`;
  const bareCid = input.attachmentHref.replace(/^cid:/, '');

  const soapPartHeader =
    `--${boundary}${CRLF}` +
    `Content-Type: ${SOAP_XML_MEDIA_TYPE}; charset=UTF-8${CRLF}` +
    `Content-Transfer-Encoding: 8bit${CRLF}` +
    `Content-ID: <${soapContentId}>${CRLF}` +
    CRLF;
  const attachmentPartHeader =
    `${CRLF}--${boundary}${CRLF}` +
    `Content-Type: ${OCTET_STREAM_MEDIA_TYPE}${CRLF}` +
    `Content-Transfer-Encoding: binary${CRLF}` +
    `Content-ID: <${bareCid}>${CRLF}` +
    CRLF;
  const epilogue = `${CRLF}--${boundary}--${CRLF}`;

  const soapBytes = Buffer.from(input.soapXml, 'utf8');
  const prologue = Buffer.from(soapPartHeader, 'utf8');
  const between = Buffer.from(attachmentPartHeader, 'utf8');
  const closing = Buffer.from(epilogue, 'utf8');

  const contentLength =
    prologue.byteLength + soapBytes.byteLength + between.byteLength + input.attachmentByteLength + closing.byteLength;

  async function* body(): AsyncGenerator<Buffer> {
    yield prologue;
    yield soapBytes;
    yield between;
    const file = createReadStream(input.attachmentFilePath);
    for await (const chunk of file) yield chunk as Buffer;
    yield closing;
  }

  return {
    stream: Readable.from(body()),
    contentLength,
    boundary,
    soapContentId,
    contentType:
      `multipart/related; type="${SOAP_XML_MEDIA_TYPE}"; ` +
      `start="<${soapContentId}>"; start-info="${SOAP_XML_MEDIA_TYPE}"; boundary="${boundary}"`,
  };
}
