import { EBMS_ERROR_CODE_NOT_SERVICED, EBMS_ERROR_CODE_NOT_SERVICED_DETAIL } from '../constants.js';
import { EBMS_ERROR_DEFINITIONS } from '../ebms-errors.js';
import type { EbmsErrorSpec, InboundFailure, InboundFailureReason } from './types.js';

/**
 * The deliberate inbound failure -> ebMS error mapping (Phase 5). The protocol
 * facts (name, severity, category) come from the shared
 * {@link EBMS_ERROR_DEFINITIONS}, so receiving error construction does not
 * depend on the sender's retry classification.
 *
 * The wire error carries no free-form local diagnostics: an internal
 * `failure.detail` is for logs, not for the peer.
 */
const CODE_BY_REASON: Readonly<Record<InboundFailureReason, string>> = {
  'body.too-large': 'EBMS:0202',
  aborted: 'EBMS:0202',
  'mime.content-type-invalid': 'EBMS:0007',
  'mime.boundary-invalid': 'EBMS:0007',
  'mime.parts-too-many': 'EBMS:0007',
  'mime.header-too-large': 'EBMS:0007',
  'mime.part-too-large': 'EBMS:0007',
  'mime.malformed': 'EBMS:0007',
  'mime.duplicate-header': 'EBMS:0007',
  'mime.no-soap-part': 'EBMS:0007',
  'mime.ambiguous-root': 'EBMS:0007',
  'mime.duplicate-content-id': 'EBMS:0007',
  'xml.malformed': 'EBMS:0009',
  'xml.doctype': 'EBMS:0009',
  'xml.too-large': 'EBMS:0009',
  'xml.too-deep': 'EBMS:0009',
  'xml.too-many-nodes': 'EBMS:0009',
  'signature.malformed': 'EBMS:0101',
  'signature.bad-signature': 'EBMS:0101',
  'signature.digest-mismatch': 'EBMS:0101',
  'signature.coverage': 'EBMS:0101',
  'signature.attachment-digest': 'EBMS:0101',
  'certificate.untrusted': 'EBMS:0101',
  'certificate.revoked': 'EBMS:0101',
  'certificate.unavailable': 'EBMS:0101',
  'encryption.invalid': 'EBMS:0102',
  'decrypt.unsupported-algorithm': 'EBMS:0102',
  'decrypt.key-unwrap': 'EBMS:0102',
  'decrypt.key-unavailable': 'EBMS:0102',
  'decrypt.bad-key-length': 'EBMS:0102',
  'decrypt.gcm-auth': 'EBMS:0102',
  'decompress.failed': 'EBMS:0303',
  'decompress.too-large': 'EBMS:0303',
  'addressing.party-mismatch': 'EBMS:0103',
  'addressing.invalid-header': 'EBMS:0009',
  'addressing.pmode-mismatch': 'EBMS:0010',
  'addressing.mpc': 'EBMS:0010',
  'addressing.sbdh-mismatch': 'EBMS:0003',
  'limits.invalid': 'EBMS:0202',
  'payload.spool-failed': 'EBMS:0202',
  'payload.too-large': 'EBMS:0202',
  'internal.error': 'EBMS:0202',
};

/** The ebMS error to return for a failed `open`, with the protocol severity. */
export function ebmsErrorFor(failure: InboundFailure): EbmsErrorSpec {
  const code = CODE_BY_REASON[failure.reason];
  const definition = EBMS_ERROR_DEFINITIONS[code as keyof typeof EBMS_ERROR_DEFINITIONS];
  return {
    code,
    severity: definition?.severity ?? 'failure',
    ...(definition?.name ? { shortDescription: definition.name } : {}),
  };
}

/**
 * The error for a participant/document/process combination this receiver does
 * not service. The serviced-participant decision is the caller's; this packages
 * the Peppol-mandated result (EBMS:0004 with `PEPPOL:NOT_SERVICED`).
 */
export function notServicedError(): EbmsErrorSpec {
  return {
    code: EBMS_ERROR_CODE_NOT_SERVICED,
    severity: 'failure',
    detail: EBMS_ERROR_CODE_NOT_SERVICED_DETAIL,
  };
}
