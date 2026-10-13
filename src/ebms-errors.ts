/**
 * Direction-neutral ebMS 3.0 / AS4 error metadata: code, name, severity and
 * category, straight from [EBMS3CORE] §6.2 and [AS4PROFILE] §3.6. This is the
 * shared source of truth for both the sender's outcome classification and the
 * receiver's error-signal construction; neither side may own the definitions.
 *
 * Retry/acceptance policy (`OutcomeClass`) is a sender concern and stays in
 * `outcome.ts`; only the protocol facts live here.
 */
export type EbmsErrorSeverity = 'failure' | 'warning';

export interface EbmsErrorDefinition {
  readonly name: string;
  readonly severity: EbmsErrorSeverity;
  readonly category: string;
}

export const EBMS_ERROR_DEFINITIONS = {
  'EBMS:0001': { name: 'ValueNotRecognized', severity: 'failure', category: 'Content' },
  'EBMS:0002': { name: 'FeatureNotSupported', severity: 'warning', category: 'Content' },
  'EBMS:0003': { name: 'ValueInconsistent', severity: 'failure', category: 'Content' },
  'EBMS:0004': { name: 'Other', severity: 'failure', category: 'Content' },
  'EBMS:0005': { name: 'ConnectionFailure', severity: 'failure', category: 'Communication' },
  'EBMS:0006': { name: 'EmptyMessagePartitionChannel', severity: 'warning', category: 'Communication' },
  'EBMS:0007': { name: 'MimeInconsistency', severity: 'failure', category: 'Unpackaging' },
  'EBMS:0008': { name: 'FeatureNotSupported', severity: 'failure', category: 'Unpackaging' },
  'EBMS:0009': { name: 'InvalidHeader', severity: 'failure', category: 'Unpackaging' },
  'EBMS:0010': { name: 'ProcessingModeMismatch', severity: 'failure', category: 'Processing' },
  'EBMS:0011': { name: 'ExternalPayloadError', severity: 'failure', category: 'Content' },
  'EBMS:0101': { name: 'FailedAuthentication', severity: 'failure', category: 'Processing' },
  'EBMS:0102': { name: 'FailedDecryption', severity: 'failure', category: 'Processing' },
  'EBMS:0103': { name: 'PolicyNoncompliance', severity: 'failure', category: 'Processing' },
  'EBMS:0201': { name: 'DysfunctionalReliability', severity: 'failure', category: 'Processing' },
  'EBMS:0202': { name: 'DeliveryFailure', severity: 'failure', category: 'Communication' },
  'EBMS:0301': { name: 'MissingReceipt', severity: 'failure', category: 'Communication' },
  'EBMS:0302': { name: 'InvalidReceipt', severity: 'failure', category: 'Communication' },
  'EBMS:0303': { name: 'DecompressionFailure', severity: 'failure', category: 'Communication' },
} as const satisfies Readonly<Record<string, EbmsErrorDefinition>>;
