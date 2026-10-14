/**
 * The strict remote-XML parser lives in `src/xml/strict.ts` so receiving,
 * receipts and lookup share one implementation. This module remains the receiving
 * entry point and asserts that the shared fault reasons stay a subset of the
 * receiving failure reasons.
 */
import type { InboundFailureReason } from './types.js';
import type { XmlFaultReason } from '../xml/strict.js';

export {
  XmlFault,
  defaultXmlLimits,
  parseStrictXml,
  validateXmlLimits,
  type XmlFaultReason,
  type XmlLimits,
} from '../xml/strict.js';

type AssertAssignable<A extends B, B> = A;

/** Compile-time proof that every shared XML fault reason is a valid receive reason. */
export type XmlFaultReasonIsInboundReason = AssertAssignable<XmlFaultReason, InboundFailureReason>;
