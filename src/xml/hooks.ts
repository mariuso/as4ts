/**
 * Instrumentation hooks for the expensive shared XML operations. Receiving tests
 * use these to prove that an over-budget document never reaches the DOM parser or
 * the canonicaliser — "the call failed" alone does not prove it failed before
 * allocation. Observe only; never receives document content.
 */
export const xmlHooks: {
  /** Called immediately before a DOM parser is constructed. */
  onDomParse?: () => void;
  /** Called immediately before the canonicaliser processes a node. */
  onCanonicalize?: () => void;
} = {};
