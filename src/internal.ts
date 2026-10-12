/**
 * Test-only internals. Not part of the package surface (see
 * `test/package-surface.test.ts`). Tests import from here to inject a
 * deterministic entropy source, which the public `sendAs4` deliberately does
 * not accept.
 */
export { sendAs4Internal } from './send.js';
export { defaultEntropy } from './entropy.js';
export type { Entropy } from './entropy.js';
