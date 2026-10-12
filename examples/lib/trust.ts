import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import type { SmEnv } from './smp.js';

const here = dirname(fileURLToPath(import.meta.url));
const TRUST_DIR = join(here, '..', '..', 'assets', 'trust');

export interface BundledTrust {
  /** Peppol root trust anchor(s) for the environment. */
  readonly roots: readonly string[];
  /** Peppol access point intermediate CA(s) for the environment. */
  readonly intermediates: readonly string[];
}

/**
 * Peppol trust anchors shipped with the repo. These are the public certificates
 * OpenPeppol provides for the test and production environments: the root, the
 * access-point CA (issues the AS4 AP certificates we encrypt to and verify
 * receipts with) and the service-metadata-publisher CA. Targets are prefixed
 * test-/prod- in assets/trust and are refreshed by `npm run trust:update`.
 *
 * The root is long-lived. The CAs rotate (G3 today), so re-run the update if
 * validation starts failing with "no trusted issuer".
 */
export function bundledTrust(env: SmEnv): BundledTrust {
  const prefix = env === 'test' ? 'test' : 'prod';
  const read = (name: string): string => readFileSync(join(TRUST_DIR, `${prefix}-${name}.pem`), 'utf8');
  return {
    roots: [read('root')],
    intermediates: [read('apca'), read('smpca')],
  };
}

export function trustDir(): string {
  return TRUST_DIR;
}
