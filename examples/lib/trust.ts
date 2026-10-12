import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

/** Peppol environment. The SML zone is passed explicitly; see {@link smlZone}. */
export type SmEnv = 'test' | 'prod';

const here = dirname(fileURLToPath(import.meta.url));
const TRUST_DIR = join(here, '..', '..', 'assets', 'trust');

export interface BundledTrust {
  /** Peppol root trust anchor(s) for the environment. */
  readonly roots: readonly string[];
  /** Peppol access point intermediate CA(s) for the environment. */
  readonly intermediates: readonly string[];
  /** Access-point CA(s), used for the receiver and receipt purposes. */
  readonly apIntermediates: readonly string[];
  /** Service-metadata-publisher CA(s), used for the `smp-signer` purpose. */
  readonly smpIntermediates: readonly string[];
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
  const apca = read('apca');
  const smpca = read('smpca');
  return {
    roots: [read('root')],
    intermediates: [apca, smpca],
    apIntermediates: [apca],
    smpIntermediates: [smpca],
  };
}

/**
 * The SML zone for an environment. The test zone is verified by DNS. The
 * production zone could not be confirmed against a specification release and is
 * marked UNVERIFIED in the README; pass `--sml` to override it. [PFUOI4] v4.4.0
 * changed POLICY 7's DNS zone name.
 */
export function smlZone(env: SmEnv): string {
  return env === 'test' ? 'participant.sml.test.tech.peppol.org' : 'participant.sml.tech.peppol.org';
}

export function trustDir(): string {
  return TRUST_DIR;
}
