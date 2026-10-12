import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

export interface TempWorkspace {
  readonly dir: string;
  /** Resolve a path inside the workspace. */
  path(name: string): string;
  /** Remove the whole workspace. Safe to call more than once. */
  cleanup(): Promise<void>;
}

export interface TempWorkspaceOptions {
  /** Parent directory. Defaults to the OS temp directory. */
  readonly directory?: string;
  readonly prefix?: string;
}

/**
 * A private scratch directory. Ciphertext is streamed here so that a payload of
 * any size never has to fit in memory. `mkdtemp` creates it with mode 0700 and
 * it is removed on every path by the caller's `finally`.
 */
export async function createTempWorkspace(options: TempWorkspaceOptions = {}): Promise<TempWorkspace> {
  const dir = await mkdtemp(join(options.directory ?? tmpdir(), options.prefix ?? 'as4-sender-'));
  let cleaned = false;
  return {
    dir,
    path: (name: string) => join(dir, name),
    async cleanup() {
      if (cleaned) return;
      cleaned = true;
      await rm(dir, { recursive: true, force: true });
    },
  };
}
