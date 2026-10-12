import type { Entropy } from '../../src/entropy.js';

/** A deterministic Entropy: byte values count up from zero; uuid is fixed. */
export function fixedEntropy(): Entropy {
  let counter = 0;
  return {
    bytes: (length) => {
      const out = Buffer.alloc(length);
      for (let i = 0; i < length; i += 1) out[i] = counter++ & 0xff;
      return out;
    },
    uuid: () => '11111111-2222-4333-8444-555555555555',
  };
}
