import { parseSignal, type ParsedSignal } from '../../src/xml/signal.js';
import type { ResponseLimits } from '../../src/response-limits.js';

/** The pre-Item-6 shape: a parsed signal, or null when it could not be read. */
export function parseSignalOrNull(bytes: Buffer, limits?: ResponseLimits): ParsedSignal | null {
  const parsed = parseSignal(bytes, limits);
  return parsed.ok ? parsed.signal : null;
}

/** Parse a signal expected to be readable; throw with the strict reason otherwise. */
export function parseSignalOrThrow(bytes: Buffer, limits?: ResponseLimits): ParsedSignal {
  const parsed = parseSignal(bytes, limits);
  if (!parsed.ok) throw new Error(`parseSignal failed: ${parsed.reason}`);
  return parsed.signal;
}
