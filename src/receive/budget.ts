/**
 * A message-scoped budget for aggregate decompressed output. A per-attachment
 * limit cannot bound the total a message may consume, so a caller recovering
 * several attachments shares one instance across the calls. It is not
 * concurrency-safe: a single recovery orchestration owns it.
 *
 * The maximum must be a non-negative safe integer, and reservations must be
 * non-negative safe integers; an invalid value is rejected explicitly rather than
 * silently removing the bound. `0` legitimately represents an exhausted budget.
 */
export class MessageBudget {
  private used = 0;
  private readonly maxBytes: number;

  constructor(maxBytes: number) {
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
      throw new RangeError('MessageBudget maximum must be a non-negative safe integer');
    }
    this.maxBytes = maxBytes;
  }

  /** Bytes still available across the message. */
  remaining(): number {
    return this.maxBytes - this.used;
  }

  /**
   * Reserve `bytes`. Returns true and records the reservation when it fits;
   * returns false without recording anything when it would exceed the budget.
   * Throws for a reservation that is not a non-negative safe integer.
   */
  reserve(bytes: number): boolean {
    if (!Number.isSafeInteger(bytes) || bytes < 0) {
      throw new RangeError('MessageBudget reservation must be a non-negative safe integer');
    }
    if (bytes > this.remaining()) return false;
    this.used += bytes;
    return true;
  }
}
