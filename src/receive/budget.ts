/**
 * A message-scoped budget for aggregate decompressed output. A per-attachment
 * limit cannot bound the total a message may consume, so a caller recovering
 * several attachments shares one instance across the calls. It is not
 * concurrency-safe: a single recovery orchestration owns it.
 */
export class MessageBudget {
  private used = 0;

  constructor(private readonly maxBytes: number) {}

  /** Bytes still available across the message. */
  remaining(): number {
    return Math.max(0, this.maxBytes - this.used);
  }

  /**
   * Reserve `bytes`. Returns true and records the reservation when it fits;
   * returns false without recording anything when it would exceed the budget.
   */
  reserve(bytes: number): boolean {
    if (!Number.isFinite(bytes) || bytes < 0) return false;
    if (bytes > this.remaining()) return false;
    this.used += bytes;
    return true;
  }
}
