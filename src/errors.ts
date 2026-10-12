/**
 * Internal, non-exported failure carriers. Expected failures are converted to
 * values by the entry point; nothing here ever reaches the caller as a thrown
 * exception. None of these carry secret material.
 */

export class SenderFault extends Error {
  readonly reason: string;
  constructor(reason: string, message: string) {
    super(message);
    this.name = 'SenderFault';
    this.reason = reason;
  }
}

export interface TransportFailureInfo {
  /** Node error code when available. */
  readonly code?: string;
  /**
   * Conservative fact: true once the connection was established, after which
   * request bytes may have reached the receiver. It can be true even when no
   * body byte was flushed, but is false only when the request definitely was not
   * sent.
   */
  readonly requestMayHaveBeenSent: boolean;
  readonly responseStarted: boolean;
  /** True when the attempt was stopped by the caller's AbortSignal. */
  readonly aborted: boolean;
}

export class TransportError extends Error {
  readonly info: TransportFailureInfo;
  constructor(message: string, info: TransportFailureInfo) {
    super(message);
    this.name = 'TransportError';
    this.info = info;
  }
}
