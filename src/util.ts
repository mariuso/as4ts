import { createHash, X509Certificate } from 'node:crypto';

/** Extract all PEM certificate blocks from a string or array of strings. */
export function collectPemCertificates(input: string | readonly string[]): string[] {
  const parts = typeof input === 'string' ? [input] : input;
  const out: string[] = [];
  const end = '-----END CERTIFICATE-----';
  const begin = '-----BEGIN CERTIFICATE-----';
  for (const part of parts) {
    for (const chunk of part.split(end)) {
      const start = chunk.indexOf(begin);
      if (start < 0) continue;
      out.push(normalizePem(chunk.slice(start) + end));
    }
  }
  return out;
}

export function normalizePem(pem: string): string {
  const trimmed = pem.trim();
  const labelMatch = trimmed.match(/-----BEGIN ([A-Z0-9 ]+)-----/);
  const label = labelMatch?.[1] ?? 'CERTIFICATE';
  const body = trimmed.replace(/-----[A-Z0-9 ]+-----/g, '').replace(/\s+/g, '');
  const wrapped = (body.match(/.{1,64}/g) ?? []).join('\n');
  return `-----BEGIN ${label}-----\n${wrapped}\n-----END ${label}-----`;
}

export function parseCertificate(pem: string): X509Certificate {
  return new X509Certificate(pem);
}

/** SHA-256 fingerprint of the DER encoding, lowercase hex without separators. */
export function certFingerprint256(cert: X509Certificate): string {
  return cert.fingerprint256.replace(/:/g, '').toLowerCase();
}

export function sha256Base64(data: Buffer | Uint8Array): string {
  return createHash('sha256').update(data).digest('base64');
}

export function commonNameOf(cert: X509Certificate): string {
  const match = /(?:^|\n)\s*CN=([^\n]+)/.exec(cert.subject);
  return match?.[1]?.trim() ?? '';
}

/** True when two certificates are byte-identical (same DER). */
export function sameCertificate(a: X509Certificate, b: X509Certificate): boolean {
  return Buffer.compare(Buffer.from(a.raw), Buffer.from(b.raw)) === 0;
}

/**
 * True when `value` is an RFC 2822 `msg-id` without the surrounding angle
 * brackets, as required for eb:MessageId by [CEF] §3.2.2. Kept pragmatic:
 * exactly one `@`, no whitespace or reserved characters, and a dot-atom-ish
 * left part with a dot-atom or domain-literal right part.
 */
export function isValidMessageId(value: string): boolean {
  if (typeof value !== 'string') return false;
  if (value.length === 0 || value.length > 320) return false;
  if (value !== value.trim()) return false;
  if (/[\s<>",;\\]/.test(value)) return false;
  const parts = value.split('@');
  if (parts.length !== 2) return false;
  const [left, right] = parts as [string, string];
  const atom = /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*$/;
  const domain = /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*$/;
  const literal = /^\[[^\]\s]+\]$/;
  if (!left || !right) return false;
  if (!atom.test(left)) return false;
  return domain.test(right) || literal.test(right);
}

/**
 * Reduce an unknown thrown value to a short, secret-free message.
 * Keys, payload bytes and passphrases never appear in our own error messages,
 * but this also strips anything that looks like PEM material defensively.
 */
export function safeMessage(err: unknown): string {
  const raw = err instanceof Error ? err.message : String(err);
  return raw
    .replace(/-----BEGIN[\s\S]*?-----END [A-Z ]+-----/g, '[redacted]')
    .replace(/[A-Za-z0-9+/=]{80,}/g, '[redacted]')
    .slice(0, 300);
}
