/**
 * Redact secret-bearing flags from a command line before it is written to logs,
 * traces or evidence. Values (and `--flag=value` forms) of any flag whose name
 * looks like key material or a passphrase are replaced with `[redacted]`.
 */
const SECRET = /(^|[-_])(p12|pfx|pass|passphrase|password|secret|key)($|[-_])/i;

export function redactArgv(argv: readonly string[]): string {
  const out: string[] = [];
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i]!;
    if (!token.startsWith('--')) {
      out.push(token);
      continue;
    }
    const eq = token.indexOf('=');
    const name = (eq >= 0 ? token.slice(2, eq) : token.slice(2)).toLowerCase();
    if (!SECRET.test(name)) {
      out.push(token);
      continue;
    }
    if (eq >= 0) {
      out.push(`--${name}=[redacted]`);
    } else {
      out.push(`--${name}`);
      if (argv[i + 1] !== undefined) {
        out.push('[redacted]');
        i += 1;
      }
    }
  }
  return out.join(' ');
}

/** Redact secret flag values that appear inside a free-form message. */
export function redactMessage(message: string, argv: readonly string[]): string {
  let redacted = message;
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i]!;
    if (!token.startsWith('--')) continue;
    const eq = token.indexOf('=');
    const name = (eq >= 0 ? token.slice(2, eq) : token.slice(2)).toLowerCase();
    if (!SECRET.test(name)) continue;
    const value = eq >= 0 ? token.slice(eq + 1) : argv[i + 1];
    if (value && value.length > 0) redacted = redacted.split(value).join('[redacted]');
  }
  return redacted;
}
