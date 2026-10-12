/**
 * A small, read-only ASN.1 DER reader. It only understands the constructions
 * needed to pull revocation endpoints, serial numbers and dates out of X.509
 * certificates and CRLs. It never parses untrusted data on a path that decides
 * signature validity; Node's OpenSSL-backed crypto does that.
 */

export const enum DerClass {
  Universal = 0,
  Application = 1,
  Context = 2,
  Private = 3,
}

export interface DerNode {
  readonly cls: DerClass;
  readonly constructed: boolean;
  readonly tag: number;
  /** Raw TLV bytes, including the header. */
  readonly raw: Buffer;
  /** Content bytes only. */
  readonly value: Buffer;
}

export interface DerParseResult {
  readonly node: DerNode;
  readonly end: number;
}

export function parseDer(buf: Buffer, offset = 0): DerParseResult {
  if (offset + 2 > buf.length) throw new Error('DER: truncated header');
  const first = buf[offset]!;
  const cls = (first >> 6) as DerClass;
  const constructed = (first & 0x20) !== 0;
  let tag = first & 0x1f;
  let cursor = offset + 1;
  if (tag === 0x1f) {
    tag = 0;
    for (;;) {
      const b = buf[cursor++]!;
      tag = (tag << 7) | (b & 0x7f);
      if ((b & 0x80) === 0) break;
    }
  }
  let length = buf[cursor++]!;
  if ((length & 0x80) !== 0) {
    const count = length & 0x7f;
    if (count === 0 || count > 4) throw new Error('DER: unsupported length');
    length = 0;
    for (let i = 0; i < count; i += 1) length = (length << 8) | buf[cursor++]!;
  }
  const valueStart = cursor;
  const valueEnd = valueStart + length;
  if (valueEnd > buf.length) throw new Error('DER: truncated value');
  return {
    node: {
      cls,
      constructed,
      tag,
      raw: buf.subarray(offset, valueEnd),
      value: buf.subarray(valueStart, valueEnd),
    },
    end: valueEnd,
  };
}

export function children(node: DerNode): DerNode[] {
  const out: DerNode[] = [];
  let offset = 0;
  while (offset < node.value.length) {
    const { node: child, end } = parseDer(node.value, offset);
    out.push(child);
    offset = end;
  }
  return out;
}

export function isUniversal(node: DerNode, tag: number): boolean {
  return node.cls === DerClass.Universal && node.tag === tag;
}

export const TAG = {
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  SEQUENCE: 0x10,
  SET: 0x11,
  UTC_TIME: 0x17,
  GENERALIZED_TIME: 0x18,
  IA5_STRING: 0x16,
} as const;

export function decodeOid(value: Buffer): string {
  if (value.length === 0) return '';
  const parts: number[] = [];
  let first = value[0]!;
  parts.push(Math.floor(first / 40), first % 40);
  let acc = 0;
  for (let i = 1; i < value.length; i += 1) {
    const b = value[i]!;
    acc = (acc << 7) | (b & 0x7f);
    if ((b & 0x80) === 0) {
      parts.push(acc);
      acc = 0;
    }
  }
  return parts.join('.');
}

/** Serial number as lowercase hex, without sign. */
export function decodeIntegerHex(value: Buffer): string {
  let start = 0;
  while (start < value.length - 1 && value[start] === 0x00) start += 1;
  return value.subarray(start).toString('hex').toLowerCase();
}

/** Parse UTCTime / GeneralizedTime into a Date. */
export function decodeTime(node: DerNode): Date {
  const text = node.value.toString('latin1');
  if (node.tag === TAG.UTC_TIME) {
    // YYMMDDHHMMSSZ
    const yy = Number(text.slice(0, 2));
    const year = yy >= 50 ? 1900 + yy : 2000 + yy;
    return new Date(
      Date.UTC(
        year,
        Number(text.slice(2, 4)) - 1,
        Number(text.slice(4, 6)),
        Number(text.slice(6, 8)),
        Number(text.slice(8, 10)),
        Number(text.slice(10, 12)),
      ),
    );
  }
  // YYYYMMDDHHMMSSZ
  return new Date(
    Date.UTC(
      Number(text.slice(0, 4)),
      Number(text.slice(4, 6)) - 1,
      Number(text.slice(6, 8)),
      Number(text.slice(8, 10)),
      Number(text.slice(10, 12)),
      Number(text.slice(12, 14)),
    ),
  );
}

// ---------------------------------------------------------------------------
// Minimal DER encoder, used only to build OCSP requests.
// ---------------------------------------------------------------------------

function encodeLength(length: number): Buffer {
  if (length < 0x80) return Buffer.from([length]);
  const bytes: number[] = [];
  let n = length;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

export function tlv(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), encodeLength(content.length), content]);
}

export function derSequence(...items: Buffer[]): Buffer {
  return tlv(0x30, Buffer.concat(items));
}

export function derOid(oid: string): Buffer {
  const parts = oid.split('.').map((p) => Number(p));
  const bytes: number[] = [parts[0]! * 40 + parts[1]!];
  for (let i = 2; i < parts.length; i += 1) {
    let value = parts[i]!;
    const stack: number[] = [value & 0x7f];
    value >>= 7;
    while (value > 0) {
      stack.unshift((value & 0x7f) | 0x80);
      value >>= 7;
    }
    bytes.push(...stack);
  }
  return tlv(0x06, Buffer.from(bytes));
}

export function derNull(): Buffer {
  return tlv(0x05, Buffer.alloc(0));
}

export function derOctetString(content: Buffer): Buffer {
  return tlv(0x04, content);
}

export function derInteger(value: Buffer): Buffer {
  let v = value;
  while (v.length > 1 && v[0] === 0x00 && (v[1]! & 0x80) === 0) v = v.subarray(1);
  if (v.length === 0) v = Buffer.from([0]);
  if ((v[0]! & 0x80) !== 0) v = Buffer.concat([Buffer.from([0x00]), v]);
  return tlv(0x02, v);
}

export function derContext(tag: number, content: Buffer, constructed = false): Buffer {
  return tlv((constructed ? 0xa0 : 0x80) | tag, content);
}

export function derBitString(content: Buffer, unusedBits = 0): Buffer {
  return tlv(0x03, Buffer.concat([Buffer.from([unusedBits]), content]));
}
