import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { attachmentDigestBase64 } from '../src/receive/attachment.js';

const raw = (bytes: Buffer): string => createHash('sha256').update(bytes).digest('base64');

test('binary and gzip attachments are digested as raw bytes', () => {
  const gzip = Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0x02, 0x03, 0x04]);
  assert.equal(attachmentDigestBase64('application/octet-stream', gzip), raw(gzip));
  assert.equal(attachmentDigestBase64('application/gzip', gzip), raw(gzip));
});

test('XML attachments are canonicalised before digesting', () => {
  const a = Buffer.from('<a c="1" b="2"><x/></a>', 'utf8');
  const b = Buffer.from('<a b="2" c="1"><x/></a>', 'utf8');
  // Attribute order differs, but the canonical form (and digest) is equal.
  assert.equal(attachmentDigestBase64('application/xml', a), attachmentDigestBase64('application/xml', b));
  // And it is not the raw-byte digest, which is order-sensitive.
  assert.notEqual(attachmentDigestBase64('application/xml', a), raw(a));
});

test('a media-type parameter does not change the XML decision', () => {
  const xml = Buffer.from('<a/>', 'utf8');
  assert.equal(
    attachmentDigestBase64('application/xml; charset=UTF-8', xml),
    attachmentDigestBase64('application/xml', xml),
  );
});
