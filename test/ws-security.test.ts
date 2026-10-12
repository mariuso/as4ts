import test from 'node:test';
import assert from 'node:assert/strict';
import { ALGO_SHA256, SWA_TRANSFORM_SIGNATURE } from '../src/constants.js';
import { parseXml } from '../src/xml/nodes.js';
import { verifyWsSecuritySignature } from '../src/xml/ws-security.js';
import { buildSignedReceipt, type ReceiptBuildOptions } from './helpers/receipt.js';
import { createTestPki } from './helpers/pki.js';

/**
 * Negative and contract tests for the direction-neutral WS-Security verifier.
 * They cover the gaps the receiving review found: reference transforms and
 * digest methods that were never checked (especially for `cid:` attachments),
 * permissive signature selection, and certificate parsing errors escaping as
 * exceptions instead of values.
 */
const pki = createTestPki();
const REF = 'message@as4-sender.test';

function build(overrides: Partial<ReceiptBuildOptions> = {}) {
  return buildSignedReceipt({ signer: pki.receiver, refToMessageId: REF, references: [], ...overrides });
}

function verify(xml: string) {
  return verifyWsSecuritySignature(parseXml(Buffer.from(xml, 'utf8')));
}

test('accepts a profile-conformant receipt signature (sanity)', () => {
  const result = verify(build().xml);
  assert.equal(result.ok, true);
});

test('rejects an in-envelope reference with an unsupported transform', () => {
  const result = verify(build({ referenceTransformAlgorithm: 'http://example.com/evil-transform' }).xml);
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'bad-signature');
});

test('rejects an attachment reference with an unsupported transform', () => {
  const result = verify(
    build({
      extraSignedInfoReferences: [
        { uri: 'cid:attachment@example', transform: 'http://example.com/evil-transform', digest: 'AAAA' },
      ],
    }).xml,
  );
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'bad-signature');
});

test('checks the attachment reference digest algorithm even though its content is resolved later', () => {
  // The bypass this replaces: a correctly signed envelope with a valid in-envelope
  // reference plus a `cid:` reference whose digest method was never inspected.
  const result = verify(
    build({
      extraSignedInfoReferences: [
        {
          uri: 'cid:attachment@example',
          transform: SWA_TRANSFORM_SIGNATURE,
          digest: 'AAAA',
          digestMethod: 'http://example.com/evil-digest',
        },
      ],
    }).xml,
  );
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'bad-signature');
});

test('accepts a well-formed attachment reference and reports its validated facts', () => {
  const result = verify(
    build({
      extraSignedInfoReferences: [
        { uri: 'cid:attachment@example', transform: SWA_TRANSFORM_SIGNATURE, digest: 'AAAA' },
      ],
    }).xml,
  );
  assert.equal(result.ok, true);
  if (result.ok) {
    const attachment = result.signature.references.find((r) => r.uri === 'cid:attachment@example');
    assert.ok(attachment);
    assert.deepEqual(attachment.transforms, [SWA_TRANSFORM_SIGNATURE]);
    assert.equal(attachment.digestMethod, ALGO_SHA256);
  }
});

test('returns a value (not an exception) when the signer certificate is malformed', () => {
  const attacked = build().xml.replace(
    /(<wsse:BinarySecurityToken[^>]*>)[\s\S]*?(<\/wsse:BinarySecurityToken>)/,
    '$1not-a-real-certificate$2',
  );
  const result = verify(attacked);
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'malformed');
});

test('rejects a signature that is not inside a wsse:Security header', () => {
  const built = build();
  const signature = /<ds:Signature[\s\S]*?<\/ds:Signature>/.exec(built.xml)?.[0];
  assert.ok(signature);
  const moved = built.xml.replace(signature, '').replace('</env:Body>', `${signature}</env:Body>`);
  const result = verify(moved);
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'malformed');
});

test('rejects an ambiguous header with more than one signature', () => {
  const built = build();
  const signature = /<ds:Signature[\s\S]*?<\/ds:Signature>/.exec(built.xml)?.[0];
  assert.ok(signature);
  const doubled = built.xml.replace(signature, signature + signature);
  const result = verify(doubled);
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'malformed');
});
