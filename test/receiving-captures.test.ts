import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ALGO_SHA256, EBMS_NS, SOAP_ENV_NS } from '../src/constants.js';
import { defaultInboundLimits } from '../src/receive/types.js';
import { parseMultipartRelated, selectSoapPart, type MimeLimits } from '../src/receive/mime.js';
import { parseStrictXml } from '../src/receive/xml.js';
import { firstByLocalName } from '../src/xml/nodes.js';
import { verifyWsSecuritySignature, type VerifiedReference } from '../src/xml/ws-security.js';

/**
 * Captured inbound requests from independent senders (see
 * docs/receiving-fixtures.md). They prove more than MIME framing: for each
 * capture the signature must verify, it must cover `eb:Messaging` and the SOAP
 * Body, and every expected reference must match on URI, digest, digest algorithm
 * and ordered transforms. The attachment digest check needs the receiver's
 * decryption credential and lands with `openAs4Message`.
 *
 * While no captures are present the test skips, so the suite stays green.
 */
const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, 'fixtures', 'inbound');

const LIMITS: MimeLimits = {
  maxRequestBytes: defaultInboundLimits.maxRequestBytes,
  maxParts: defaultInboundLimits.maxParts,
  maxHeaderBytes: defaultInboundLimits.maxHeaderBytes,
  maxPartBytes: defaultInboundLimits.maxPartBytes,
  maxBoundaryLength: defaultInboundLimits.maxBoundaryLength,
};

interface ExpectedReference {
  readonly uri: string;
  readonly digest: string;
  readonly transforms?: readonly { readonly algorithm: string }[];
}

interface CaptureMetadata {
  readonly contentType: string;
  readonly expectedParts?: number;
  readonly expectedCoverage?: { readonly messaging?: boolean; readonly body?: boolean };
  readonly expectedSignedReferences?: readonly ExpectedReference[];
}

const captures = existsSync(fixtures)
  ? readdirSync(fixtures, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name)
  : [];

if (captures.length === 0) {
  test('inbound wire captures', (t) => {
    t.skip('no inbound captures recorded yet — see docs/receiving-fixtures.md');
  });
} else {
  for (const name of captures) {
    test(`verifies the captured request ${name}`, async () => {
      const dir = join(fixtures, name);
      const metadata = JSON.parse(readFileSync(join(dir, 'metadata.json'), 'utf8')) as CaptureMetadata;
      const body = readFileSync(join(dir, 'request.bin'));
      const parsed = await parseMultipartRelated({
        contentType: metadata.contentType,
        body: (async function* () {
          yield body;
        })(),
        limits: LIMITS,
      });
      if (metadata.expectedParts !== undefined) assert.equal(parsed.parts.length, metadata.expectedParts);

      const soap = selectSoapPart(parsed);
      const document = parseStrictXml(soap.body);
      const verification = verifyWsSecuritySignature(document);
      assert.equal(verification.ok, true, verification.ok ? '' : verification.detail);
      if (!verification.ok) return;

      const messaging = firstByLocalName(document, EBMS_NS, 'Messaging');
      const soapBody = firstByLocalName(document, SOAP_ENV_NS, 'Body');
      if (metadata.expectedCoverage?.messaging !== false) {
        assert.ok(
          messaging && verification.signature.coveredElements.includes(messaging),
          'the signature covers eb:Messaging',
        );
      }
      if (metadata.expectedCoverage?.body !== false) {
        assert.ok(
          soapBody && verification.signature.coveredElements.includes(soapBody),
          'the signature covers the Body',
        );
      }

      for (const expected of metadata.expectedSignedReferences ?? []) {
        const actual: VerifiedReference | undefined = verification.signature.references.find(
          (reference) => reference.uri === expected.uri,
        );
        assert.ok(actual, `expected reference ${expected.uri}`);
        assert.equal(actual.digest, expected.digest, `digest for ${expected.uri}`);
        assert.equal(actual.digestMethod, ALGO_SHA256, `digest method for ${expected.uri}`);
        if (expected.transforms) {
          assert.deepEqual(
            actual.transforms.map((transform) => transform.algorithm),
            expected.transforms.map((transform) => transform.algorithm),
            `transforms for ${expected.uri}`,
          );
        }
      }
    });
  }
}
