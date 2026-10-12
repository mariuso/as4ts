import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { defaultInboundLimits } from '../src/receive/types.js';
import { parseMultipartRelated, selectSoapPart, type MimeLimits } from '../src/receive/mime.js';

/**
 * Captured inbound requests from independent senders (see
 * docs/receiving-fixtures.md). When captures are present they are parsed with the
 * real bounded MIME parser; when none are recorded yet the test skips, so the
 * suite stays green until the fixtures exist.
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
    test(`parses the captured request ${name}`, async () => {
      const dir = join(fixtures, name);
      const metadata = JSON.parse(readFileSync(join(dir, 'metadata.json'), 'utf8')) as {
        contentType: string;
        expectedParts?: number;
      };
      const body = readFileSync(join(dir, 'request.bin'));
      const parsed = await parseMultipartRelated({
        contentType: metadata.contentType,
        body: (async function* () {
          yield body;
        })(),
        limits: LIMITS,
      });
      const soap = selectSoapPart(parsed);
      assert.ok(soap.body.length > 0, 'the SOAP part is non-empty');
      if (metadata.expectedParts !== undefined) {
        assert.equal(parsed.parts.length, metadata.expectedParts);
      }
    });
  }
}
