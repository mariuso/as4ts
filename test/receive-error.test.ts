import test from 'node:test';
import assert from 'node:assert/strict';
import { EBMS_ERROR_CODE_NOT_SERVICED, EBMS_ERROR_CODE_NOT_SERVICED_DETAIL } from '../src/constants.js';
import { EBMS_ERROR_DEFINITIONS } from '../src/ebms-errors.js';
import { EBMS_ERROR_TABLE } from '../src/outcome.js';
import { ebmsErrorFor, notServicedError } from '../src/receive/error.js';
import type { InboundFailure } from '../src/receive/types.js';

function failure(reason: InboundFailure['reason']): InboundFailure {
  return { ok: false, stage: 'mime', reason, answerable: true, correlation: { messageId: 'm' } };
}

test('maps receiving failures to deliberate ebMS errors', () => {
  assert.equal(ebmsErrorFor(failure('decompress.failed')).code, 'EBMS:0303');
  assert.equal(ebmsErrorFor(failure('decompress.too-large')).code, 'EBMS:0303');
  assert.equal(ebmsErrorFor(failure('decrypt.gcm-auth')).code, 'EBMS:0102');
  assert.equal(ebmsErrorFor(failure('decrypt.key-unavailable')).code, 'EBMS:0102');
  assert.equal(ebmsErrorFor(failure('signature.bad-signature')).code, 'EBMS:0101');
  assert.equal(ebmsErrorFor(failure('certificate.untrusted')).code, 'EBMS:0101');
  assert.equal(ebmsErrorFor(failure('addressing.party-mismatch')).code, 'EBMS:0103');
  assert.equal(ebmsErrorFor(failure('addressing.invalid-header')).code, 'EBMS:0009');
  assert.equal(ebmsErrorFor(failure('addressing.pmode-mismatch')).code, 'EBMS:0010');
  assert.equal(ebmsErrorFor(failure('addressing.mpc')).code, 'EBMS:0010');
  assert.equal(ebmsErrorFor(failure('addressing.sbdh-mismatch')).code, 'EBMS:0003');
  assert.equal(ebmsErrorFor(failure('mime.no-soap-part')).code, 'EBMS:0007');
  assert.equal(ebmsErrorFor(failure('xml.malformed')).code, 'EBMS:0009');
  assert.equal(ebmsErrorFor(failure('payload.spool-failed')).code, 'EBMS:0202');
});

test('uses the shared protocol severity and never leaks local diagnostics', () => {
  const result = ebmsErrorFor({
    ok: false,
    stage: 'internal',
    reason: 'internal.error',
    detail: 'secret spool path /tmp/xyz',
    answerable: true,
  });
  assert.equal(result.severity, EBMS_ERROR_DEFINITIONS['EBMS:0202'].severity);
  assert.equal(result.detail, undefined);
  assert.equal(result.code, 'EBMS:0202');
});

test('not-serviced is EBMS:0004 with the Peppol detail', () => {
  assert.deepEqual(notServicedError(), {
    code: EBMS_ERROR_CODE_NOT_SERVICED,
    severity: 'failure',
    detail: EBMS_ERROR_CODE_NOT_SERVICED_DETAIL,
  });
});

test('the sender table and the shared definitions agree on every code', () => {
  for (const [code, row] of Object.entries(EBMS_ERROR_TABLE)) {
    const definition = EBMS_ERROR_DEFINITIONS[code as keyof typeof EBMS_ERROR_DEFINITIONS];
    assert.ok(definition, `missing shared definition for ${code}`);
    assert.equal(row.name, definition.name);
    assert.equal(row.severity, definition.severity);
    assert.equal(row.category, definition.category);
  }
});
