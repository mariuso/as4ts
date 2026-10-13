import test from 'node:test';
import assert from 'node:assert/strict';
import { MimeFault, extractBoundary, extractStart, type MimeLimits } from '../src/receive/mime.js';

/**
 * The MIME framing itself is covered by `receive-multipart.test.ts`. This file
 * covers the shared parameter helpers.
 */
const LIMITS: MimeLimits = {
  maxRequestBytes: 1_000_000,
  maxParts: 8,
  maxHeaderBytes: 4096,
  maxPartBytes: 500_000,
  maxBoundaryLength: 70,
};

const BOUNDARY = '----=_Part_test_boundary';

test('extracts a quoted or unquoted boundary', () => {
  assert.equal(extractBoundary(`multipart/related; boundary="${BOUNDARY}"`, LIMITS), BOUNDARY);
  assert.equal(extractBoundary(`multipart/related; boundary=${BOUNDARY}`, LIMITS), BOUNDARY);
  assert.equal(extractBoundary(`multipart/mixed; boundary="${BOUNDARY}"`, LIMITS), BOUNDARY);
});

test('rejects a non-multipart content type and a missing or mis-named boundary', () => {
  assert.throws(
    () => extractBoundary('application/soap+xml', LIMITS),
    (err) => err instanceof MimeFault && err.reason === 'mime.content-type-invalid',
  );
  assert.throws(
    () => extractBoundary('multipart/related', LIMITS),
    (err) => err instanceof MimeFault && err.reason === 'mime.boundary-invalid',
  );
  assert.throws(
    () => extractBoundary(`multipart/related; notboundary="${BOUNDARY}"`, LIMITS),
    (err) => err instanceof MimeFault && err.reason === 'mime.boundary-invalid',
  );
});

test('rejects an over-long boundary', () => {
  assert.throws(
    () => extractBoundary(`multipart/related; boundary="${'a'.repeat(71)}"`, LIMITS),
    (err) => err instanceof MimeFault && err.reason === 'mime.boundary-invalid',
  );
});

test('extracts the start Content-ID with or without angle brackets', () => {
  assert.equal(extractStart(`multipart/related; boundary="b"; start="<soap@x>"`), 'soap@x');
  assert.equal(extractStart(`multipart/related; boundary="b"; start=soap@x`), 'soap@x');
  assert.equal(extractStart('multipart/related; boundary="b"'), null);
});
