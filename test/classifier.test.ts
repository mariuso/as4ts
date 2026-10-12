import test from 'node:test';
import assert from 'node:assert/strict';
import { classify, classifyEbmsError, DEFAULT_CLASSIFY_TABLE, EBMS_ERROR_TABLE } from '../src/classifier.js';

test('ebMS error table: every code maps to a documented class', () => {
  for (const [code, row] of Object.entries(EBMS_ERROR_TABLE)) {
    assert.equal(classifyEbmsError({ code }), row.outcome, code);
  }
  assert.equal(classifyEbmsError({ code: 'EBMS:9999' }), 'fatal');
});

test('EBMS:0004 is fatal only with detail PEPPOL:NOT_SERVICED, otherwise retryable', () => {
  assert.equal(classifyEbmsError({ code: 'EBMS:0004', detail: 'PEPPOL:NOT_SERVICED' }), 'fatal');
  assert.equal(classifyEbmsError({ code: 'EBMS:0004' }), 'retryable');
  assert.equal(classifyEbmsError({ code: 'EBMS:0004', detail: 'something else' }), 'retryable');
});

test('several errors: the most severe class wins', () => {
  const result = {
    outcome: 'error-signal' as const,
    as4MessageId: 'a@b',
    sentAt: '',
    receiverCertificateCommonName: '',
    transportProfile: '',
    raw: new Uint8Array(),
    errors: [
      { code: 'EBMS:0005', severity: 'failure', raw: new Uint8Array() },
      { code: 'EBMS:0001', severity: 'failure', raw: new Uint8Array() },
    ],
  };
  assert.equal(classify(result), 'fatal');
});

test('not-sent caused by a local I/O failure is retryable', () => {
  const result = {
    outcome: 'not-sent' as const,
    as4MessageId: 'a@b',
    sentAt: '',
    receiverCertificateCommonName: '',
    transportProfile: '',
    reason: 'spool.failed' as const,
  };
  assert.equal(classify(result), 'retryable');
  assert.equal(classify({ ...result, reason: 'certificate.refused' }), 'fatal');
});

test('a custom table overrides the default', () => {
  assert.equal(
    classifyEbmsError({ code: 'EBMS:0001' }, { ...DEFAULT_CLASSIFY_TABLE, ebms: { 'EBMS:0001': 'retryable' } }),
    'retryable',
  );
});

test('transport failures before bytes are retryable, after are unknown', () => {
  const base = {
    outcome: 'transport-failure' as const,
    as4MessageId: 'a@b',
    sentAt: '',
    receiverCertificateCommonName: '',
    transportProfile: '',
  };
  assert.equal(classify({ ...base, requestBytesWritten: false, aborted: false }), 'retryable');
  assert.equal(classify({ ...base, requestBytesWritten: true, aborted: false }), 'unknown');
  assert.equal(classify({ ...base, requestBytesWritten: false, aborted: true }), 'retryable');
  assert.equal(classify({ ...base, requestBytesWritten: true, aborted: true }), 'unknown');
});

test('no-signal 502/504 is unknown (gateway may have forwarded), other 5xx retryable, 4xx fatal', () => {
  const base = {
    outcome: 'no-signal' as const,
    as4MessageId: 'a@b',
    receiverCertificateCommonName: '',
    transportProfile: '',
    bodyEmpty: true,
    status: 0,
  };
  assert.equal(classify({ ...base, status: 502 }), 'unknown');
  assert.equal(classify({ ...base, status: 504 }), 'unknown');
  assert.equal(classify({ ...base, status: 500 }), 'retryable');
  assert.equal(classify({ ...base, status: 503 }), 'retryable');
  assert.equal(classify({ ...base, status: 400 }), 'fatal');
  assert.equal(classify({ ...base, status: 200 }), 'unknown');
});
