import test from 'node:test';
import assert from 'node:assert/strict';
import { constants, createHash, sign as cryptoSign, X509Certificate } from 'node:crypto';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { buildCertificatePath } from '../src/pki/chain.js';
import { validateCertificatePem } from '../src/pki/validate.js';
import { checkRevocation, extractRevocationEndpoints, buildOcspRequest } from '../src/pki/revocation.js';
import {
  children,
  derBitString,
  derContext,
  derInteger,
  derNull,
  derOctetString,
  derOid,
  derSequence,
  parseDer,
  tlv,
} from '../src/pki/asn1.js';
import { parseCertificate } from '../src/util.js';
import { defaultRevocationPolicy, RevocationCache } from '../src/certificate-validator.js';
import { createTestPki, createDelegatedResponder, type TestCert } from './helpers/pki.js';

const DAY = 24 * 3600 * 1000;
const NO_REVOCATION = () => defaultRevocationPolicy({ ocsp: false, crl: false });

test('builds a path from the leaf to the root trust anchor', () => {
  const pki = createTestPki();
  const result = buildCertificatePath(
    parseCertificate(pki.receiver.certPem),
    [pki.intermediate.certPem],
    [pki.root.certPem],
    new Date(),
  );
  assert.equal(result.ok, true);
  if (result.ok) {
    assert.equal(result.chain.length, 3);
    assert.equal(result.chain[0]!.subject, pki.receiver.cert.subject);
  }
});

test('rejects a path to an unknown issuer', () => {
  const pki = createTestPki();
  const other = createTestPki();
  const result = buildCertificatePath(
    parseCertificate(pki.receiver.certPem),
    [pki.intermediate.certPem],
    [other.root.certPem],
    new Date(),
  );
  assert.equal(result.ok, false);
});

test('rejects an expired certificate', () => {
  const past = new Date(Date.now() - 400 * DAY);
  const pki = createTestPki({ now: past });
  const result = buildCertificatePath(
    parseCertificate(pki.receiver.certPem),
    [pki.intermediate.certPem],
    [pki.root.certPem],
    new Date(),
  );
  assert.equal(result.ok, false);
  if (!result.ok) assert.match(result.reason, /not yet valid|expired/);
});

test('extracts the CRL distribution point from an end-entity certificate', () => {
  const pki = createTestPki({ crlUrl: 'http://crl.example/root.crl' });
  const endpoints = extractRevocationEndpoints(parseCertificate(pki.receiver.certPem));
  assert.deepEqual(endpoints.crl, ['http://crl.example/root.crl']);
});

test('detects a revoked certificate from a configured serial list', async () => {
  const pki = createTestPki();
  const result = await validateCertificatePem(pki.revoked.certPem, {
    roots: [pki.root.certPem],
    intermediates: [pki.intermediate.certPem],
    revocation: NO_REVOCATION(),
    extraRevokedSerials: { [pki.intermediate.commonName]: [pki.revoked.serialHex] },
    now: new Date(),
  });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.status, 'revoked');
});

test('fetches and verifies a CRL over HTTP', async () => {
  let crl: Buffer | null = null;
  const server = createServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/pkix-crl' });
    res.end(crl ?? Buffer.alloc(0));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;
  try {
    const pki = createTestPki({ crlUrl: `http://127.0.0.1:${port}/crl` });
    crl = pki.makeCrl();
    const policy = defaultRevocationPolicy({ ocsp: false, crl: true, timeoutMs: 3000, maxCacheMs: 1000 });

    const good = await validateCertificatePem(pki.receiver.certPem, {
      roots: [pki.root.certPem],
      intermediates: [pki.intermediate.certPem],
      revocation: policy,
      now: new Date(),
    });
    assert.equal(good.ok, true, good.ok ? '' : good.reason);

    const revoked = await validateCertificatePem(pki.revoked.certPem, {
      roots: [pki.root.certPem],
      intermediates: [pki.intermediate.certPem],
      revocation: policy,
      now: new Date(),
    });
    assert.equal(revoked.ok, false);
    if (!revoked.ok) assert.equal(revoked.status, 'revoked');
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

test('strict policy blocks when the revocation service cannot be reached', async () => {
  const pki = createTestPki({ crlUrl: 'http://127.0.0.1:1/crl' });
  const result = await validateCertificatePem(pki.receiver.certPem, {
    roots: [pki.root.certPem],
    intermediates: [pki.intermediate.certPem],
    revocation: defaultRevocationPolicy({ ocsp: false, crl: true, timeoutMs: 1000, maxCacheMs: 1000 }),
    now: new Date(),
  });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.status, 'unavailable');
});

test('soft policy allows when the revocation service cannot be reached', async () => {
  const pki = createTestPki({ crlUrl: 'http://127.0.0.1:1/crl' });
  const result = await validateCertificatePem(pki.receiver.certPem, {
    roots: [pki.root.certPem],
    intermediates: [pki.intermediate.certPem],
    revocation: defaultRevocationPolicy({
      unreachable: 'soft',
      ocsp: false,
      crl: true,
      timeoutMs: 1000,
      maxCacheMs: 1000,
    }),
    now: new Date(),
  });
  assert.equal(result.ok, true);
});

test('falls back to the CRL when the OCSP answer cannot be verified', async () => {
  const pki = createTestPki();
  const crl = pki.makeCrl();
  const fetchImpl = (async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.includes('ocsp')) return new Response(Buffer.from('not an ocsp response'), { status: 200 });
    if (url.includes('crl')) return new Response(new Uint8Array(crl), { status: 200 });
    return new Response('', { status: 404 });
  }) as unknown as typeof fetch;

  const answer = await checkRevocation(
    parseCertificate(pki.receiver.certPem),
    pki.intermediate.cert,
    { ocsp: ['http://ocsp.example/'], crl: ['http://crl.example/root.crl'] },
    {
      policy: defaultRevocationPolicy({ ocsp: true, crl: true, timeoutMs: 2000, maxCacheMs: 1000 }),
      now: () => new Date(),
      fetchImpl,
    },
  );
  assert.equal(answer.status, 'good', answer.reason);
  assert.equal(answer.source, 'crl');
});

test('accepts a good OCSP answer signed by a delegated responder', async () => {
  const pki = createTestPki();
  const responder = createDelegatedResponder(pki);
  const ocsp = buildOcspResponse({
    responder,
    certId: certIdFromRequest(buildOcspRequest(parseCertificate(pki.receiver.certPem), pki.intermediate.cert)),
    thisUpdate: new Date(Date.now() - 60_000),
    nextUpdate: new Date(Date.now() + 3600_000),
  });
  const fetchImpl = (async (input: RequestInfo | URL) => {
    if (String(input).includes('ocsp')) return new Response(new Uint8Array(ocsp), { status: 200 });
    return new Response('', { status: 404 });
  }) as unknown as typeof fetch;

  const answer = await checkRevocation(
    parseCertificate(pki.receiver.certPem),
    pki.intermediate.cert,
    { ocsp: ['http://ocsp.example/'], crl: [] },
    {
      policy: defaultRevocationPolicy({ ocsp: true, crl: true, timeoutMs: 2000, maxCacheMs: 1000 }),
      now: () => new Date(),
      fetchImpl,
    },
  );
  assert.equal(answer.status, 'good', answer.reason);
  assert.equal(answer.source, 'ocsp');
});

test('rejects a replayed OCSP answer issued for a different certificate', async () => {
  // A genuine "good" answer for pki.receiver, replayed for pki.sender (same
  // issuer). Without CertID matching this would be accepted as good and hide
  // revocation of pki.sender.
  const pki = createTestPki();
  const responder = createDelegatedResponder(pki);
  const ocsp = buildOcspResponse({
    responder,
    certId: certIdFromRequest(buildOcspRequest(parseCertificate(pki.receiver.certPem), pki.intermediate.cert)),
    thisUpdate: new Date(Date.now() - 60_000),
    nextUpdate: new Date(Date.now() + 3600_000),
  });
  const fetchImpl = (async (input: RequestInfo | URL) => {
    if (String(input).includes('ocsp')) return new Response(new Uint8Array(ocsp), { status: 200 });
    return new Response('', { status: 404 });
  }) as unknown as typeof fetch;

  const answer = await checkRevocation(
    parseCertificate(pki.sender.certPem),
    pki.intermediate.cert,
    { ocsp: ['http://ocsp.example/'], crl: [] },
    {
      policy: defaultRevocationPolicy({ ocsp: true, crl: true, timeoutMs: 2000, maxCacheMs: 1000 }),
      now: () => new Date(),
      fetchImpl,
    },
  );
  assert.notEqual(answer.status, 'good');
  assert.notEqual(answer.source, 'ocsp');
});

test('bounds the revocation response body and treats an oversized body as no answer', async () => {
  // Both endpoints return far more than the cap, so neither can produce an
  // answer. The read must fail rather than buffer an unbounded body.
  const pki = createTestPki();
  const huge = new Uint8Array(4096);
  const fetchImpl = (async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.includes('ocsp') || url.includes('crl')) return new Response(huge, { status: 200 });
    return new Response('', { status: 404 });
  }) as unknown as typeof fetch;

  const answer = await checkRevocation(
    parseCertificate(pki.receiver.certPem),
    pki.intermediate.cert,
    { ocsp: ['http://ocsp.example/'], crl: ['http://crl.example/root.crl'] },
    {
      policy: defaultRevocationPolicy({
        ocsp: true,
        crl: true,
        timeoutMs: 2000,
        maxResponseBytes: 1024,
        maxCacheMs: 1000,
      }),
      now: () => new Date(),
      fetchImpl,
    },
  );
  assert.equal(answer.status, 'unknown');
});

function ocspFetch(ocsp: Buffer): typeof fetch {
  return (async (input: RequestInfo | URL) =>
    String(input).includes('ocsp')
      ? new Response(new Uint8Array(ocsp), { status: 200 })
      : new Response('', { status: 404 })) as unknown as typeof fetch;
}

function crlFetch(crl: Buffer): typeof fetch {
  return (async (input: RequestInfo | URL) =>
    String(input).includes('crl')
      ? new Response(new Uint8Array(crl), { status: 200 })
      : new Response('', { status: 404 })) as unknown as typeof fetch;
}

function receiverCertId(pki: ReturnType<typeof createTestPki>): Buffer {
  return certIdFromRequest(buildOcspRequest(parseCertificate(pki.receiver.certPem), pki.intermediate.cert));
}

test('rejects an OCSP answer whose correctly-tagged nextUpdate has passed', async () => {
  const pki = createTestPki();
  const responder = createDelegatedResponder(pki);
  const now = new Date();
  const ocsp = buildOcspResponse({
    responder,
    certId: receiverCertId(pki),
    thisUpdate: new Date(now.getTime() - 2 * 3600_000),
    nextUpdate: new Date(now.getTime() - 3600_000),
  });
  const answer = await checkRevocation(
    parseCertificate(pki.receiver.certPem),
    pki.intermediate.cert,
    { ocsp: ['http://ocsp.example/'], crl: [] },
    {
      policy: defaultRevocationPolicy({ ocsp: true, crl: true, timeoutMs: 2000, maxCacheMs: 1000 }),
      now: () => now,
      fetchImpl: ocspFetch(ocsp),
    },
  );
  assert.equal(answer.status, 'unknown', answer.reason);
});

test('rejects an OCSP answer with no thisUpdate', async () => {
  const pki = createTestPki();
  const responder = createDelegatedResponder(pki);
  const now = new Date();
  const ocsp = buildOcspResponse({
    responder,
    certId: receiverCertId(pki),
    thisUpdate: null,
    nextUpdate: new Date(now.getTime() + 3600_000),
  });
  const answer = await checkRevocation(
    parseCertificate(pki.receiver.certPem),
    pki.intermediate.cert,
    { ocsp: ['http://ocsp.example/'], crl: [] },
    {
      policy: defaultRevocationPolicy({ ocsp: true, crl: true, timeoutMs: 2000, maxCacheMs: 1000 }),
      now: () => now,
      fetchImpl: ocspFetch(ocsp),
    },
  );
  assert.equal(answer.status, 'unknown', answer.reason);
});

test('rejects an OCSP answer whose ResponderID does not match the signer', async () => {
  const pki = createTestPki();
  const responder = createDelegatedResponder(pki);
  const now = new Date();
  const ocsp = buildOcspResponse({
    responder,
    certId: receiverCertId(pki),
    thisUpdate: new Date(now.getTime() - 60_000),
    nextUpdate: new Date(now.getTime() + 3600_000),
    responderId: { kind: 'key', value: createHash('sha1').update('not the responder key').digest() },
  });
  const answer = await checkRevocation(
    parseCertificate(pki.receiver.certPem),
    pki.intermediate.cert,
    { ocsp: ['http://ocsp.example/'], crl: [] },
    {
      policy: defaultRevocationPolicy({ ocsp: true, crl: true, timeoutMs: 2000, maxCacheMs: 1000 }),
      now: () => now,
      fetchImpl: ocspFetch(ocsp),
    },
  );
  assert.notEqual(answer.status, 'good');
});

test('bounds an OCSP answer without nextUpdate by ocspMaxAgeMs', async () => {
  const pki = createTestPki();
  const responder = createDelegatedResponder(pki);
  const now = new Date();
  const maxAgeMs = 3600_000;
  const thisUpdate = new Date(Math.floor((now.getTime() - 60_000) / 1000) * 1000); // whole seconds only

  const recent = buildOcspResponse({ responder, certId: receiverCertId(pki), thisUpdate, nextUpdate: null });
  const accepted = await checkRevocation(
    parseCertificate(pki.receiver.certPem),
    pki.intermediate.cert,
    { ocsp: ['http://ocsp.example/'], crl: [] },
    {
      policy: defaultRevocationPolicy({
        ocsp: true,
        crl: true,
        timeoutMs: 2000,
        maxCacheMs: 1000,
        ocspMaxAgeMs: maxAgeMs,
      }),
      now: () => now,
      fetchImpl: ocspFetch(recent),
    },
  );
  assert.equal(accepted.status, 'good');
  assert.equal(accepted.expiresAt?.getTime(), thisUpdate.getTime() + maxAgeMs);

  const stale = buildOcspResponse({
    responder,
    certId: receiverCertId(pki),
    thisUpdate: new Date(now.getTime() - 2 * maxAgeMs),
    nextUpdate: null,
  });
  const rejected = await checkRevocation(
    parseCertificate(pki.receiver.certPem),
    pki.intermediate.cert,
    { ocsp: ['http://ocsp.example/'], crl: [] },
    {
      policy: defaultRevocationPolicy({
        ocsp: true,
        crl: true,
        timeoutMs: 2000,
        maxCacheMs: 1000,
        ocspMaxAgeMs: maxAgeMs,
      }),
      now: () => now,
      fetchImpl: ocspFetch(stale),
    },
  );
  assert.equal(rejected.status, 'unknown', rejected.reason);
});

test('does not serve a cached OCSP answer past its effective expiry', async () => {
  const pki = createTestPki();
  const responder = createDelegatedResponder(pki);
  const maxAgeMs = 3600_000;
  const thisUpdate = new Date(Date.now() - 60_000);
  let nowMs = Date.now();
  const ocsp = buildOcspResponse({ responder, certId: receiverCertId(pki), thisUpdate, nextUpdate: null });
  const options = {
    policy: defaultRevocationPolicy({
      ocsp: true,
      crl: true,
      timeoutMs: 2000,
      maxCacheMs: 10 * maxAgeMs,
      ocspMaxAgeMs: maxAgeMs,
    }),
    now: () => new Date(nowMs),
    fetchImpl: ocspFetch(ocsp),
    cache: new RevocationCache(),
  };
  const first = await checkRevocation(
    parseCertificate(pki.receiver.certPem),
    pki.intermediate.cert,
    { ocsp: ['http://ocsp.example/'], crl: [] },
    options,
  );
  assert.equal(first.status, 'good');

  nowMs = thisUpdate.getTime() + maxAgeMs + 1000;
  const second = await checkRevocation(
    parseCertificate(pki.receiver.certPem),
    pki.intermediate.cert,
    { ocsp: ['http://ocsp.example/'], crl: [] },
    options,
  );
  assert.equal(second.status, 'unknown', second.reason);
});

test('rejects a delta CRL instead of treating absence from it as non-revocation', async () => {
  const pki = createTestPki();
  const now = new Date();
  const delta = pki.makeCrl([], {
    thisUpdate: new Date(now.getTime() - 60_000),
    nextUpdate: new Date(now.getTime() + 7 * 24 * 3600 * 1000),
    extensions: [{ oid: '2.5.29.27', critical: true, der: derInteger(Buffer.from([1])) }],
  });
  const answer = await checkRevocation(
    parseCertificate(pki.receiver.certPem),
    pki.intermediate.cert,
    { ocsp: [], crl: ['http://crl.example/root.crl'] },
    {
      policy: defaultRevocationPolicy({ ocsp: false, crl: true, timeoutMs: 2000, maxCacheMs: 1000 }),
      now: () => now,
      fetchImpl: crlFetch(delta),
    },
  );
  assert.notEqual(answer.status, 'good');
});

test('accepts a delegated responder identified by name (byName)', async () => {
  const pki = createTestPki();
  const responder = createDelegatedResponder(pki);
  const now = new Date();
  const ocsp = buildOcspResponse({
    responder,
    certId: receiverCertId(pki),
    thisUpdate: new Date(now.getTime() - 60_000),
    nextUpdate: new Date(now.getTime() + 3600_000),
    responderId: { kind: 'name', value: subjectNameDer(responder.cert) },
  });
  const answer = await checkRevocation(
    parseCertificate(pki.receiver.certPem),
    pki.intermediate.cert,
    { ocsp: ['http://ocsp.example/'], crl: [] },
    {
      policy: defaultRevocationPolicy({ ocsp: true, crl: true, timeoutMs: 2000, maxCacheMs: 1000 }),
      now: () => now,
      fetchImpl: ocspFetch(ocsp),
    },
  );
  assert.equal(answer.status, 'good', answer.reason);
});

test('rejects an OCSP response whose [0] nextUpdate is present but malformed', async () => {
  const pki = createTestPki();
  const responder = createDelegatedResponder(pki);
  const now = new Date();
  const ocsp = buildOcspResponse({
    responder,
    certId: receiverCertId(pki),
    thisUpdate: new Date(now.getTime() - 60_000),
    nextUpdateDer: derContext(0, derNull(), true), // [0] EXPLICIT NULL: present but not a time
  });
  const answer = await checkRevocation(
    parseCertificate(pki.receiver.certPem),
    pki.intermediate.cert,
    { ocsp: ['http://ocsp.example/'], crl: [] },
    {
      policy: defaultRevocationPolicy({ ocsp: true, crl: true, timeoutMs: 2000, maxCacheMs: 1000 }),
      now: () => now,
      fetchImpl: ocspFetch(ocsp),
    },
  );
  assert.equal(answer.status, 'unknown', answer.reason);
});

test('rejects an OCSP response with an unsupported version', async () => {
  const pki = createTestPki();
  const responder = createDelegatedResponder(pki);
  const now = new Date();
  const ocsp = buildOcspResponse({
    responder,
    certId: receiverCertId(pki),
    thisUpdate: new Date(now.getTime() - 60_000),
    nextUpdate: new Date(now.getTime() + 3600_000),
    version: 1,
  });
  const answer = await checkRevocation(
    parseCertificate(pki.receiver.certPem),
    pki.intermediate.cert,
    { ocsp: ['http://ocsp.example/'], crl: [] },
    {
      policy: defaultRevocationPolicy({ ocsp: true, crl: true, timeoutMs: 2000, maxCacheMs: 1000 }),
      now: () => now,
      fetchImpl: ocspFetch(ocsp),
    },
  );
  assert.equal(answer.status, 'unknown', answer.reason);
});

test('rejects unrecognized critical extensions at response and SingleResponse level', async () => {
  const pki = createTestPki();
  const responder = createDelegatedResponder(pki);
  const now = new Date();
  const options = {
    policy: defaultRevocationPolicy({ ocsp: true, crl: true, timeoutMs: 2000, maxCacheMs: 1000 }),
    now: () => now,
  };

  const responseLevel = buildOcspResponse({
    responder,
    certId: receiverCertId(pki),
    thisUpdate: new Date(now.getTime() - 60_000),
    nextUpdate: new Date(now.getTime() + 3600_000),
    responseExtensions: criticalExtensionsWrapper(1, '1.2.3.4.5'),
  });
  assert.equal(
    (
      await checkRevocation(
        parseCertificate(pki.receiver.certPem),
        pki.intermediate.cert,
        { ocsp: ['http://ocsp.example/'], crl: [] },
        { ...options, fetchImpl: ocspFetch(responseLevel) },
      )
    ).status,
    'unknown',
  );

  const singleLevel = buildOcspResponse({
    responder,
    certId: receiverCertId(pki),
    thisUpdate: new Date(now.getTime() - 60_000),
    nextUpdate: new Date(now.getTime() + 3600_000),
    singleExtensions: criticalExtensionsWrapper(1, '1.2.3.4.6'),
  });
  assert.equal(
    (
      await checkRevocation(
        parseCertificate(pki.receiver.certPem),
        pki.intermediate.cert,
        { ocsp: ['http://ocsp.example/'], crl: [] },
        { ...options, fetchImpl: ocspFetch(singleLevel) },
      )
    ).status,
    'unknown',
  );
});

test('rejects a CRL with an invalid nextUpdate and does not cache it forever', async () => {
  const pki = createTestPki();
  const now = new Date();
  const crl = pki.makeCrl([], {
    thisUpdate: new Date(now.getTime() - 60_000),
    nextUpdateDer: tlv(0x18, Buffer.from('not-a-time')),
  });
  let fetches = 0;
  const fetchImpl = (async (input: RequestInfo | URL) => {
    if (String(input).includes('crl')) {
      fetches += 1;
      return new Response(new Uint8Array(crl), { status: 200 });
    }
    return new Response('', { status: 404 });
  }) as unknown as typeof fetch;
  const cache = new RevocationCache();
  const endpoints = { ocsp: [], crl: ['http://crl.example/root.crl'] };

  const first = await checkRevocation(parseCertificate(pki.receiver.certPem), pki.intermediate.cert, endpoints, {
    policy: defaultRevocationPolicy({ ocsp: false, crl: true, timeoutMs: 2000, maxCacheMs: 1000 }),
    now: () => now,
    fetchImpl,
    cache,
  });
  assert.notEqual(first.status, 'good');

  const later = new Date(now.getTime() + 24 * 3600_000);
  const second = await checkRevocation(parseCertificate(pki.receiver.certPem), pki.intermediate.cert, endpoints, {
    policy: defaultRevocationPolicy({ ocsp: false, crl: true, timeoutMs: 2000, maxCacheMs: 1000 }),
    now: () => later,
    fetchImpl,
    cache,
  });
  assert.notEqual(second.status, 'good');
  assert.ok(fetches >= 2, 'the CRL must be re-fetched, not served from a never-expiring cache entry');
});

test('the revocation cache never stores a non-finite expiry', () => {
  const cache = new RevocationCache();
  const now = new Date();
  cache.set('key', { status: 'good', source: 'crl', reason: 'x', expiresAt: new Date(NaN) }, now, 1000);
  assert.equal(cache.get('key', new Date(now.getTime() + 24 * 3600_000)), null);
});

function certIdFromRequest(requestDer: Buffer): Buffer {
  const tbsRequest = children(parseDer(requestDer).node)[0]!;
  const requestList = children(tbsRequest)[0]!;
  const request = children(requestList)[0]!;
  const certId = children(request)[0]!;
  return Buffer.from(certId.raw);
}

function generalizedTime(date: Date): Buffer {
  const pad = (n: number, width = 2) => String(n).padStart(width, '0');
  const text =
    pad(date.getUTCFullYear(), 4) +
    pad(date.getUTCMonth() + 1) +
    pad(date.getUTCDate()) +
    pad(date.getUTCHours()) +
    pad(date.getUTCMinutes()) +
    pad(date.getUTCSeconds()) +
    'Z';
  return tlv(0x18, Buffer.from(text, 'latin1'));
}

function responderKeyHash(cert: X509Certificate): Buffer {
  const tbs = children(parseDer(Buffer.from(cert.raw)).node)[0]!;
  const list = children(tbs);
  let i = 0;
  if (list[i] && list[i]!.cls === 2 && list[i]!.tag === 0) i += 1; // version
  i += 5; // serial, signature, issuer, validity, subject
  const spki = list[i]!;
  const bitString = children(spki)[1]!;
  return createHash('sha1').update(bitString.value.subarray(1)).digest();
}

function subjectNameDer(cert: X509Certificate): Buffer {
  const tbs = children(parseDer(Buffer.from(cert.raw)).node)[0]!;
  const list = children(tbs);
  let i = 0;
  if (list[i] && list[i]!.cls === 2 && list[i]!.tag === 0) i += 1; // version
  i += 4; // serial, signature, issuer, validity
  return Buffer.from(list[i]!.raw); // subject Name
}

/** An explicit Extensions wrapper carrying one critical extension. */
function criticalExtensionsWrapper(tag: number, oid: string): Buffer {
  const ext = derSequence(derOid(oid), tlv(0x01, Buffer.from([0xff])), tlv(0x04, derNull()));
  return derContext(tag, derSequence(ext), true);
}

function buildOcspResponse(input: {
  readonly responder: TestCert;
  /** Raw CertID TLV to echo in the SingleResponse (from buildOcspRequest). */
  readonly certId: Buffer;
  /** `null` omits thisUpdate entirely (a malformed response). */
  readonly thisUpdate?: Date | null;
  /** `null` omits nextUpdate entirely. */
  readonly nextUpdate?: Date | null;
  /** Raw `[0]` node to use instead of a well-formed nextUpdate. */
  readonly nextUpdateDer?: Buffer;
  /** ResponderID to emit; defaults to byKey of the responder's public key. */
  readonly responderId?: { readonly kind: 'name' | 'key'; readonly value: Buffer };
  /** ResponseData version to emit (default v1, omitted). */
  readonly version?: number;
  /** Raw responseExtensions `[1]` node. */
  readonly responseExtensions?: Buffer;
  /** Raw singleExtensions `[1]` node. */
  readonly singleExtensions?: Buffer;
}): Buffer {
  const singleParts: Buffer[] = [input.certId, derContext(0, Buffer.alloc(0))];
  if (input.thisUpdate !== null) singleParts.push(generalizedTime(input.thisUpdate ?? new Date()));
  if (input.nextUpdateDer) singleParts.push(input.nextUpdateDer);
  else if (input.nextUpdate !== null && input.nextUpdate !== undefined) {
    singleParts.push(derContext(0, generalizedTime(input.nextUpdate), true));
  }
  if (input.singleExtensions) singleParts.push(input.singleExtensions);

  const id = input.responderId ?? { kind: 'key' as const, value: responderKeyHash(input.responder.cert) };
  // Normative OCSP module uses EXPLICIT tagging, so byKey wraps an OCTET STRING.
  const responderIdDer =
    id.kind === 'key' ? derContext(2, derOctetString(id.value), true) : derContext(1, id.value, true);

  const rdParts: Buffer[] = [];
  if (input.version !== undefined) rdParts.push(derContext(0, derInteger(Buffer.from([input.version])), true));
  rdParts.push(responderIdDer, generalizedTime(new Date()), derSequence(derSequence(...singleParts)));
  if (input.responseExtensions) rdParts.push(input.responseExtensions);

  const tbs = derSequence(...rdParts);
  const sigAlg = derSequence(derOid('1.2.840.113549.1.1.11'), derNull());
  const signature = cryptoSign('sha256', tbs, { key: input.responder.keyObject, padding: constants.RSA_PKCS1_PADDING });
  const basic = derSequence(
    tbs,
    sigAlg,
    derBitString(signature),
    derContext(0, derSequence(Buffer.from(input.responder.cert.raw)), true),
  );
  const responseBytes = derSequence(derOid('1.3.6.1.5.5.7.48.1.1'), derOctetString(basic));
  return derSequence(tlv(0x0a, Buffer.from([0])), derContext(0, responseBytes, true));
}
