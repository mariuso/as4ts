import test from 'node:test';
import assert from 'node:assert/strict';
import { constants, sign as cryptoSign } from 'node:crypto';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { buildCertificatePath } from '../src/pki/chain.js';
import { validateCertificatePem } from '../src/pki/validate.js';
import { checkRevocation, extractRevocationEndpoints, buildOcspRequest } from '../src/pki/revocation.js';
import {
  children,
  derBitString,
  derContext,
  derNull,
  derOctetString,
  derOid,
  derSequence,
  parseDer,
  tlv,
} from '../src/pki/asn1.js';
import { parseCertificate } from '../src/util.js';
import { defaultRevocationPolicy } from '../src/certificate-validator.js';
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

function buildOcspResponse(input: {
  readonly responder: TestCert;
  /** Raw CertID TLV to echo in the SingleResponse (from buildOcspRequest). */
  readonly certId: Buffer;
  readonly thisUpdate: Date;
  readonly nextUpdate: Date;
}): Buffer {
  const tbs = derSequence(
    derContext(2, Buffer.alloc(20)),
    generalizedTime(new Date()),
    derSequence(
      derSequence(
        input.certId,
        derContext(0, Buffer.alloc(0)),
        generalizedTime(input.thisUpdate),
        derContext(0, generalizedTime(input.nextUpdate), true),
      ),
    ),
  );
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
