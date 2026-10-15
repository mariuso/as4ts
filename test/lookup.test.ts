import test from 'node:test';
import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { createCertificateValidator, defaultRevocationPolicy } from '../src/certificate-validator.js';
import { lookupParticipant } from '../src/lookup/index.js';
import { verifySmpSignature } from '../src/lookup/smp-signature.js';
import { defaultLookupLimits } from '../src/lookup/limits.js';
import { parseStrictXml } from '../src/xml/strict.js';
import { participantDnsName, participantHash } from '../src/lookup/sml.js';
import type { LookupInput, LookupResult } from '../src/lookup/index.js';
import type { ParticipantId, ScopedId } from '../src/types.js';
import { buildServiceGroup, buildSignedServiceMetadata } from './helpers/smp.js';
import { createTestPki, type TestPki } from './helpers/pki.js';
import { xmlHooks } from '../src/xml/hooks.js';

const DAY = 24 * 3600 * 1000;

const AP = createTestPki();
const SMP = createTestPki();
const EXPIRED_SMP = createTestPki({ now: new Date(Date.now() - 400 * DAY) });

const PARTICIPANT: ParticipantId = { scheme: 'iso6523-actorid-upis', value: '0192:222222222' };
const SEGMENT = 'iso6523-actorid-upis::0192:222222222';
const DOCUMENT_TYPE: ScopedId = {
  scheme: 'busdox-docid-qns',
  value: 'urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice##urn:cen.eu:en16931:2017::2.1',
};
const PROCESS: ScopedId = { scheme: 'cenbii-procid-ubl', value: 'urn:www.cenbii.eu:profile:bii05:ver2.0' };
const TRANSPORT = 'peppol-transport-as4-v2_0';
const SML_ZONE = 'participant.sml.test.tech.peppol.org';
const SMP_BASE = 'https://smp.example.org';
const ENDPOINT = 'https://ap.example.org/as4';

const naptr = (url = SMP_BASE) => [
  { order: 10, preference: 10, flags: 'U', service: 'Meta:SMP', regexp: `!^.*$!${url}!`, replacement: '.' },
];

function refHref(documentType: ScopedId = DOCUMENT_TYPE, base = SMP_BASE): string {
  return `${base}/${encodeURIComponent(SEGMENT)}/services/${encodeURIComponent(`${documentType.scheme}::${documentType.value}`)}`;
}

function validatorFor(ap: TestPki = AP, smp: TestPki = SMP) {
  const validator = createCertificateValidator({
    roots: [ap.root.certPem, smp.root.certPem],
    intermediates: [ap.intermediate.certPem, smp.intermediate.certPem],
    intermediatesByPurpose: {
      'receiver-encryption': [ap.intermediate.certPem],
      'receipt-signer': [ap.intermediate.certPem],
      'message-signer': [ap.intermediate.certPem],
      'smp-signer': [smp.intermediate.certPem],
    },
    revocation: defaultRevocationPolicy({ ocsp: false, crl: false }),
  });
  return (input: Parameters<typeof validator.validate>[0]) => validator.validate(input);
}

interface Route {
  readonly contains: string;
  readonly status?: number;
  readonly body?: string;
  readonly contentType?: string;
}

function mockFetch(routes: readonly Route[]): typeof fetch {
  return (async (input: RequestInfo | URL) => {
    const url = String(input);
    const route = routes.find((candidate) => url.includes(candidate.contains));
    if (!route) return new Response('', { status: 404 });
    return new Response(route.body ?? '', {
      status: route.status ?? 200,
      headers: { 'content-type': route.contentType ?? 'application/xml' },
    });
  }) as unknown as typeof fetch;
}

function metadata(overrides: Partial<Parameters<typeof buildSignedServiceMetadata>[0]> = {}): string {
  return buildSignedServiceMetadata({
    participant: PARTICIPANT,
    documentType: DOCUMENT_TYPE,
    process: PROCESS,
    transportProfile: TRANSPORT,
    endpointUrl: ENDPOINT,
    receiverCertificatePem: AP.receiver.certPem,
    signer: SMP.sender,
    ...overrides,
  });
}

function baseInput(overrides: Partial<LookupInput> = {}): LookupInput {
  const routes: Route[] = [
    { contains: '/services/', body: metadata() },
    {
      contains: encodeURIComponent(SEGMENT),
      body: buildServiceGroup(PARTICIPANT, [{ documentType: DOCUMENT_TYPE, href: refHref() }]),
    },
  ];
  return {
    participant: PARTICIPANT,
    documentType: DOCUMENT_TYPE,
    process: PROCESS,
    sml: SML_ZONE,
    validateCertificate: validatorFor(),
    resolveNaptr: async () => naptr(),
    fetch: mockFetch(routes),
    now: () => new Date(),
    ...overrides,
  };
}

test('participantHash matches the Policy for use of Identifiers example', () => {
  assert.equal(participantHash('0088:123abc'), 'Y7DZFXAF3D4CJZ4KCGRXTEC6TWVCGA4KY7ZWA5BOIF6MSWD4TDRQ');
  assert.equal(participantHash('0088:123ABC'), participantHash('0088:123abc'));
});

test('participantDnsName is <hash>.<scheme>.<sml zone>', () => {
  assert.equal(
    participantDnsName(PARTICIPANT, SML_ZONE),
    `${participantHash(PARTICIPANT.value)}.iso6523-actorid-upis.participant.sml.test.tech.peppol.org`,
  );
});

test('lookupParticipant returns the endpoint, certificate and dates', async () => {
  const result = await lookupParticipant(
    baseInput({
      fetch: mockFetch([
        {
          contains: '/services/',
          body: metadata({
            serviceActivationDate: '2020-01-01T00:00:00Z',
            serviceExpirationDate: '2999-01-01T00:00:00Z',
          }),
        },
        {
          contains: encodeURIComponent(SEGMENT),
          body: buildServiceGroup(PARTICIPANT, [{ documentType: DOCUMENT_TYPE, href: refHref() }]),
        },
      ]),
    }),
  );
  assert.equal(result.outcome, 'found');
  if (result.outcome !== 'found') return;
  assert.equal(result.endpointUrl, ENDPOINT);
  assert.equal(result.transportProfile, TRANSPORT);
  assert.equal(result.serviceActivationDate, '2020-01-01T00:00:00Z');
  assert.equal(result.serviceExpirationDate, '2999-01-01T00:00:00Z');
  assert.equal(new X509Certificate(result.receiverCertificate).subject, AP.receiver.cert.subject);
  assert.equal(new X509Certificate(result.signerCertificate).subject, SMP.sender.cert.subject);
  assert.ok(result.smpUrl.includes('/services/'));
});

test('lookupParticipant reports not-registered when the SML has no NAPTR', async () => {
  const notFound = (): never => {
    const error = new Error('queryNaptr ENOTFOUND') as NodeJS.ErrnoException;
    error.code = 'ENOTFOUND';
    throw error;
  };
  const result = await lookupParticipant(baseInput({ resolveNaptr: async () => notFound() }));
  assert.equal(result.outcome, 'not-registered');
});

test('lookupParticipant reports not-registered when the SMP has no service group', async () => {
  const result = await lookupParticipant(
    baseInput({ fetch: mockFetch([{ contains: encodeURIComponent(SEGMENT), status: 404 }]) }),
  );
  assert.equal(result.outcome, 'not-registered');
});

test('lookupParticipant reports a retryable unavailable on DNS failure', async () => {
  const servfail = (): never => {
    const error = new Error('queryNaptr ESERVFAIL') as NodeJS.ErrnoException;
    error.code = 'ESERVFAIL';
    throw error;
  };
  const result = await lookupParticipant(baseInput({ resolveNaptr: async () => servfail() }));
  assert.equal(result.outcome, 'unavailable');
  if (result.outcome === 'unavailable') assert.equal(result.retryable, true);
});

test('lookupParticipant reports a retryable unavailable on SMP HTTP 500', async () => {
  const result = await lookupParticipant(
    baseInput({ fetch: mockFetch([{ contains: encodeURIComponent(SEGMENT), status: 500 }]) }),
  );
  assert.equal(result.outcome, 'unavailable');
  if (result.outcome === 'unavailable') assert.equal(result.retryable, true);
});

test('lookupParticipant rejects a non-https SMP URL from SML', async () => {
  const result = await lookupParticipant(baseInput({ resolveNaptr: async () => naptr('http://smp.example.org') }));
  assert.equal(result.outcome, 'unavailable');
  if (result.outcome === 'unavailable') assert.equal(result.retryable, false);
});

test('lookupParticipant reports not-supported when no reference matches the document type', async () => {
  const other: ScopedId = { scheme: 'busdox-docid-qns', value: 'urn:other::Doc##x::1.0' };
  const result = await lookupParticipant(
    baseInput({
      fetch: mockFetch([
        { contains: '/services/', body: metadata({ documentType: other }) },
        {
          contains: encodeURIComponent(SEGMENT),
          body: buildServiceGroup(PARTICIPANT, [{ documentType: other, href: refHref(other) }]),
        },
      ]),
    }),
  );
  assert.equal(result.outcome, 'not-supported');
});

test('lookupParticipant reports not-supported when the process does not match', async () => {
  const other: ScopedId = { scheme: 'cenbii-procid-ubl', value: 'urn:other:process' };
  const result = await lookupParticipant(
    baseInput({
      fetch: mockFetch([
        { contains: '/services/', body: metadata({ process: other }) },
        {
          contains: encodeURIComponent(SEGMENT),
          body: buildServiceGroup(PARTICIPANT, [{ documentType: DOCUMENT_TYPE, href: refHref() }]),
        },
      ]),
    }),
  );
  assert.equal(result.outcome, 'not-supported');
});

test('lookupParticipant ignores a not-yet-active endpoint', async () => {
  const result = await lookupParticipant(
    baseInput({
      fetch: mockFetch([
        { contains: '/services/', body: metadata({ serviceActivationDate: '2999-01-01T00:00:00Z' }) },
        {
          contains: encodeURIComponent(SEGMENT),
          body: buildServiceGroup(PARTICIPANT, [{ documentType: DOCUMENT_TYPE, href: refHref() }]),
        },
      ]),
    }),
  );
  assert.equal(result.outcome, 'not-supported');
});

test('lookupParticipant ignores an expired endpoint', async () => {
  const result = await lookupParticipant(
    baseInput({
      fetch: mockFetch([
        { contains: '/services/', body: metadata({ serviceExpirationDate: '2000-01-01T00:00:00Z' }) },
        {
          contains: encodeURIComponent(SEGMENT),
          body: buildServiceGroup(PARTICIPANT, [{ documentType: DOCUMENT_TYPE, href: refHref() }]),
        },
      ]),
    }),
  );
  assert.equal(result.outcome, 'not-supported');
});

test('lookupParticipant rejects tampered service metadata', async () => {
  const tampered = metadata().replace(ENDPOINT, 'https://evil.example.org/as4');
  const result = await lookupParticipant(
    baseInput({
      fetch: mockFetch([
        { contains: '/services/', body: tampered },
        {
          contains: encodeURIComponent(SEGMENT),
          body: buildServiceGroup(PARTICIPANT, [{ documentType: DOCUMENT_TYPE, href: refHref() }]),
        },
      ]),
    }),
  );
  assert.equal(result.outcome, 'signature-invalid');
});

test('lookupParticipant rejects an access point certificate used as SMP signer', async () => {
  const result = await lookupParticipant(
    baseInput({
      fetch: mockFetch([
        { contains: '/services/', body: metadata({ signer: AP.sender }) },
        {
          contains: encodeURIComponent(SEGMENT),
          body: buildServiceGroup(PARTICIPANT, [{ documentType: DOCUMENT_TYPE, href: refHref() }]),
        },
      ]),
    }),
  );
  assert.equal(result.outcome, 'signature-invalid');
});

test('lookupParticipant rejects an expired SMP signer', async () => {
  const result = await lookupParticipant(
    baseInput({
      validateCertificate: validatorFor(AP, EXPIRED_SMP),
      fetch: mockFetch([
        { contains: '/services/', body: metadata({ signer: EXPIRED_SMP.sender }) },
        {
          contains: encodeURIComponent(SEGMENT),
          body: buildServiceGroup(PARTICIPANT, [{ documentType: DOCUMENT_TYPE, href: refHref() }]),
        },
      ]),
    }),
  );
  assert.equal(result.outcome, 'signature-invalid');
});

test('lookupParticipant follows one SMP Redirect', async () => {
  const finalUrl = 'https://smp2.example.org/iso6523-actorid-upis/services/final';
  const redirect = metadata({
    redirectHref: finalUrl,
    participant: PARTICIPANT,
    documentType: DOCUMENT_TYPE,
  });
  const final = metadata();
  const result = await lookupParticipant(
    baseInput({
      fetch: mockFetch([
        { contains: 'smp2.example.org', body: final },
        { contains: '/services/', body: redirect },
        {
          contains: encodeURIComponent(SEGMENT),
          body: buildServiceGroup(PARTICIPANT, [{ documentType: DOCUMENT_TYPE, href: refHref() }]),
        },
      ]),
    }),
  );
  assert.equal(result.outcome, 'found');
  if (result.outcome === 'found') assert.equal(result.smpUrl, finalUrl);
});

test('lookupParticipant does not follow more than one SMP redirect', async () => {
  const first = 'https://smp1.example.org/redirect';
  const second = 'https://smp2.example.org/redirect';
  const result = await lookupParticipant(
    baseInput({
      fetch: mockFetch([
        { contains: 'smp2.example.org', body: metadata({ redirectHref: 'https://smp3.example.org/redirect' }) },
        { contains: 'smp1.example.org/redirect', body: metadata({ redirectHref: second }) },
        { contains: '/services/', body: metadata({ redirectHref: first }) },
        {
          contains: encodeURIComponent(SEGMENT),
          body: buildServiceGroup(PARTICIPANT, [{ documentType: DOCUMENT_TYPE, href: refHref() }]),
        },
      ]),
    }),
  );
  assert.equal(result.outcome, 'unavailable');
  if (result.outcome === 'unavailable') assert.equal(result.retryable, false);
});

test('the validator keeps the SMP CA and the access point CA apart', async () => {
  const validate = validatorFor();
  const now = new Date();
  const smpAsSmp = await validate({ certificatePem: SMP.sender.certPem, purpose: 'smp-signer', now });
  const apAsSmp = await validate({ certificatePem: AP.sender.certPem, purpose: 'smp-signer', now });
  const apAsMessage = await validate({ certificatePem: AP.sender.certPem, purpose: 'message-signer', now });
  const smpAsReceipt = await validate({ certificatePem: SMP.sender.certPem, purpose: 'receipt-signer', now });
  assert.equal(smpAsSmp.ok, true);
  assert.equal(apAsMessage.ok, true);
  assert.equal(apAsSmp.ok, false);
  assert.equal(smpAsReceipt.ok, false);
});

test('lookupParticipant refuses an oversized SMP response', async () => {
  const oversized = (async () => {
    let sent = 0;
    const chunk = new Uint8Array(1024 * 1024);
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (sent >= 9) {
          controller.close();
          return;
        }
        sent += 1;
        controller.enqueue(chunk);
      },
    });
    return new Response(stream, { status: 200, headers: { 'content-type': 'application/xml' } });
  }) as unknown as typeof fetch;
  const result = await lookupParticipant(baseInput({ fetch: oversized }));
  assert.equal(result.outcome, 'unavailable');
  if (result.outcome === 'unavailable') {
    assert.equal(result.retryable, false);
    assert.match(result.reason, /exceeds/);
  }
});

test('lookupParticipant never throws for an expected failure', async () => {
  const results: LookupResult[] = await Promise.all([
    lookupParticipant(
      baseInput({
        resolveNaptr: async () => {
          throw new Error('boom');
        },
      }),
    ),
    lookupParticipant(baseInput({ fetch: mockFetch([{ contains: encodeURIComponent(SEGMENT), status: 503 }]) })),
    lookupParticipant(baseInput({ resolveNaptr: async () => [] })),
  ]);
  for (const result of results) assert.ok(typeof result.outcome === 'string');
});

// --- Item 6: strict parsing and bounded canonicalisation ---------------------

test('lookupParticipant rejects an invalid limits override before any DNS query', async () => {
  let dnsCalled = false;
  const result = await lookupParticipant(
    baseInput({
      limits: { maxMetadataBytes: Number.NaN },
      resolveNaptr: async () => {
        dnsCalled = true;
        return naptr();
      },
    }),
  );
  assert.equal(result.outcome, 'unavailable');
  if (result.outcome === 'unavailable') assert.match(result.reason, /limits\.invalid/);
  assert.equal(dnsCalled, false, 'no DNS query may run for an invalid override');
});

test('lookupParticipant rejects a DOCTYPE-bearing ServiceGroup with the strict reason', async () => {
  const result = await lookupParticipant(
    baseInput({
      fetch: mockFetch([
        { contains: '/services/', body: metadata() },
        { contains: encodeURIComponent(SEGMENT), body: '<!DOCTYPE x []><x/>' },
      ]),
    }),
  );
  assert.equal(result.outcome, 'unavailable');
  if (result.outcome === 'unavailable') assert.match(result.reason, /xml\.doctype/);
});

test('lookupParticipant rejects malformed signed metadata rather than repairing it', async () => {
  const result = await lookupParticipant(
    baseInput({
      fetch: mockFetch([
        { contains: '/services/', body: '<SignedServiceMetadata><broken></SignedServiceMetadata>' },
        {
          contains: encodeURIComponent(SEGMENT),
          body: buildServiceGroup(PARTICIPANT, [{ documentType: DOCUMENT_TYPE, href: refHref() }]),
        },
      ]),
    }),
  );
  assert.equal(result.outcome, 'unavailable');
  if (result.outcome === 'unavailable') assert.match(result.reason, /xml\.malformed/);
});

test('an over-canonical-budget SMP response is signature-invalid without canonicalising', async () => {
  // Build the fixture (which itself canonicalises) before installing the counter.
  const input = baseInput({
    limits: { maxCanonicalBytes: 8 },
    fetch: mockFetch([
      { contains: '/services/', body: metadata() },
      {
        contains: encodeURIComponent(SEGMENT),
        body: buildServiceGroup(PARTICIPANT, [{ documentType: DOCUMENT_TYPE, href: refHref() }]),
      },
    ]),
  });
  let canonicalizations = 0;
  xmlHooks.onCanonicalize = () => {
    canonicalizations += 1;
  };
  try {
    const result = await lookupParticipant(input);
    assert.equal(result.outcome, 'signature-invalid');
    assert.equal(canonicalizations, 0, 'the canonicaliser must not run over budget');
  } finally {
    delete xmlHooks.onCanonicalize;
  }
});

test('an over-canonical-budget SMP response never clones the document', () => {
  const document = parseStrictXml(Buffer.from(metadata(), 'utf8'), {
    maxBytes: defaultLookupLimits.maxMetadataBytes,
    maxDepth: defaultLookupLimits.maxDepth,
    maxNodes: defaultLookupLimits.maxMetadataNodes,
    maxAttributes: defaultLookupLimits.maxAttributes,
    maxTokenBytes: defaultLookupLimits.maxTokenBytes,
  });
  let clones = 0;
  const original = document.cloneNode.bind(document);
  (document as unknown as { cloneNode: typeof original }).cloneNode = (...args: Parameters<typeof original>) => {
    clones += 1;
    return original(...args);
  };
  const result = verifySmpSignature(document, { ...defaultLookupLimits, maxCanonicalBytes: 8 });
  assert.equal(result.ok, false);
  assert.equal(clones, 0, 'an over-budget response must not be cloned');
});

test('lookupParticipant rejects a hostile redirect target with the strict reason', async () => {
  const result = await lookupParticipant(
    baseInput({
      fetch: mockFetch([
        { contains: '/services/', body: metadata({ redirectHref: `${SMP_BASE}/redirected.xml` }) },
        { contains: 'redirected.xml', body: '<!DOCTYPE x []><x/>' },
        {
          contains: encodeURIComponent(SEGMENT),
          body: buildServiceGroup(PARTICIPANT, [{ documentType: DOCUMENT_TYPE, href: refHref() }]),
        },
      ]),
    }),
  );
  assert.equal(result.outcome, 'unavailable');
  if (result.outcome === 'unavailable') {
    assert.match(result.reason, /xml\.doctype/);
    assert.match(result.reason, /redirected\.xml/);
  }
});
