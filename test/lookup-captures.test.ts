import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createCertificateValidator, defaultRevocationPolicy } from '../src/certificate-validator.js';
import { lookupParticipant, type LookupInput } from '../src/lookup/index.js';
import { selectEndpoint, serviceMetadataRedirectHref } from '../src/lookup/smp.js';
import { verifySmpSignature } from '../src/lookup/smp-signature.js';
import { parseXml, serializeXml } from '../src/xml/nodes.js';
import type { ParticipantId, ScopedId } from '../src/types.js';
import { DS_NS } from '../src/constants.js';

/**
 * Real SMP responses captured from the Peppol test network. Two independent SMP
 * implementations: smp.helger.com (phase4) and test-smp.elma-smp.no. The raw
 * ServiceGroup and SignedServiceMetadata are committed under test/fixtures/smp
 * and the participant/document type/process they serve are in manifest.json.
 *
 * These are not optional: the synthetic tests sign with the same function the
 * verifier uses, so they cannot catch a canonicalisation mistake, a namespace
 * mix-up, or facts read from outside the signed node-set. These can.
 */
const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, 'fixtures', 'smp');
const trust = join(here, '..', 'assets', 'trust');

interface Fixture {
  readonly name: string;
  readonly participant: ParticipantId;
  readonly documentType: ScopedId;
  readonly process: ScopedId;
  readonly sml: string;
  readonly smpBase: string;
  readonly endpointUrl: string;
}

const manifest = JSON.parse(readFileSync(join(fixtures, 'manifest.json'), 'utf8')) as Fixture[];
const read = (name: string): string => readFileSync(join(fixtures, name), 'utf8');

const roots = [readFileSync(join(trust, 'test-root.pem'), 'utf8')];
const apca = readFileSync(join(trust, 'test-apca.pem'), 'utf8');
const smpca = readFileSync(join(trust, 'test-smpca.pem'), 'utf8');

function validateCertificate(): LookupInput['validateCertificate'] {
  const validator = createCertificateValidator({
    roots,
    intermediates: [apca, smpca],
    intermediatesByPurpose: { 'smp-signer': [smpca] },
    revocation: defaultRevocationPolicy({ ocsp: false, crl: false, unreachable: 'soft' }),
  });
  return (input) => validator.validate(input);
}

function naptr(smpBase: string) {
  return [{ order: 100, preference: 10, flags: 'U', service: 'Meta:SMP', regexp: `!.*!${smpBase}!`, replacement: '' }];
}

function mockFetch(routes: readonly { contains: string; body: string }[]): typeof fetch {
  return (async (input: RequestInfo | URL) => {
    const url = String(input);
    const route = routes.find((candidate) => url.includes(candidate.contains));
    if (!route) return new Response('', { status: 404 });
    return new Response(route.body, { status: 200, headers: { 'content-type': 'application/xml' } });
  }) as unknown as typeof fetch;
}

function inputFor(entry: Fixture, overrides: Partial<LookupInput> = {}): LookupInput {
  const segment = `${entry.participant.scheme}::${entry.participant.value}`;
  return {
    participant: entry.participant,
    documentType: entry.documentType,
    process: entry.process,
    sml: entry.sml,
    validateCertificate: validateCertificate(),
    resolveNaptr: async () => naptr(entry.smpBase),
    fetch: mockFetch([
      { contains: '/services/', body: read(`${entry.name}.signed.xml`) },
      { contains: encodeURIComponent(segment), body: read(`${entry.name}.group.xml`) },
    ]),
    now: () => new Date(),
    ...overrides,
  };
}

for (const entry of manifest) {
  test(`captured ${entry.name} response verifies and finds the endpoint`, async () => {
    const result = await lookupParticipant(inputFor(entry));
    assert.equal(result.outcome, 'found', result.outcome === 'found' ? '' : JSON.stringify(result));
    if (result.outcome === 'found') {
      assert.equal(result.endpointUrl, entry.endpointUrl);
      assert.equal(result.transportProfile, 'peppol-transport-as4-v2_0');
      assert.ok(result.signerCertificate.includes('BEGIN CERTIFICATE'));
    }
  });

  test(`captured ${entry.name} response carries inherited namespaces for inclusive C14N`, () => {
    // Regression for real responses that declare their namespaces on the root:
    // without passing the inherited namespaces, SignedInfo canonicalises
    // differently and the signature fails.
    const verified = verifySmpSignature(parseXml(read(`${entry.name}.signed.xml`)));
    assert.equal(verified.ok, true, verified.ok ? '' : verified.reason);
  });
}

/**
 * A genuine signature for participant A, with a forged ServiceInformation for
 * participant B hidden inside the ds:Signature element. The digest does not
 * cover the inside of the signature, so the signature still verifies; the attack
 * is to get the lookup to read the forged facts. The verifier must return only
 * the nodes the digest covered.
 */
function forgeInsideSignature(realXml: string, fakeServiceInformation: string): string {
  const match = /<(?:[A-Za-z0-9]+:)?Signature\b[^>]*>/.exec(realXml);
  assert.ok(match, 'fixture has no Signature element');
  const at = match.index + match[0].length;
  return realXml.slice(0, at) + fakeServiceInformation + realXml.slice(at);
}

const EVIL_PARTICIPANT: ParticipantId = { scheme: 'iso6523-actorid-upis', value: '0192:666666666' };
const EVIL_DOCUMENT_TYPE: ScopedId = { scheme: 'busdox-docid-qns', value: 'urn:evil::Invoice##evil::9.9' };
const EVIL_PROCESS: ScopedId = { scheme: 'cenbii-procid-ubl', value: 'urn:evil:process' };

const EVIL_SERVICE_INFORMATION = (() => {
  const SMP = 'http://busdox.org/serviceMetadata/publishing/1.0/';
  const IDS = 'http://busdox.org/transport/identifiers/1.0/';
  const WSA = 'http://www.w3.org/2005/08/addressing';
  return (
    `<smp:ServiceInformation xmlns:smp="${SMP}" xmlns:id="${IDS}" xmlns:wsa="${WSA}">` +
    `<id:ParticipantIdentifier scheme="iso6523-actorid-upis">${EVIL_PARTICIPANT.value}</id:ParticipantIdentifier>` +
    `<id:DocumentIdentifier scheme="busdox-docid-qns">${EVIL_DOCUMENT_TYPE.value}</id:DocumentIdentifier>` +
    `<smp:ProcessList><smp:Process>` +
    `<id:ProcessIdentifier scheme="cenbii-procid-ubl">${EVIL_PROCESS.value}</id:ProcessIdentifier>` +
    `<smp:ServiceEndpointList><smp:Endpoint transportProfile="peppol-transport-as4-v2_0">` +
    `<wsa:EndpointReference><wsa:Address>https://evil.example.org/as4</wsa:Address></wsa:EndpointReference>` +
    `<smp:Certificate>EVILCERTIFICATE</smp:Certificate>` +
    `</smp:Endpoint></smp:ServiceEndpointList></smp:Process></smp:ProcessList></smp:ServiceInformation>`
  );
})();

const helger = manifest.find((entry) => entry.name === 'helger')!;

test('forged facts inside the ds:Signature are not read as verified facts', () => {
  const forged = forgeInsideSignature(read('helger.signed.xml'), EVIL_SERVICE_INFORMATION);
  const verified = verifySmpSignature(parseXml(forged));
  assert.equal(verified.ok, true, verified.ok ? '' : verified.reason);
  if (!verified.ok) return;

  // The digest-covered document must not contain the forged facts.
  const cleaned = serializeXml(verified.verifiedDocument);
  assert.ok(!cleaned.includes('evil.example.org'), 'forged endpoint leaked into the verified document');
  assert.ok(!cleaned.includes(EVIL_DOCUMENT_TYPE.value), 'forged document type leaked into the verified document');

  // And selecting for the attacker's facts finds nothing.
  const selection = selectEndpoint(verified.verifiedDocument, {
    participant: EVIL_PARTICIPANT,
    documentType: EVIL_DOCUMENT_TYPE,
    process: EVIL_PROCESS,
    transportProfile: 'peppol-transport-as4-v2_0',
    now: new Date(),
  });
  assert.equal(selection.found, false);
});

test('lookup does not return a forged endpoint hidden inside the signature', async () => {
  const forged = forgeInsideSignature(read('helger.signed.xml'), EVIL_SERVICE_INFORMATION);
  const segment = `${EVIL_PARTICIPANT.scheme}::${EVIL_PARTICIPANT.value}`;
  const fakeGroup =
    `<?xml version="1.0" encoding="UTF-8"?>` +
    `<ServiceGroup xmlns="http://busdox.org/serviceMetadata/publishing/1.0/">` +
    `<ServiceMetadataReference href="${helger.smpBase}/${encodeURIComponent(segment)}/services/${encodeURIComponent(`${EVIL_DOCUMENT_TYPE.scheme}::${EVIL_DOCUMENT_TYPE.value}`)}"/>` +
    `</ServiceGroup>`;
  const result = await lookupParticipant({
    participant: EVIL_PARTICIPANT,
    documentType: EVIL_DOCUMENT_TYPE,
    process: EVIL_PROCESS,
    sml: helger.sml,
    validateCertificate: validateCertificate(),
    resolveNaptr: async () => naptr(helger.smpBase),
    fetch: mockFetch([
      { contains: '/services/', body: forged },
      { contains: encodeURIComponent(segment), body: fakeGroup },
    ]),
    now: () => new Date(),
  });
  assert.notEqual(result.outcome, 'found');
});

test('the SMP signature must be a direct child of the root', () => {
  // Move the signature inside smp:ServiceMetadata: the digest still verifies
  // (the enveloped transform removes it), but it is no longer root-level.
  const raw = read('helger.signed.xml');
  const match = /<((?:[A-Za-z0-9]+:)?)(Signature\b[^>]*)>[\s\S]*?<\/\1Signature>/.exec(raw);
  assert.ok(match, 'no signature block');
  const signatureBlock = match[0];
  const withoutSignature = raw.replace(signatureBlock, '');
  const nested = withoutSignature.replace(/(<(?:[A-Za-z0-9]+:)?ServiceMetadata\b[^>]*>)/, `$1${signatureBlock}`);
  const verified = verifySmpSignature(parseXml(nested));
  assert.equal(verified.ok, false);
});

test('the SMP signature reference URI must be empty', () => {
  const raw = read('helger.signed.xml');
  // Give the (only) reference an id-based URI. The reported fact must be
  // signature-invalid, not a digest over a sub-element.
  const tampered = raw.replace(/(<(?:\w+:)?Reference\b[^>]*\bURI=")"/, '$1#smp-service-metadata"');
  assert.notEqual(tampered, raw, 'failed to tamper the reference URI');
  const verified = verifySmpSignature(parseXml(tampered));
  assert.equal(verified.ok, false);
});

test('the redirect is read only from the verified document', () => {
  const forged = forgeInsideSignature(
    read('helger.signed.xml'),
    `<smp:Redirect xmlns:smp="http://busdox.org/serviceMetadata/publishing/1.0/" href="https://evil.example.org/redirect"/>`,
  );
  const verified = verifySmpSignature(parseXml(forged));
  assert.equal(verified.ok, true);
  if (!verified.ok) return;
  assert.equal(serviceMetadataRedirectHref(verified.verifiedDocument), null);
});

test('the default-namespace capture verifies and the signature is removed', () => {
  // The elma capture binds the ds elements to a default namespace instead of a
  // prefix; inclusive C14N must still carry the inherited namespaces.
  const verified = verifySmpSignature(parseXml(read('elma.signed.xml')));
  assert.equal(verified.ok, true, verified.ok ? '' : verified.reason);
  if (verified.ok) {
    const references = verified.verifiedDocument.getElementsByTagNameNS(DS_NS, 'Reference');
    assert.equal(references.length, 0, 'the signature must be removed from the verified document');
  }
});
