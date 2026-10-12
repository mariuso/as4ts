import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createCertificateValidator, defaultRevocationPolicy } from '../src/certificate-validator.js';
import { DS_NS, EBBP_SIGNALS_NS, WSSE_NS } from '../src/constants.js';
import { verifyReceipt } from '../src/receipt/verify.js';
import { elementsByLocalName, firstByLocalName, textOf } from '../src/xml/nodes.js';
import { parseSignal, type ParsedSignal } from '../src/xml/signal.js';
import { normalizePem } from '../src/util.js';

/**
 * Golden receipts: raw signal messages captured from real access points on the
 * Peppol test network by this project's own send path, and the signer's public
 * certificate. No third-party material is involved.
 *
 * Dropping `<name>.receipt.xml` into test/fixtures/captures/ adds a case; the
 * test is self-describing (message id, signer and time come from the capture).
 */
const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, 'fixtures', 'captures');
const trust = join(here, '..', 'assets', 'trust');

// Bundled G3 test PKI (the captures below were signed under it).
const roots = [readFileSync(join(trust, 'test-root.pem'), 'utf8')];
const intermediates = [
  readFileSync(join(trust, 'test-apca.pem'), 'utf8'),
  readFileSync(join(trust, 'test-smpca.pem'), 'utf8'),
];

function signerPem(signal: ParsedSignal): string {
  const token = elementsByLocalName(signal.document, WSSE_NS, 'BinarySecurityToken')[0];
  assert.ok(token, 'receipt has no BinarySecurityToken');
  return normalizePem(`-----BEGIN CERTIFICATE-----\n${textOf(token)!.replace(/\s+/g, '')}\n-----END CERTIFICATE-----`);
}

/** The capture echoes the original message's references; we do not hold the
 * outbound message, so the expected digests come from the receipt's own
 * NonRepudiationInformation. Signature, C14N, signer chain and binding are still
 * verified cryptographically. */
function nonRepudiationReferences(signal: ParsedSignal) {
  const nri = firstByLocalName(signal.signalElement, EBBP_SIGNALS_NS, 'NonRepudiationInformation');
  assert.ok(nri, 'receipt has no NonRepudiationInformation');
  return elementsByLocalName(nri, DS_NS, 'Reference').map((reference) => ({
    uri: reference.getAttribute('URI') ?? '',
    digest: textOf(firstByLocalName(reference, DS_NS, 'DigestValue'))!.trim(),
  }));
}

const captures = readdirSync(fixtures).filter((name) => name.endsWith('.receipt.xml'));
assert.ok(captures.length > 0, 'no golden captures committed');

for (const file of captures) {
  test(`verifies the captured receipt ${file}`, async () => {
    const signal = parseSignal(readFileSync(join(fixtures, file)));
    assert.ok(signal, `${file}: could not parse a signal`);
    assert.equal(signal.kind, 'receipt', `${file}: not a receipt`);
    assert.ok(signal.timestamp, `${file}: receipt has no timestamp`);
    assert.ok(signal.refToMessageId, `${file}: receipt has no RefToMessageId`);

    const signer = signerPem(signal);

    // Deterministic and offline: validate as of the receipt's own timestamp
    // (necessarily inside the signer's validity window) and do not touch the
    // network for revocation.
    const validator = createCertificateValidator({
      roots,
      intermediates,
      revocation: defaultRevocationPolicy({ ocsp: false, crl: false, unreachable: 'soft' }),
    });

    const result = await verifyReceipt({
      signal,
      as4MessageId: signal.refToMessageId,
      receiverCertificatePem: signer,
      signedReferences: nonRepudiationReferences(signal),
      validateCertificate: (input) => validator.validate(input),
      now: () => new Date(signal.timestamp!),
    });

    assert.equal(result.ok, true, result.ok ? '' : `${result.reason}: ${result.detail}`);
    if (result.ok) {
      assert.equal(result.receipt.refToMessageId, signal.refToMessageId);
      assert.equal(result.receipt.signerMatchesSmPCertificate, true);
      assert.ok(result.receipt.raw.length > 0);
    }
  });
}
