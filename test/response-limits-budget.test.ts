import test from 'node:test';
import assert from 'node:assert/strict';
import { constants, sign as cryptoSign } from 'node:crypto';
import { ALGO_EXC_C14N, ALGO_SHA256, DS_NS, SOAP_ENV_NS, WSU_NS } from '../src/constants.js';
import { defaultRevocationPolicy } from '../src/certificate-validator.js';
import { canonicalSizeUpperBound, canonicalize, canonicalizeDigest } from '../src/xml/c14n.js';
import { firstByLocalName, parseXml } from '../src/xml/nodes.js';
import { parseSignal } from '../src/xml/signal.js';
import { verifyWsSecuritySignature } from '../src/xml/ws-security.js';
import { xmlHooks } from '../src/xml/hooks.js';
import { verifyReceipt, type SignedReference } from '../src/receipt/verify.js';
import { defaultResponseLimits } from '../src/response-limits.js';
import { createTestPki } from './helpers/pki.js';
import { buildSignedReceipt, type ReceiptReference } from './helpers/receipt.js';
import { testValidator } from './helpers/input.js';

/**
 * Item 6: the receipt canonicalisation budget is a **total** across SignedInfo
 * and every reference (so 64 references cannot multiply a per-call bound), and
 * the namespace-expansion attack Item 4 fixed on receive is rejected on the
 * response path too.
 */
const pki = createTestPki();
const MESSAGE_ID = 'the-message-we-sent@as4-sender.test';
const revocation = defaultRevocationPolicy({ ocsp: false, crl: false });
const validateCertificate = testValidator(pki, { revocation });

const refs: ReceiptReference[] = [
  { uri: '#body-id', transform: ALGO_EXC_C14N, digest: 'AAAA' },
  { uri: '#messaging-id', transform: ALGO_EXC_C14N, digest: 'BBBB' },
  {
    uri: 'cid:attachment@x',
    transform: 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#STR-Transform',
    digest: 'CCCC',
  },
];
const signedReferences: SignedReference[] = refs.map((reference) => ({ uri: reference.uri, digest: reference.digest }));

let canonicalizeCalls = 0;
xmlHooks.onCanonicalize = () => {
  canonicalizeCalls += 1;
};
function reset(): void {
  canonicalizeCalls = 0;
}

/** Add a second in-envelope reference to a fresh element and re-sign SignedInfo. */
function addReference(xml: string): { document: Document } {
  const document = parseXml(Buffer.from(xml, 'utf8'));
  const body = firstByLocalName(document, SOAP_ENV_NS, 'Body')!;
  const extra = document.createElementNS(SOAP_ENV_NS, 'env:Extra');
  extra.setAttributeNS(WSU_NS, 'wsu:Id', 'extra-id');
  extra.appendChild(document.createTextNode('extra content '.repeat(40)));
  body.appendChild(extra);

  const signedInfo = firstByLocalName(document, DS_NS, 'SignedInfo')!;
  const reference = document.createElementNS(DS_NS, 'ds:Reference');
  reference.setAttribute('URI', '#extra-id');
  const transforms = document.createElementNS(DS_NS, 'ds:Transforms');
  const transform = document.createElementNS(DS_NS, 'ds:Transform');
  transform.setAttribute('Algorithm', ALGO_EXC_C14N);
  transforms.appendChild(transform);
  reference.appendChild(transforms);
  const digestMethod = document.createElementNS(DS_NS, 'ds:DigestMethod');
  digestMethod.setAttribute('Algorithm', ALGO_SHA256);
  reference.appendChild(digestMethod);
  const digestValue = document.createElementNS(DS_NS, 'ds:DigestValue');
  digestValue.appendChild(document.createTextNode(canonicalizeDigest(extra)));
  reference.appendChild(digestValue);
  signedInfo.appendChild(reference);

  const signatureValue = firstByLocalName(document, DS_NS, 'SignatureValue')!;
  while (signatureValue.firstChild) signatureValue.removeChild(signatureValue.firstChild);
  signatureValue.appendChild(
    document.createTextNode(
      cryptoSign('sha256', Buffer.from(canonicalize(signedInfo), 'utf8'), {
        key: pki.receiver.keyObject,
        padding: constants.RSA_PKCS1_PADDING,
      }).toString('base64'),
    ),
  );
  return { document };
}

test('the total canonical budget is shared across SignedInfo and every reference', () => {
  const { xml } = buildSignedReceipt({ signer: pki.receiver, refToMessageId: MESSAGE_ID, references: [] });
  const { document } = addReference(xml);
  const signedInfo = firstByLocalName(document, DS_NS, 'SignedInfo')!;
  const references = Array.from(signedInfo.getElementsByTagNameNS(DS_NS, 'Reference'));
  const elements = references.map((reference) => {
    const uri = reference.getAttribute('URI')!;
    const id = uri.slice(1);
    const all = document.getElementsByTagName('*');
    for (let i = 0; i < all.length; i += 1) {
      const element = all.item(i)!;
      if (element.getAttributeNS(WSU_NS, 'Id') === id) return element;
    }
    throw new Error('unreachable');
  });

  const bounds = [signedInfo, ...elements].map((element) => canonicalSizeUpperBound(element));
  // The verifier canonicalises SignedInfo with its InclusiveNamespaces list.
  const actuals = [
    Buffer.byteLength(canonicalize(signedInfo, ['env']), 'utf8'),
    ...elements.map((element) => Buffer.byteLength(canonicalize(element), 'utf8')),
  ];
  const perCall = Math.max(...bounds) + 128;
  const total = actuals.reduce((sum, size) => sum + size, 0);
  const canonicalisations = actuals.length;

  // Each canonicalisation fits the per-call bound, but their sum exceeds the total.
  reset();
  const rejected = verifyWsSecuritySignature(document, {
    maxCanonicalBytes: perCall,
    maxTotalCanonicalBytes: total - 1,
  });
  assert.equal(rejected.ok, false);
  if (!rejected.ok) assert.equal(rejected.reason, 'too-large');
  const rejectedCalls = canonicalizeCalls;
  assert.ok(rejectedCalls < canonicalisations, `stopped at ${rejectedCalls} of ${canonicalisations}`);
  assert.equal(rejectedCalls, 2, 'stopped at the reference that would not fit the remaining budget');

  // Positive control: a total that covers the sum verifies, with every reference.
  reset();
  const accepted = verifyWsSecuritySignature(document, { maxCanonicalBytes: perCall, maxTotalCanonicalBytes: total });
  assert.equal(accepted.ok, true);
  assert.equal(canonicalizeCalls, canonicalisations);

  // The per-call bound alone also verifies: the total is what rejected the first run.
  reset();
  assert.equal(verifyWsSecuritySignature(document, { maxCanonicalBytes: perCall }).ok, true);
});

test('the namespace-expansion receipt is rejected at the default limits before canonicalising', async () => {
  const uri = `urn:${'x'.repeat(60_000)}`;
  const pad = `<ds:Object><a:Pad xmlns:a="${uri}">${'<a:x/>'.repeat(2000)}</a:Pad></ds:Object>`;
  const xml = buildSignedReceipt({ signer: pki.receiver, refToMessageId: MESSAGE_ID, references: refs }).xml.replace(
    '<ds:SignatureMethod',
    `${pad}<ds:SignatureMethod`,
  );

  // The attack passes strict parsing under the default limits.
  assert.ok(Buffer.byteLength(xml, 'utf8') < defaultResponseLimits.maxXmlBytes);
  const parsed = parseSignal(Buffer.from(xml, 'utf8'));
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;

  const signedInfo = firstByLocalName(parsed.signal.document, DS_NS, 'SignedInfo')!;
  assert.ok(
    canonicalSizeUpperBound(signedInfo) > defaultResponseLimits.maxCanonicalBytes,
    `SignedInfo bound ${canonicalSizeUpperBound(signedInfo)} does not exceed the budget`,
  );

  reset();
  const result = await verifyReceipt({
    signal: parsed.signal,
    as4MessageId: MESSAGE_ID,
    receiverCertificatePem: pki.receiver.certPem,
    signedReferences,
    validateCertificate,
    now: () => new Date(),
  });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'receipt.malformed');
  assert.equal(canonicalizeCalls, 0, 'the canonicaliser must not run on the expansion');
});
