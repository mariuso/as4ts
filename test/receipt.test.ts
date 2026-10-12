import test from 'node:test';
import assert from 'node:assert/strict';
import { ALGO_EXC_C14N, SWA_TRANSFORM_SIGNATURE } from '../src/constants.js';
import { defaultRevocationPolicy } from '../src/certificate-validator.js';
import { parseSignal } from '../src/xml/signal.js';
import { verifyReceipt, type SignedReference } from '../src/receipt/verify.js';
import { createTestPki } from './helpers/pki.js';
import { buildSignedReceipt, unrelatedSelfSigned, type ReceiptReference } from './helpers/receipt.js';
import { testValidator } from './helpers/input.js';

const pki = createTestPki();
const MESSAGE_ID = 'the-message-we-sent@as4-sender.test';

const refs: ReceiptReference[] = [
  { uri: '#body-id', transform: ALGO_EXC_C14N, digest: 'AAAA' },
  { uri: '#messaging-id', transform: ALGO_EXC_C14N, digest: 'BBBB' },
  { uri: 'cid:attachment@x', transform: SWA_TRANSFORM_SIGNATURE, digest: 'CCCC' },
];
const signedReferences: SignedReference[] = refs.map((r) => ({ uri: r.uri, digest: r.digest }));

const validateCertificate = testValidator(pki, { revocation: defaultRevocationPolicy({ ocsp: false, crl: false }) });

function check(overrides: Partial<Parameters<typeof buildSignedReceipt>[0]> = {}, validator = validateCertificate) {
  const { signal } = buildSignedReceipt({
    signer: pki.receiver,
    refToMessageId: MESSAGE_ID,
    references: refs,
    ...overrides,
  });
  return verifyReceipt({
    signal,
    as4MessageId: MESSAGE_ID,
    receiverCertificatePem: pki.receiver.certPem,
    signedReferences,
    validateCertificate: validator,
    now: () => new Date(),
  });
}

test('verifies a well-formed receipt from the SMP-published certificate', async () => {
  const result = await check();
  assert.equal(result.ok, true);
  if (result.ok) {
    assert.equal(result.receipt.signerMatchesSmPCertificate, true);
    assert.equal(result.receipt.refToMessageId, MESSAGE_ID);
  }
});

test('rejects a receipt whose RefToMessageId differs', async () => {
  const result = await check({ refToMessageId: 'someone-else@test' });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'receipt.ref-mismatch');
});

test('rejects a receipt with an altered NonRepudiationInformation digest', async () => {
  const result = await check({ tamperedDigests: { 'cid:attachment@x': 'DDDD' } });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'receipt.digest-mismatch');
});

test('rejects a receipt that acknowledges only part of the message', async () => {
  // Only the (empty) body is acknowledged; the messaging header and attachment
  // are missing, so this must not count as accepting the whole message.
  const result = await check({ references: [refs[0]!] });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'receipt.malformed');
});

test('rejects an acknowledgement with an unsupported transform', async () => {
  const result = await check({
    references: [{ ...refs[0]!, transform: 'http://example.com/evil' }, refs[1]!, refs[2]!],
  });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'receipt.digest-mismatch');
});

test('rejects an acknowledgement with more than one transform', async () => {
  const result = await check({
    references: [{ ...refs[0]!, transforms: [ALGO_EXC_C14N, ALGO_EXC_C14N] }, refs[1]!, refs[2]!],
  });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'receipt.digest-mismatch');
});

test('rejects an acknowledgement with an unsupported digest method', async () => {
  const result = await check({
    references: [{ ...refs[0]!, digestMethod: 'http://example.com/evil' }, refs[1]!, refs[2]!],
  });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'receipt.digest-mismatch');
});

test('rejects an acknowledgement with altered transform parameters', async () => {
  const result = await check({
    references: [{ ...refs[0]!, inclusivePrefixes: ['env'] }, refs[1]!, refs[2]!],
  });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'receipt.digest-mismatch');
});

test('rejects a duplicate acknowledgement reference', async () => {
  const result = await check({ references: [refs[0]!, refs[0]!, refs[1]!, refs[2]!] });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'receipt.malformed');
});

test('rejects an acknowledgement for a reference we did not sign', async () => {
  const result = await check({
    references: [refs[0]!, refs[1]!, refs[2]!, { uri: '#extra', transform: ALGO_EXC_C14N, digest: 'ZZZZ' }],
  });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'receipt.malformed');
});

test('rejects a receipt whose own signature references an unresolved element', async () => {
  const result = await check({
    extraSignedInfoReferences: [{ uri: '#does-not-exist', transform: ALGO_EXC_C14N, digest: 'AAAA' }],
  });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'receipt.malformed');
});

test('rejects a receipt with a broken signature', async () => {
  const result = await check({ breakSignature: true });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'receipt.bad-signature');
});

test('rejects a receipt from an untrusted signer', async () => {
  const unrelated = unrelatedSelfSigned();
  const result = await check({ signer: unrelated, embeddedCertPem: unrelated.certPem });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'receipt.untrusted-signer');
});

test("rejects a forged receipt wrapped around another signer's signature", async () => {
  // The signature is made with an unrelated key, but the receipt embeds the
  // receiver's trusted certificate. The signature must fail before any trust
  // decision is made.
  const forged = unrelatedSelfSigned();
  const result = await check({ signer: forged, embeddedCertPem: pki.receiver.certPem });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'receipt.bad-signature');
});

test('rejects a trusted signer whose common name differs from the receiver', async () => {
  const result = await check({ signer: pki.sender, embeddedCertPem: pki.sender.certPem });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'receipt.wrong-signer');
});

test('rejects a response with a forged unsigned receipt prepended to a genuine one', () => {
  const otherRefs: ReceiptReference[] = [
    { uri: '#other-body', transform: ALGO_EXC_C14N, digest: 'ZZZZ' },
    { uri: 'cid:other@x', transform: SWA_TRANSFORM_SIGNATURE, digest: 'YYYY' },
  ];
  const genuine = buildSignedReceipt({ signer: pki.receiver, refToMessageId: 'other@test', references: otherRefs });
  const forged = buildSignedReceipt({ signer: unrelatedSelfSigned(), refToMessageId: MESSAGE_ID, references: refs });
  const forgedMessaging = /<eb:Messaging[\s\S]*?<\/eb:Messaging>/.exec(forged.xml)?.[0];
  assert.ok(forgedMessaging);
  const attacked = genuine.xml.replace('<env:Header>', `<env:Header>${forgedMessaging}`);
  // The ambiguity (two eb:Messaging) is rejected outright, so no trust decision is made.
  assert.equal(parseSignal(Buffer.from(attacked)), null);
});

test('rejects a signature that does not cover the signal message we read', async () => {
  const result = await check({ referenceTarget: 'body' });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'receipt.bad-signature');
});

test('rejects a response with a duplicate element id', async () => {
  const built = buildSignedReceipt({ signer: pki.receiver, refToMessageId: MESSAGE_ID, references: refs });
  const bst = /<wsse:BinarySecurityToken[\s\S]*?<\/wsse:BinarySecurityToken>/.exec(built.xml)?.[0];
  assert.ok(bst);
  const attacked = built.xml.replace('<wsse:Security>', `<wsse:Security>${bst}`);
  const signal = parseSignal(Buffer.from(attacked));
  assert.ok(signal); // still a single Messaging/SignalMessage...
  const result = await verifyReceipt({
    signal,
    as4MessageId: MESSAGE_ID,
    receiverCertificatePem: pki.receiver.certPem,
    signedReferences,
    validateCertificate,
    now: () => new Date(),
  });
  assert.equal(result.ok, false); // ...but the duplicate id makes the signer unresolvable
});

test('rejects a receipt from a revoked signer', async () => {
  const revokedValidator = testValidator(pki, {
    extraRevokedSerials: { [pki.intermediate.commonName]: [pki.revoked.serialHex] },
  });
  const result = await check({ signer: pki.revoked }, revokedValidator);
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'receipt.revoked-signer');
});

// Negative-algorithm and envelope-variant cases, ported from the shape of
// phase4's WrongSigningAlgorithm/WrongSigningDigestAlgorithm and TestReceipt11/12.
test('rejects a receipt with an unsupported SignatureMethod algorithm', async () => {
  const result = await check({ signatureMethodAlgorithm: 'http://www.randomcrypt.com/random' });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'receipt.bad-signature');
});

test('rejects a receipt with an unsupported DigestMethod algorithm', async () => {
  const result = await check({ digestMethodAlgorithm: 'http://www.randomdigest.com/randomdigest' });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'receipt.bad-signature');
});

test('verifies a receipt in a SOAP 1.1 envelope (prefix-agnostic)', async () => {
  const result = await check({ soapVersion: '1.1', soapPrefix: 'S11' });
  assert.equal(result.ok, true);
});

test('verifies a receipt whose InclusiveNamespaces prefix is uppercase (S12)', async () => {
  const result = await check({ soapPrefix: 'S12' });
  assert.equal(result.ok, true);
});
