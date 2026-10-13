import test from 'node:test';
import assert from 'node:assert/strict';
import {
  EBMS_NS,
  EBMS_ROLE_INITIATOR,
  EBMS_ROLE_RESPONDER,
  PEPPOL_PARTY_ID_TYPE,
  SOAP_ENV_NS,
} from '../src/constants.js';
import { peppolProfile } from '../src/profile.js';
import { AddressingFault, readUserMessage } from '../src/receive/user-message.js';
import { defaultXmlLimits, parseStrictXml } from '../src/receive/xml.js';

const SERVICE = { scheme: 'cenbii-procid-ubl', value: 'urn:fdc:peppol.eu:2017:poacc:billing:01:1.0' };
const ACTION = 'busdox-docid-qns::urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice##x::2.1';

function userMessage(overrides: { partyIdType?: string } = {}): string {
  const partyIdType = overrides.partyIdType ?? PEPPOL_PARTY_ID_TYPE;
  return (
    '<eb:UserMessage>' +
    '<eb:MessageInfo><eb:MessageId>m1</eb:MessageId><eb:Timestamp>2026-01-01T00:00:00Z</eb:Timestamp></eb:MessageInfo>' +
    '<eb:PartyInfo>' +
    `<eb:From><eb:PartyId type="${partyIdType}">0192:111111111</eb:PartyId><eb:Role>${EBMS_ROLE_INITIATOR}</eb:Role></eb:From>` +
    `<eb:To><eb:PartyId type="${partyIdType}">0192:222222222</eb:PartyId><eb:Role>${EBMS_ROLE_RESPONDER}</eb:Role></eb:To>` +
    '</eb:PartyInfo>' +
    `<eb:CollaborationInfo><eb:Service type="${SERVICE.scheme}">${SERVICE.value}</eb:Service><eb:Action>${ACTION}</eb:Action></eb:CollaborationInfo>` +
    '<eb:MessageProperties>' +
    `<eb:Property name="originalSender" type="iso6523-actorid-upis">0192:111111111</eb:Property>` +
    `<eb:Property name="finalRecipient" type="iso6523-actorid-upis">0192:222222222</eb:Property>` +
    '</eb:MessageProperties>' +
    '<eb:PayloadInfo><eb:PartInfo href="cid:att@x"/></eb:PayloadInfo>' +
    '</eb:UserMessage>'
  );
}

function envelope(messaging: string): Document {
  return parseStrictXml(
    Buffer.from(
      `<env:Envelope xmlns:env="${SOAP_ENV_NS}" xmlns:eb="${EBMS_NS}"><env:Header>${messaging}</env:Header><env:Body/></env:Envelope>`,
      'utf8',
    ),
    defaultXmlLimits,
  );
}

function rejectAddressing(document: Document): boolean {
  assert.throws(
    () => readUserMessage(document, peppolProfile),
    (err) => err instanceof AddressingFault && err.reason === 'addressing.unsupported',
  );
  return true;
}

test('reads a complete UserMessage into verified facts', () => {
  const facts = readUserMessage(envelope(`<eb:Messaging>${userMessage()}</eb:Messaging>`), peppolProfile);
  assert.equal(facts.messageId, 'm1');
  assert.equal(facts.fromPartyId, '0192:111111111');
  assert.equal(facts.toPartyId, '0192:222222222');
  assert.deepEqual(facts.service, SERVICE);
  assert.deepEqual(facts.originalSender, { scheme: 'iso6523-actorid-upis', value: '0192:111111111' });
  assert.deepEqual(facts.finalRecipient, { scheme: 'iso6523-actorid-upis', value: '0192:222222222' });
  assert.equal(facts.partHref, 'cid:att@x');
});

test('rejects more than one UserMessage by cardinality, not first match', () => {
  rejectAddressing(envelope(`<eb:Messaging>${userMessage()}${userMessage()}</eb:Messaging>`));
});

test('rejects more than one eb:Messaging', () => {
  rejectAddressing(
    envelope(`<eb:Messaging>${userMessage()}</eb:Messaging><eb:Messaging>${userMessage()}</eb:Messaging>`),
  );
});

test('rejects a PartyId whose type is not the profile type', () => {
  rejectAddressing(envelope(`<eb:Messaging>${userMessage({ partyIdType: 'urn:wrong' })}</eb:Messaging>`));
});

test('rejects duplicate Message properties', () => {
  const duplicated = userMessage().replace(
    '</eb:MessageProperties>',
    '<eb:Property name="originalSender" type="iso6523-actorid-upis">x</eb:Property></eb:MessageProperties>',
  );
  rejectAddressing(envelope(`<eb:Messaging>${duplicated}</eb:Messaging>`));
});
