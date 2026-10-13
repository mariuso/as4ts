import test from 'node:test';
import assert from 'node:assert/strict';
import { checkSbdh, documentTypeFromAction, readSbdh } from '../src/receive/sbdh.js';
import { defaultXmlLimits, parseStrictXml } from '../src/receive/xml.js';

const SBDH_NS = 'http://www.unece.org/ebusiness/2010/MDA/StandardBusinessDocumentHeader';
const SENDER = { scheme: 'iso6523-actorid-upis', value: '0192:111111111' };
const RECEIVER = { scheme: 'iso6523-actorid-upis', value: '0192:222222222' };
const PROCESS = { scheme: 'cenbii-procid-ubl', value: 'urn:fdc:peppol.eu:2017:poacc:billing:01:1.0' };
const DOCUMENT = {
  scheme: 'busdox-docid-qns',
  value: 'urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice##urn:cen.eu:en16931:2017::2.1',
};
const expected = {
  originalSender: SENDER,
  finalRecipient: RECEIVER,
  process: PROCESS,
  documentType: DOCUMENT,
};

function check(xml: string) {
  return checkSbdh(Buffer.from(xml, 'utf8'), defaultXmlLimits, expected);
}

/** A complete SBDH; `options` lets a case omit a scheme or a field. */
function header(options: { partyScheme?: boolean; scopeScheme?: boolean; receiver?: boolean } = {}): string {
  const authority = options.partyScheme === false ? '' : ` Authority="${SENDER.scheme}"`;
  const receiverAuthority = options.partyScheme === false ? '' : ` Authority="${RECEIVER.scheme}"`;
  const processScheme = options.scopeScheme === false ? '' : `<Identifier>${PROCESS.scheme}</Identifier>`;
  const documentScheme = options.scopeScheme === false ? '' : `<Identifier>${DOCUMENT.scheme}</Identifier>`;
  return (
    `<StandardBusinessDocument xmlns="${SBDH_NS}">` +
    '<StandardBusinessDocumentHeader><HeaderVersion>1.0</HeaderVersion>' +
    `<Sender><Identifier${authority}>${SENDER.value}</Identifier></Sender>` +
    (options.receiver === false
      ? ''
      : `<Receiver><Identifier${receiverAuthority}>${RECEIVER.value}</Identifier></Receiver>`) +
    '<DocumentIdentification><Standard>urn:oasis</Standard><Type>Invoice</Type></DocumentIdentification>' +
    '<BusinessScope>' +
    `<Scope><Type>PROCESSID</Type><InstanceIdentifier>${PROCESS.value}</InstanceIdentifier>${processScheme}</Scope>` +
    `<Scope><Type>DOCUMENTID</Type><InstanceIdentifier>${DOCUMENT.value}</InstanceIdentifier>${documentScheme}</Scope>` +
    '</BusinessScope>' +
    '</StandardBusinessDocumentHeader>' +
    '</StandardBusinessDocument>'
  );
}

test('a complete SBDH is consistent', () => {
  assert.deepEqual(check(header()), { status: 'consistent' });
});

test('omitted schemes fall back to the specified defaults', () => {
  assert.deepEqual(check(header({ partyScheme: false, scopeScheme: false })), { status: 'consistent' });
});

test('a missing required field is not consistent', () => {
  const result = check(header({ receiver: false }));
  assert.equal(result.status, 'inconsistent');
  if (result.status === 'inconsistent') {
    assert.ok(result.mismatches.some((mismatch) => mismatch.includes('Receiver')));
  }
});

test('an empty header is not consistent', () => {
  const empty = `<StandardBusinessDocument xmlns="${SBDH_NS}"><StandardBusinessDocumentHeader/></StandardBusinessDocument>`;
  const result = check(empty);
  assert.equal(result.status, 'inconsistent');
});

test('a mismatched value is inconsistent', () => {
  const result = check(header().replace(SENDER.value, '0192:999999999'));
  assert.equal(result.status, 'inconsistent');
  if (result.status === 'inconsistent') {
    assert.ok(result.mismatches.some((mismatch) => mismatch.includes('originalSender')));
  }
});

test('a header in the wrong namespace is missing, not consistent', () => {
  const wrong = header().replace(SBDH_NS, 'urn:unrelated:namespace');
  assert.deepEqual(check(wrong), { status: 'missing' });
});

test('a header nested inside an unrelated document is missing, not consistent', () => {
  const nested = `<Root xmlns="urn:unrelated">${header()}</Root>`;
  assert.deepEqual(check(nested), { status: 'missing' });
});

test('duplicate identifiers are malformed', () => {
  const duplicated =
    `<StandardBusinessDocument xmlns="${SBDH_NS}"><StandardBusinessDocumentHeader>` +
    `<Sender><Identifier>${SENDER.value}</Identifier><Identifier>x</Identifier></Sender>` +
    '</StandardBusinessDocumentHeader></StandardBusinessDocument>';
  const result = check(duplicated);
  assert.equal(result.status, 'malformed');
});

test('a header nested under the wrong element is missing', () => {
  const nestedHeader = `<StandardBusinessDocument xmlns="${SBDH_NS}"><Wrapper><StandardBusinessDocumentHeader/></Wrapper></StandardBusinessDocument>`;
  assert.deepEqual(check(nestedHeader), { status: 'missing' });
});

test('readSbdh requires the SBDH root and a direct header child', () => {
  assert.equal(readSbdh(parseStrictXml(Buffer.from(header(), 'utf8'), defaultXmlLimits))?.sender?.value, SENDER.value);
  const wrongPosition = parseStrictXml(
    Buffer.from(
      `<StandardBusinessDocument xmlns="${SBDH_NS}"><Wrapper><StandardBusinessDocumentHeader/></Wrapper></StandardBusinessDocument>`,
      'utf8',
    ),
    defaultXmlLimits,
  );
  assert.equal(readSbdh(wrongPosition), null);
});

test('documentTypeFromAction splits the eb:Action scheme and value', () => {
  assert.deepEqual(documentTypeFromAction(`${DOCUMENT.scheme}::${DOCUMENT.value}`), DOCUMENT);
  assert.equal(documentTypeFromAction('no-separator'), null);
});
