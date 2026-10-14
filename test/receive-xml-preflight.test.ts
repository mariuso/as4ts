import test from 'node:test';
import assert from 'node:assert/strict';
import {
  CanonicalizationLimitExceeded,
  canonicalSizeUpperBound,
  canonicalize,
  canonicalizeWithin,
} from '../src/xml/c14n.js';
import { xmlHooks } from '../src/xml/hooks.js';
import { attachmentDigestBase64 } from '../src/receive/attachment.js';
import { XmlFault, defaultXmlLimits, parseStrictXml, validateXmlLimits, type XmlLimits } from '../src/receive/xml.js';

/**
 * Item 4 adversarial acceptance: the bounded XML preflight and the
 * canonicalisation budget, instrumented so an over-budget document is proven not
 * to reach the DOM parser or the canonicaliser ("the call failed" alone does not
 * prove it failed before allocation).
 */
const limits = (overrides: Partial<XmlLimits> = {}): XmlLimits => ({ ...defaultXmlLimits, ...overrides });
const reason = (r: string) => (err: unknown) => err instanceof XmlFault && err.reason === r;

let domCalls = 0;
let c14nCalls = 0;
xmlHooks.onDomParse = () => {
  domCalls += 1;
};
xmlHooks.onCanonicalize = () => {
  c14nCalls += 1;
};
function reset(): void {
  domCalls = 0;
  c14nCalls = 0;
}

// --- Early enforcement: the DOM parser is never invoked ----------------------

test('excessive input, depth, nodes, attributes and tokens never reach the DOM parser', () => {
  const doc = Buffer.from('<a b="1"><c>text</c></a>', 'utf8');
  const cases: ReadonlyArray<readonly [Partial<XmlLimits>, string]> = [
    [{ maxBytes: 4 }, 'xml.too-large'],
    [{ maxDepth: 1 }, 'xml.too-deep'],
    [{ maxNodes: 1 }, 'xml.too-many-nodes'],
    [{ maxAttributes: 0 }, 'xml.too-many-attributes'],
    [{ maxTokenBytes: 2 }, 'xml.token-too-large'],
  ];
  reset();
  for (const [overrides, expected] of cases) {
    assert.throws(() => parseStrictXml(doc, limits(overrides)), reason(expected), JSON.stringify(overrides));
  }
  assert.equal(domCalls, 0, 'the DOM parser must not run for any over-budget document');
});

test('a valid document reaches the DOM parser exactly once', () => {
  reset();
  parseStrictXml(Buffer.from('<a><b/></a>', 'utf8'));
  assert.equal(domCalls, 1);
});

// --- Node accounting matches the DOM representation --------------------------

test('every node kind counts toward the node budget, exactly', () => {
  const cases: ReadonlyArray<readonly [string, number]> = [
    ['<a/>', 1],
    ['<a>text</a>', 2],
    ['<a>x&amp;y</a>', 2], // an entity expands into a single text node
    ['<a><![CDATA[x]]></a>', 2],
    ['<a><!--c--></a>', 2],
    ['<?pi?><a/>', 2],
    ['<!--p--><a/>', 2],
    ['<r><a/><b/></r>', 3],
  ];
  for (const [xml, nodes] of cases) {
    assert.doesNotThrow(() => parseStrictXml(Buffer.from(xml), limits({ maxNodes: nodes })), xml);
    assert.throws(
      () => parseStrictXml(Buffer.from(xml), limits({ maxNodes: nodes - 1 })),
      reason('xml.too-many-nodes'),
      xml,
    );
  }
});

test('prolog and epilog nodes are counted, not only root content', () => {
  const xml = Buffer.from('<!--a--><r/><!--b-->', 'utf8'); // 3 nodes
  assert.doesNotThrow(() => parseStrictXml(xml, limits({ maxNodes: 3 })));
  assert.throws(() => parseStrictXml(xml, limits({ maxNodes: 2 })), reason('xml.too-many-nodes'));
});

test('namespace declarations count toward the attribute budget', () => {
  const xml = Buffer.from('<a xmlns:x="urn:u" x:b="1"/>', 'utf8'); // xmlns:x + x:b = 2
  assert.doesNotThrow(() => parseStrictXml(xml, limits({ maxAttributes: 2 })));
  assert.throws(() => parseStrictXml(xml, limits({ maxAttributes: 1 })), reason('xml.too-many-attributes'));
});

test('an unfinished lexical token is bounded before the parser sees EOF', () => {
  assert.throws(
    () => parseStrictXml(Buffer.from(`<a><!--${'x'.repeat(300)}`), limits({ maxTokenBytes: 128 })),
    reason('xml.token-too-large'),
  );
});

// --- Exact boundaries --------------------------------------------------------

test('byte, depth, node and attribute caps are exact, one budget at a time', () => {
  const xml = '<a b="1"><c>t</c></a>'; // a, c, text = 3 nodes; depth 2; 1 attribute
  const bytes = Buffer.from(xml, 'utf8');
  assert.doesNotThrow(() => parseStrictXml(bytes, limits({ maxBytes: bytes.length })));
  assert.throws(() => parseStrictXml(bytes, limits({ maxBytes: bytes.length - 1 })), reason('xml.too-large'));

  assert.doesNotThrow(() => parseStrictXml(bytes, limits({ maxDepth: 2 })));
  assert.throws(() => parseStrictXml(bytes, limits({ maxDepth: 1 })), reason('xml.too-deep'));

  assert.doesNotThrow(() => parseStrictXml(bytes, limits({ maxNodes: 3 })));
  assert.throws(() => parseStrictXml(bytes, limits({ maxNodes: 2 })), reason('xml.too-many-nodes'));

  assert.doesNotThrow(() => parseStrictXml(bytes, limits({ maxAttributes: 1 })));
  assert.throws(() => parseStrictXml(bytes, limits({ maxAttributes: 0 })), reason('xml.too-many-attributes'));

  const token = Buffer.from(`<a>${'x'.repeat(64)}</a>`, 'utf8');
  assert.doesNotThrow(() => parseStrictXml(token, limits({ maxTokenBytes: 64 })));
  assert.throws(() => parseStrictXml(token, limits({ maxTokenBytes: 63 })), reason('xml.token-too-large'));
});

// --- DTD rejection is lexical, not textual -----------------------------------

test('a real DTD is rejected while the same text in a comment or CDATA is accepted', () => {
  assert.throws(() => parseStrictXml(Buffer.from('<!DOCTYPE a []><a/>', 'utf8')), reason('xml.doctype'));
  assert.doesNotThrow(() => parseStrictXml(Buffer.from('<a><!-- <!DOCTYPE x> --></a>', 'utf8')));
  assert.doesNotThrow(() => parseStrictXml(Buffer.from('<a><![CDATA[<!DOCTYPE x>]]></a>', 'utf8')));
});

// --- Encoding and XML-version policy -----------------------------------------

test('the shared encoding policy is applied to the DOM path', () => {
  const rejects = [
    Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('<?xml version="1.0" encoding="utf-16"?><a/>')]),
    Buffer.from('<?xml version="1.0" encoding="us-ascii"?><a>\u00e9</a>', 'utf8'),
    Buffer.from('<?xml version="1.1"?><a/>', 'utf8'),
    Buffer.from(`<?xml version="1.0"${' '.repeat(300)}encoding="utf-16"?><a/>`, 'utf8'),
    Buffer.from([0x3c, 0x61, 0x3e, 0xff, 0x3c, 0x2f, 0x61, 0x3e]),
    Buffer.from([0xff, 0xfe, 0x3c, 0x61, 0x2f, 0x3e]), // UTF-16 byte order mark
  ];
  for (const bytes of rejects) {
    assert.throws(() => parseStrictXml(bytes), reason('xml.malformed'), bytes.toString('latin1').slice(0, 48));
  }
  // A processing instruction whose target begins with `xml` is not the declaration.
  assert.doesNotThrow(() => parseStrictXml(Buffer.from('<?xml-stylesheet encoding="utf-16"?><a/>', 'utf8')));
});

// --- Configuration validation ------------------------------------------------

test('every XML limit must be a finite, non-negative safe integer', () => {
  assert.doesNotThrow(() => validateXmlLimits(defaultXmlLimits));
  for (const bad of [Number.NaN, -1, 1.5, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(
      () => parseStrictXml(Buffer.from('<a/>'), limits({ maxNodes: bad })),
      reason('limits.invalid'),
      `${bad}`,
    );
  }
  // 0 is legitimate: it allows nothing.
  assert.throws(() => parseStrictXml(Buffer.from('<a/>'), limits({ maxBytes: 0 })), reason('xml.too-large'));
});

// --- Canonicalisation expansion budget ---------------------------------------

const LONG_NS = `urn:example:${'n'.repeat(200)}`;
function expansionDocument(): Buffer {
  const siblings = '<p:item>1</p:item>'.repeat(1000);
  return Buffer.from(`<?xml version="1.0"?><r xmlns:p="${LONG_NS}">${siblings}</r>`, 'utf8');
}

test('the canonicalisation expansion bound captures repeated namespace declarations', () => {
  const document = parseStrictXml(expansionDocument());
  const bound = canonicalSizeUpperBound(document);
  const actual = canonicalize(document).length;
  assert.ok(bound >= actual, `bound ${bound} must not under-estimate the canonical size ${actual}`);
  assert.ok(actual > 200_000, `expected heavy namespace expansion, got ${actual} canonical bytes`);
});

test('an expansion-amplifying document is rejected before the canonicaliser runs', () => {
  const document = parseStrictXml(expansionDocument());
  const bound = canonicalSizeUpperBound(document);
  reset();
  assert.throws(
    () => canonicalizeWithin(document, 1000),
    (err) => err instanceof CanonicalizationLimitExceeded,
  );
  assert.equal(c14nCalls, 0, 'the canonicaliser must not run when the bound exceeds the budget');
  assert.doesNotThrow(() => canonicalizeWithin(document, bound));
  assert.equal(c14nCalls, 1);
});

test('the inclusive-prefix path is bounded too', () => {
  const document = parseStrictXml(expansionDocument());
  const bound = canonicalSizeUpperBound(document);
  reset();
  assert.throws(
    () => canonicalizeWithin(document, 1000, ['p']),
    (err) => err instanceof CanonicalizationLimitExceeded,
  );
  assert.equal(c14nCalls, 0);
  assert.doesNotThrow(() => canonicalizeWithin(document, bound, ['p']));
  assert.equal(c14nCalls, 1);
});

test('an XML attachment over the canonicalisation budget fails before digesting', () => {
  reset();
  assert.throws(
    () => attachmentDigestBase64('application/xml', expansionDocument(), undefined, 1000),
    (err) => err instanceof CanonicalizationLimitExceeded,
  );
  assert.equal(c14nCalls, 0, 'no canonical string may be allocated over budget');
  assert.equal(domCalls, 1, 'the DOM itself is still built within the DOM budget');
});

// --- Compatibility: digests are unchanged ------------------------------------

test('equivalent supported encodings retain matching digests', () => {
  const utf8 = Buffer.from('<?xml version="1.0" encoding="UTF-8"?><a>caf\u00e9</a>', 'utf8');
  const latin1 = Buffer.from('<?xml version="1.0" encoding="ISO-8859-1"?><a>caf\u00e9</a>', 'latin1');
  assert.equal(attachmentDigestBase64('application/xml', utf8), attachmentDigestBase64('application/xml', latin1));
  const ascii = Buffer.from('<?xml version="1.0" encoding="us-ascii"?><a>cafe</a>', 'utf8');
  assert.equal(
    attachmentDigestBase64('application/xml', Buffer.from('<a>cafe</a>', 'utf8')),
    attachmentDigestBase64('application/xml', ascii),
  );
});
