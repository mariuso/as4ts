import test from 'node:test';
import assert from 'node:assert/strict';
import { XmlFault, defaultXmlLimits, parseStrictXml } from '../src/receive/xml.js';

const reason = (r: string) => (err: unknown) => err instanceof XmlFault && err.reason === r;

test('accepts a well-formed document and returns the DOM', () => {
  const doc = parseStrictXml(Buffer.from('<a><b/></a>', 'utf8'));
  assert.equal(doc.documentElement.nodeName, 'a');
  // Text nodes have no childNodes; traversal must not assume one.
  assert.equal(parseStrictXml(Buffer.from('<a>text</a>', 'utf8')).documentElement.textContent, 'text');
});

test('rejects malformed XML', () => {
  assert.throws(() => parseStrictXml(Buffer.from('<a>', 'utf8')), reason('xml.malformed'));
});

test('rejects a DOCTYPE', () => {
  assert.throws(() => parseStrictXml(Buffer.from('<!DOCTYPE a []><a/>', 'utf8')), reason('xml.doctype'));
});

test('enforces a byte cap before parsing', () => {
  assert.throws(
    () => parseStrictXml(Buffer.from('<a>hello</a>', 'utf8'), { ...defaultXmlLimits, maxBytes: 4 }),
    reason('xml.too-large'),
  );
});

test('counts every node type, not only elements', () => {
  // <a>text</a> is two nodes: the element and its text child.
  assert.throws(
    () => parseStrictXml(Buffer.from('<a>text</a>', 'utf8'), { ...defaultXmlLimits, maxNodes: 1 }),
    reason('xml.too-many-nodes'),
  );
});

test('enforces a depth budget', () => {
  const deep = '<a>'.repeat(70) + '</a>'.repeat(70);
  assert.throws(
    () => parseStrictXml(Buffer.from(deep, 'utf8'), { ...defaultXmlLimits, maxDepth: 8 }),
    reason('xml.too-deep'),
  );
});

test('rejects invalid UTF-8 rather than replacing it', () => {
  assert.throws(
    () => parseStrictXml(Buffer.from([0x3c, 0x61, 0x3e, 0xff, 0x3c, 0x2f, 0x61, 0x3e])),
    reason('xml.malformed'),
  );
});

test('rejects an unsupported declared encoding', () => {
  const bytes = Buffer.from('<?xml version="1.0" encoding="UTF-16"?><a/>', 'utf8');
  assert.throws(() => parseStrictXml(bytes), reason('xml.malformed'));
});
