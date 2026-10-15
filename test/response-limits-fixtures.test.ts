import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { defaultResponseLimits } from '../src/response-limits.js';
import { defaultLookupLimits } from '../src/lookup/limits.js';
import { XmlFault, parseStrictXml, type XmlLimits } from '../src/xml/strict.js';
import { parseSignal } from '../src/xml/signal.js';

/**
 * Item 6: each recorded fixture parses at limits equal to its own measured bytes
 * and node count, and fails one below — exercising the `ResponseLimits` mapping
 * (via `parseSignal`) and the `LookupLimits` ServiceGroup/metadata mapping.
 */
const fixtures = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'captures');
const smpFixtures = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'smp');

const GENEROUS: XmlLimits = {
  maxBytes: 1 << 30,
  maxDepth: 1 << 30,
  maxNodes: 1 << 30,
  maxAttributes: 1 << 30,
  maxTokenBytes: 1 << 30,
};

/** Count nodes exactly as `parseStrictXml`'s DOM walk does. */
function nodesOf(document: Document): number {
  let count = 0;
  const walk = (node: Node): void => {
    const children = node.childNodes;
    if (!children) return;
    for (let i = 0; i < children.length; i += 1) {
      count += 1;
      walk(children.item(i)!);
    }
  };
  walk(document);
  return count;
}

function isFault(reason: string): (error: unknown) => boolean {
  return (error) => error instanceof XmlFault && error.reason === reason;
}

test('receipt fixtures parse at their own byte and node limits and fail one below', () => {
  for (const name of ['helger.receipt.xml', 'oxalis-maventa.receipt.xml']) {
    const bytes = readFileSync(join(fixtures, name));
    const nodes = nodesOf(parseStrictXml(bytes, GENEROUS));

    const ok = parseSignal(bytes, { ...defaultResponseLimits, maxXmlBytes: bytes.length, maxNodes: nodes });
    assert.equal(ok.ok, true, `${name} should parse at its own limits`);

    const tooLarge = parseSignal(bytes, {
      ...defaultResponseLimits,
      maxXmlBytes: bytes.length - 1,
      maxNodes: nodes,
    });
    assert.equal(tooLarge.ok, false, `${name} bytes - 1`);
    if (!tooLarge.ok) assert.equal(tooLarge.reason, 'xml.too-large');

    const tooMany = parseSignal(bytes, {
      ...defaultResponseLimits,
      maxXmlBytes: bytes.length,
      maxNodes: nodes - 1,
    });
    assert.equal(tooMany.ok, false, `${name} nodes - 1`);
    if (!tooMany.ok) assert.equal(tooMany.reason, 'xml.too-many-nodes');
  }
});

test('SMP fixtures parse at their own byte and node limits and fail one below', () => {
  for (const name of ['elma.group.xml', 'elma.signed.xml', 'helger.group.xml', 'helger.signed.xml']) {
    const bytes = readFileSync(join(smpFixtures, name));
    const nodes = nodesOf(parseStrictXml(bytes, GENEROUS));
    const serviceGroup = name.includes('group');

    // The ServiceGroup / metadata mapping from `lookup/index.ts`.
    const xmlLimits = (byteLimit: number, nodeLimit: number): XmlLimits => ({
      maxBytes: Math.min(
        byteLimit,
        serviceGroup ? defaultLookupLimits.maxServiceGroupBytes : defaultLookupLimits.maxMetadataBytes,
      ),
      maxDepth: defaultLookupLimits.maxDepth,
      maxNodes: Math.min(
        nodeLimit,
        serviceGroup ? defaultLookupLimits.maxServiceGroupNodes : defaultLookupLimits.maxMetadataNodes,
      ),
      maxAttributes: defaultLookupLimits.maxAttributes,
      maxTokenBytes: defaultLookupLimits.maxTokenBytes,
    });

    assert.doesNotThrow(() => parseStrictXml(bytes, xmlLimits(bytes.length, nodes)), `${name} at its own limits`);
    assert.throws(
      () => parseStrictXml(bytes, xmlLimits(bytes.length - 1, nodes)),
      isFault('xml.too-large'),
      `${name} bytes - 1`,
    );
    assert.throws(
      () => parseStrictXml(bytes, xmlLimits(bytes.length, nodes - 1)),
      isFault('xml.too-many-nodes'),
      `${name} nodes - 1`,
    );
  }
});
