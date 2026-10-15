import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalSizeUpperBound, canonicalize } from '../src/xml/c14n.js';
import { parseStrictXml } from '../src/xml/strict.js';
import { defaultLookupLimits } from '../src/lookup/limits.js';
import { defaultResponseLimits } from '../src/response-limits.js';
import { inclusiveCanonicalSizeUpperBound, inclusiveCanonicalize } from '../src/lookup/smp-signature.js';

/**
 * Item 6, Phase 4: output size is not the only cost. Per child node the
 * inclusive canonicaliser copies the in-scope namespace sets and scans them
 * linearly, so work grows as nodes × namespaces-in-scope while the output stays
 * small. This is the worst shape at the default metadata limits: a deep chain
 * that declares a fresh namespace at every level, then the remaining node budget
 * filled with prefixed leaf children at the bottom (each prefixed leaf triggers
 * an in-scope scan). Both the inclusive (SMP) and exclusive (receipt) paths are
 * timed.
 */
function worstCaseMetadata(): string {
  const namespacesPerLevel = 63;
  const levels = 61;
  const leaves = 9_900;
  let xml = '<r';
  for (let n = 0; n < namespacesPerLevel; n += 1) xml += ` xmlns:q0_${n}="urn:${'u'.repeat(40)}:0:${n}"`;
  xml += '>';
  for (let level = 1; level <= levels; level += 1) {
    xml += `<l${level}`;
    for (let n = 0; n < namespacesPerLevel; n += 1)
      xml += ` xmlns:q${level}_${n}="urn:${'u'.repeat(40)}:${level}:${n}"`;
    xml += '>';
  }
  for (let i = 0; i < leaves; i += 1) xml += '<q61_0:e/>';
  for (let level = levels; level >= 1; level -= 1) xml += `</l${level}>`;
  return `${xml}</r>`;
}

test('the worst-case document stays under two seconds on both canonical paths', () => {
  const xml = Buffer.from(worstCaseMetadata(), 'utf8');
  assert.ok(xml.byteLength < defaultLookupLimits.maxMetadataBytes, `fixture is ${xml.byteLength} bytes`);

  let started = performance.now();
  const document = parseStrictXml(xml, {
    maxBytes: defaultLookupLimits.maxMetadataBytes,
    maxDepth: defaultLookupLimits.maxDepth,
    maxNodes: defaultLookupLimits.maxMetadataNodes,
    maxAttributes: defaultLookupLimits.maxAttributes,
    maxTokenBytes: defaultLookupLimits.maxTokenBytes,
  });
  const parseMs = performance.now() - started;
  assert.ok(parseMs < 2000, `parseStrictXml took ${parseMs.toFixed(0)} ms`);

  const root = document.documentElement;
  assert.ok(root);

  started = performance.now();
  const inclusiveBound = inclusiveCanonicalSizeUpperBound(root, []);
  const inclusiveBoundMs = performance.now() - started;
  assert.ok(inclusiveBoundMs < 2000, `the inclusive bound took ${inclusiveBoundMs.toFixed(0)} ms`);

  // The bound must be within its budget, or the timing below would be skipped.
  assert.ok(
    inclusiveBound <= defaultLookupLimits.maxCanonicalBytes,
    `inclusive bound ${inclusiveBound} exceeds the default canonical budget`,
  );
  started = performance.now();
  inclusiveCanonicalize(root);
  const inclusiveC14nMs = performance.now() - started;
  assert.ok(inclusiveC14nMs < 2000, `inclusive C14N took ${inclusiveC14nMs.toFixed(0)} ms`);

  started = performance.now();
  const exclusiveBound = canonicalSizeUpperBound(root);
  const exclusiveBoundMs = performance.now() - started;
  assert.ok(exclusiveBoundMs < 2000, `the exclusive bound took ${exclusiveBoundMs.toFixed(0)} ms`);
  assert.ok(
    exclusiveBound <= defaultResponseLimits.maxCanonicalBytes,
    `exclusive bound ${exclusiveBound} exceeds the default response canonical budget`,
  );

  started = performance.now();
  canonicalize(root);
  const exclusiveC14nMs = performance.now() - started;
  assert.ok(exclusiveC14nMs < 2000, `exclusive C14N took ${exclusiveC14nMs.toFixed(0)} ms`);
});
