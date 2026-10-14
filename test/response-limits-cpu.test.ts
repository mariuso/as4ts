import test from 'node:test';
import assert from 'node:assert/strict';
import { parseStrictXml } from '../src/xml/strict.js';
import { defaultLookupLimits } from '../src/lookup/limits.js';
import { inclusiveCanonicalSizeUpperBound, inclusiveCanonicalize } from '../src/lookup/smp-signature.js';

/**
 * Item 6, Phase 4: output size is not the only cost. Per child node the
 * inclusive canonicaliser copies the in-scope namespace sets, so work can grow
 * as nodes × namespaces while the output stays small. This exercises the worst
 * shape inside the default metadata limits (a deep chain that declares a fresh
 * namespace at every level), and asserts each step stays well under two seconds.
 */
function worstCaseMetadata(): string {
  const namespacesPerLevel = 63;
  const levels = 62;
  let open = '<r';
  for (let n = 0; n < namespacesPerLevel; n += 1) open += ` xmlns:p${n}="urn:${'u'.repeat(40)}:${n}"`;
  open += '>';
  let body = '';
  for (let level = 1; level < levels; level += 1) {
    let tag = `<l${level}`;
    for (let n = 0; n < namespacesPerLevel; n += 1)
      tag += ` xmlns:q${level}_${n}="urn:${'v'.repeat(40)}:${level}:${n}"`;
    body += `${tag}>`;
  }
  body += 'x'.repeat(3000);
  for (let level = levels - 1; level >= 1; level -= 1) body += `</l${level}>`;
  return `${open}${body}</r>`;
}

test('the worst-case document stays under two seconds at the default limits', () => {
  const xml = Buffer.from(worstCaseMetadata(), 'utf8');
  assert.ok(xml.byteLength < defaultLookupLimits.maxMetadataBytes);

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
  const bound = inclusiveCanonicalSizeUpperBound(root, []);
  const boundMs = performance.now() - started;
  assert.ok(boundMs < 2000, `the bound took ${boundMs.toFixed(0)} ms`);

  started = performance.now();
  if (bound <= defaultLookupLimits.maxCanonicalBytes) inclusiveCanonicalize(root);
  const canonicalMs = performance.now() - started;
  assert.ok(canonicalMs < 2000, `inclusive canonicalisation took ${canonicalMs.toFixed(0)} ms`);
});
