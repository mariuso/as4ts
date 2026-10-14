import test from 'node:test';
import assert from 'node:assert/strict';
import { parseStrictXml } from '../src/xml/strict.js';
import {
  findAncestorNsForElement,
  inclusiveCanonicalSizeUpperBound,
  inclusiveCanonicalize,
} from '../src/lookup/smp-signature.js';

/**
 * Soundness fuzz for the inclusive canonical-size bound: for every generated
 * document, `bound >= Buffer.byteLength(inclusiveCanonicalize(node), 'utf8')`,
 * both for the whole root and for a nested `SignedInfo`-like subtree that
 * inherits namespaces and `xml:*` attributes from its ancestors.
 *
 * The generator deliberately exercises the cases the bound must model: the
 * characters C14N escapes, CDATA/comments/PIs, empty elements, prefixed and
 * unprefixed names, default-namespace changes and `xmlns=""` undeclarations,
 * prefix rebinding deeper in the tree, multi-byte UTF-8, and ancestor
 * `xml:lang` / `xml:space`.
 */
function xorshift(seed: number): () => number {
  let state = seed >>> 0 || 1;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };
}

const PLAIN_NAMES = ['a', 'b', 'c', 'item', 'elem', '\u540d', '\u00e9l\u00e9ment'];
const PREFIXES = ['p', 'q', 'r'];
const URI = ['urn:a', 'urn:bb', 'urn:ccc', 'urn:\u00e9'];
const TEXT = ['', 'x', '&amp;', '&lt;&gt;', '&quot;tab&#x9;nl&#xA;cr&#xD;', '\u00e9\u540d', '  spaced  '];
const ATTR_VALUE = ['', 'v', '&amp;&lt;&gt;&quot;', '\u540d', 'a&#x9;b'];

function pick<T>(random: () => number, values: readonly T[]): T {
  return values[random() % values.length]!;
}

function randomElement(random: () => number, depth: number, counter: { n: number }): string {
  const prefixed = random() % 2 === 0;
  const prefix = pick(random, PREFIXES);
  const name = prefixed ? `${prefix}:${pick(random, PLAIN_NAMES)}` : pick(random, PLAIN_NAMES);
  let open = `<${name}`;
  const used = new Set<string>();
  const attribute = (attributeName: string, value: string): string => {
    if (used.has(attributeName)) return '';
    used.add(attributeName);
    return ` ${attributeName}="${value}"`;
  };

  // Default-namespace changes and undeclarations.
  if (random() % 3 === 0) open += attribute('xmlns', pick(random, URI));
  if (random() % 4 === 0) open += attribute('xmlns', '');

  // Attributes, some prefixed (so an attribute visibly uses a namespace).
  const attributes: Array<{ name: string; value: string }> = [];
  const attributeCount = random() % 3;
  for (let i = 0; i < attributeCount; i += 1) {
    const attributeName = random() % 2 === 0 ? `a${i}` : `${pick(random, PREFIXES)}:a${i}`;
    attributes.push({ name: attributeName, value: pick(random, ATTR_VALUE) });
  }
  // Declare every prefix the element or an attribute uses, so the document is
  // well-formed and the strict parser accepts it.
  const prefixesToDeclare = new Set<string>();
  if (prefixed) prefixesToDeclare.add(prefix);
  for (const entry of attributes) {
    const colon = entry.name.indexOf(':');
    if (colon > 0) prefixesToDeclare.add(entry.name.slice(0, colon));
  }
  if (random() % 4 === 0) prefixesToDeclare.add(pick(random, PREFIXES));
  for (const usedPrefix of prefixesToDeclare) open += attribute(`xmlns:${usedPrefix}`, pick(random, URI));
  for (const entry of attributes) open += attribute(entry.name, entry.value);
  open += '>';

  counter.n += 1;
  if (depth >= 4 || random() % 4 === 0) return `${open}</${name}>`;

  let inner = '';
  const childCount = random() % 4;
  for (let i = 0; i < childCount; i += 1) {
    const roll = random() % 8;
    if (roll === 0) inner += `<![CDATA[${pick(random, TEXT)}]]>`;
    else if (roll === 1) inner += `<!--${pick(random, TEXT)}-->`;
    else if (roll === 2) inner += `<?pi ${pick(random, TEXT)}?>`;
    else if (roll === 3) inner += `<empty${counter.n++}/>`;
    else if (roll === 4) inner += pick(random, TEXT);
    else inner += randomElement(random, depth + 1, counter);
  }
  return `${open}${inner}</${name}>`;
}

function randomDocument(random: () => number): string {
  const counter = { n: 0 };
  const root = randomElement(random, 0, counter);
  // A root carrying ancestor xml:lang / xml:space, and sometimes a nested
  // SignedInfo-like wrapper so a subtree inherits namespaces.
  const withXml = root.replace(/^<(\w[\w\u00c0-\uffff]*)/, `<$1 xml:lang="en" xml:space="preserve"`);
  return withXml;
}

test('the inclusive canonical-size bound is sound across the fuzz corpus', () => {
  const random = xorshift(0x5eed_1234);
  const target = 24_000;
  let checked = 0;
  let attempts = 0;
  let maxRatio = 0;
  let maxRatioDoc = '';
  while (checked < target && attempts < target * 20) {
    attempts += 1;
    const xml = randomDocument(random);
    let document: Document;
    try {
      document = parseStrictXml(Buffer.from(xml, 'utf8'), {
        maxBytes: 1024 * 1024,
        maxDepth: 64,
        maxNodes: 10_000,
        maxAttributes: 64,
        maxTokenBytes: 64 * 1024,
      });
    } catch {
      continue;
    }
    const root = document.documentElement;
    if (!root) continue;

    const rootBound = inclusiveCanonicalSizeUpperBound(root, []);
    const rootActual = Buffer.byteLength(inclusiveCanonicalize(root), 'utf8');
    assert.ok(rootBound >= rootActual, `root bound ${rootBound} < actual ${rootActual} for ${xml}`);
    checked += 1;
    const ratio = rootActual === 0 ? 1 : rootBound / rootActual;
    if (ratio > maxRatio) {
      maxRatio = ratio;
      maxRatioDoc = xml;
    }

    // A nested leaf-or-subtree canonicalised on its own, with ancestor namespaces.
    const all = root.getElementsByTagName('*');
    if (all.length > 1) {
      const inner = all.item(all.length - 1) as Element;
      const ancestors = findAncestorNsForElement(inner);
      const innerBound = inclusiveCanonicalSizeUpperBound(inner, ancestors);
      const innerActual = Buffer.byteLength(inclusiveCanonicalize(inner), 'utf8');
      assert.ok(innerBound >= innerActual, `subtree bound ${innerBound} < actual ${innerActual} for ${xml}`);
    }
  }
  assert.equal(checked, target, `only ${checked} of ${target} documents parsed in ${attempts} attempts`);
  assert.ok(maxRatio < 200, `bound over-estimates by ${maxRatio.toFixed(1)}x for ${maxRatioDoc}`);
});
