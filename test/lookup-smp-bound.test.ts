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
 * for the whole root (with the direct-child envelope signature excluded, exactly
 * what `verifySmpSignature` digests) and for a randomly chosen subtree with its
 * inherited namespaces and `xml:*` attributes.
 *
 * The generator deliberately exercises: the characters C14N escapes,
 * CDATA/comments/PIs, empty elements, prefixed and unprefixed names,
 * default-namespace changes and `xmlns=""` undeclarations, prefix rebinding
 * deeper in the tree, multi-byte UTF-8, nested `ds:Signature` elements (which
 * must still be counted — only the direct child is skipped), and ancestor
 * `xml:lang` / `xml:space` / `xml:base` / `xml:id` / `xml:foo`.
 *
 * The ratio assertion is justified from the escape factors: an attribute value
 * can grow to at most 6× (`"` → `&quot;`, `&`/`\t`/`\n`/`\r` → 5-byte
 * references), text to 5×, and `<a/>` gains one `</a>`. 12× leaves margin for
 * the apex's inherited namespace declarations.
 */
const MAX_RATIO = 12;

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
const ATTR_VALUE = ['', 'v', '&amp;&lt;&gt;&quot;', '\u540d', 'a&#x9;b', '&quot;'];
const XML_ATTRS = ['xml:lang', 'xml:space', 'xml:base', 'xml:id', 'xml:foo'];
const DS_NS = 'http://www.w3.org/2000/09/xmldsig#';

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

  if (random() % 3 === 0) open += attribute('xmlns', pick(random, URI));
  if (random() % 4 === 0) open += attribute('xmlns', '');

  const attributes: Array<{ name: string; value: string }> = [];
  const attributeCount = random() % 3;
  for (let i = 0; i < attributeCount; i += 1) {
    const attributeName = random() % 2 === 0 ? `a${i}` : `${pick(random, PREFIXES)}:a${i}`;
    attributes.push({ name: attributeName, value: pick(random, ATTR_VALUE) });
  }
  if (random() % 3 === 0) attributes.push({ name: pick(random, XML_ATTRS), value: pick(random, ATTR_VALUE) });
  if (random() % 4 === 0) attributes.push({ name: 'ds:sig', value: 'v' });

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
  if (depth >= 4 || random() % 5 === 0) return `${open}</${name}>`;

  let inner = '';
  const childCount = random() % 4;
  for (let i = 0; i < childCount; i += 1) {
    const roll = random() % 10;
    if (roll === 0) inner += `<![CDATA[${pick(random, TEXT)}]]>`;
    else if (roll === 1) inner += `<!--${pick(random, TEXT)}-->`;
    else if (roll === 2) inner += `<?pi ${pick(random, TEXT)}?>`;
    else if (roll === 3) inner += `<empty${counter.n++}/>`;
    else if (roll === 4) inner += pick(random, TEXT);
    else if (roll === 5) {
      // A nested signature: the digest covers it, so the bound must count it.
      if (!used.has('xmlns:ds')) open = `${open.slice(0, -1)} xmlns:ds="${DS_NS}">`;
      inner += `<ds:Signature><ds:x>${pick(random, TEXT)}</ds:x></ds:Signature>`;
    } else inner += randomElement(random, depth + 1, counter);
  }
  return `${open}${inner}</${name}>`;
}

function randomDocument(random: () => number): string {
  const counter = { n: 0 };
  const root = randomElement(random, 0, counter);
  // Always a root with xml:* attributes and a direct-child envelope signature,
  // so the bound's `skip` (direct children only) is exercised precisely.
  let head = root;
  if (!/^<[^>]*\bxml:/.test(head))
    head = head.replace(/^<(\w[\w\u00c0-\uffff]*)/, `<$1 xml:lang="en" xml:base="urn:base"`);
  if (!head.includes('xmlns:ds=')) head = head.replace(/^<(\w[\w\u00c0-\uffff]*)/, `<$1 xmlns:ds="${DS_NS}"`);
  return head.replace(/>/, `><ds:Signature><ds:y/></ds:Signature>`);
}

function cloneWithoutDirectSignature(document: Document): Element {
  const clone = document.cloneNode(true) as Document;
  const root = clone.documentElement!;
  const children = Array.from(root.childNodes);
  for (const child of children) {
    if (
      child.nodeType === 1 &&
      (child as Element).namespaceURI === DS_NS &&
      (child as Element).localName === 'Signature'
    ) {
      root.removeChild(child);
    }
  }
  return root;
}

const isSignature = (child: Node): boolean =>
  child.nodeType === 1 && (child as Element).namespaceURI === DS_NS && (child as Element).localName === 'Signature';

test('the inclusive canonical-size bound is sound across the fuzz corpus', () => {
  const random = xorshift(0x5eed_1234);
  const target = 24_000;
  let checked = 0;
  let attempts = 0;
  let maxRatio = 0;
  let maxRatioDoc = '';
  const ratio = (bound: number, actual: number): void => {
    const value = actual === 0 ? 1 : bound / actual;
    if (value > maxRatio) maxRatio = value;
  };
  const record = (document: Document, xml: string): void => {
    const root = document.documentElement;
    if (!root) return;
    // The document digest: the root with only its direct-child signature removed.
    const digestBound = inclusiveCanonicalSizeUpperBound(root, [], isSignature);
    const digestActual = Buffer.byteLength(inclusiveCanonicalize(cloneWithoutDirectSignature(document)), 'utf8');
    assert.ok(digestBound >= digestActual, `digest bound ${digestBound} < actual ${digestActual} for ${xml}`);
    ratio(digestBound, digestActual);

    // A randomly chosen subtree, weighted towards non-leaves, with ancestors.
    const all = Array.from(root.getElementsByTagName('*'));
    if (all.length > 1) {
      const candidates = all.filter((element) => element.childNodes.length > 0 || all.length < 4);
      const inner = (candidates.length > 0 ? candidates : all)[
        random() % (candidates.length > 0 ? candidates.length : all.length)
      ] as Element;
      const innerBound = inclusiveCanonicalSizeUpperBound(inner, findAncestorNsForElement(inner));
      const innerActual = Buffer.byteLength(inclusiveCanonicalize(inner), 'utf8');
      assert.ok(innerBound >= innerActual, `subtree bound ${innerBound} < actual ${innerActual} for ${xml}`);
      ratio(innerBound, innerActual);
    }
    checked += 1;
    if (maxRatio >= MAX_RATIO) maxRatioDoc = xml;
  };

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
    record(document, xml);
  }
  assert.equal(checked, target, `only ${checked} of ${target} documents parsed in ${attempts} attempts`);
  assert.ok(
    maxRatio < MAX_RATIO,
    `bound over-estimates by ${maxRatio.toFixed(1)}x (limit ${MAX_RATIO}) for ${maxRatioDoc}`,
  );
});

// --- Fixed regressions for the two reproduced under-counts -------------------

test('a nested ds:Signature is charged; only the direct child is skipped', () => {
  const xml =
    `<r xmlns:ds="${DS_NS}"><ds:Signature><x/></ds:Signature>` +
    `<a><ds:Signature><t>${'&amp;'.repeat(10_000)}</t>${'<t/>'.repeat(20)}</ds:Signature></a></r>`;
  const document = parseStrictXml(Buffer.from(xml, 'utf8'), {
    maxBytes: 1024 * 1024,
    maxDepth: 64,
    maxNodes: 10_000,
    maxAttributes: 64,
    maxTokenBytes: 64 * 1024,
  });
  const bound = inclusiveCanonicalSizeUpperBound(document.documentElement!, [], isSignature);
  const actual = Buffer.byteLength(inclusiveCanonicalize(cloneWithoutDirectSignature(document)), 'utf8');
  assert.ok(bound >= actual, `bound ${bound} < actual ${actual}`);
});

test('every ancestor xml:* attribute is charged, not only xml:lang / xml:space', () => {
  const xml = `<r xml:base="${'u'.repeat(5000)}" xml:id="i ${'v'.repeat(5000)}"><s/></r>`;
  const document = parseStrictXml(Buffer.from(xml, 'utf8'), {
    maxBytes: 1024 * 1024,
    maxDepth: 64,
    maxNodes: 10_000,
    maxAttributes: 64,
    maxTokenBytes: 64 * 1024,
  });
  const inner = document.documentElement!.firstChild as Element;
  const bound = inclusiveCanonicalSizeUpperBound(inner, findAncestorNsForElement(inner));
  const actual = Buffer.byteLength(inclusiveCanonicalize(inner), 'utf8');
  assert.ok(bound >= actual, `bound ${bound} < actual ${actual}`);
});
