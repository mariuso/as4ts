# Inbound wire captures

Record captured inbound `UserMessage` requests here, one directory per capture,
following [docs/receiving-fixtures.md](../../../docs/receiving-fixtures.md):

```
test/fixtures/inbound/<name>/
  request.bin      # complete transfer-decoded request body, unedited
  metadata.json    # content type, sender/version, expectations
```

`test/receiving-captures.test.ts` parses every capture with the bounded MIME
parser; it skips while this directory holds no captures. Use synthetic documents
and test credentials only — never production material.
