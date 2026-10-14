# Receiving measurements: the 500 MiB contract

Measured evidence for the contract in
[receiving-limits.md](receiving-limits.md#a-500-mib-document-contract). Regenerate
with `npm run measure:receive` (see that section for the env variables). Raw JSON
is written to `measurements/` (gitignored).

## Environment

|                     | macOS run                              | Linux run                                |
| ------------------- | -------------------------------------- | ---------------------------------------- |
| Node                | v22.13.1                               | v22.23.3                                 |
| Platform            | macOS 26.0 (25A5338b), Apple M3, arm64 | Linux (Docker `node:22-bookworm`), arm64 |
| RAM                 | 16 GiB                                 | 5.76 GiB VM limit, 4 vCPU                |
| Disk                | APFS, ~14 GiB free                     | container overlay                        |
| Container           | none                                   | Docker Desktop VM on the same host       |
| `maxRSS` unit check | +261 MiB for a 256 MiB `Buffer`        | +259 MiB for a 256 MiB `Buffer`          |

Both unit checks confirm `process.resourceUsage().maxRSS` is in kilobytes.

## Fixtures

The request body is a real signed `multipart/related` message whose payload is a
valid SBDH document followed by streamed invoice content. The content is
deterministic, so the two platforms produced byte-identical fixtures. `xml` is
compressible (realistic invoice lines); `base64` is barely compressible (base64 of
random bytes, like an embedded PDF).

| Fixture    | Recovered bytes |  Wire bytes | Ratio |
| ---------- | --------------: | ----------: | ----: |
| xml-64     |      67,108,764 |   7,022,681 | 9.56× |
| xml-256    |     268,435,356 |  27,993,926 | 9.59× |
| xml-512    |     536,870,711 |  55,796,633 | 9.62× |
| base64-64  |      67,098,808 |  50,536,136 | 1.33× |
| base64-256 |     268,398,280 | 202,115,634 | 1.33× |
| base64-512 |     536,859,192 | 404,268,291 | 1.33× |

## Positive runs (override limits, concurrency 4)

Every run: all four concurrent opens returned `ok: true` with
`sbdh.status === 'consistent'`, the payload byte length and SHA-256 matched the
generator, the spool directory was empty after `dispose()`, and no `as4-*` entry
was left in `os.tmpdir()`. `MiB/s` is recovered bytes across all four receives
divided by wall time.

### macOS

| kind   | MiB | maxRSS MiB | spool peak MiB | wall s | MiB/s |
| ------ | --: | ---------: | -------------: | -----: | ----: |
| xml    |  64 |        223 |            310 |    9.5 |    27 |
| xml    | 256 |        269 |           1238 |   37.6 |    27 |
| xml    | 512 |        421 |           2474 |   75.4 |    27 |
| base64 |  64 |        372 |            641 |    4.4 |    58 |
| base64 | 256 |        682 |           2566 |   21.5 |    48 |
| base64 | 512 |       1298 |           5132 |   45.0 |    46 |

### Linux (Docker `node:22-bookworm`, 5.76 GiB, 4 vCPU)

| kind   | MiB | maxRSS MiB | spool peak MiB | wall s | MiB/s |
| ------ | --: | ---------: | -------------: | -----: | ----: |
| xml    |  64 |        189 |            310 |   23.7 |    11 |
| xml    | 256 |        260 |           1238 |   58.9 |    17 |
| xml    | 512 |        346 |           2474 |  106.5 |    19 |
| base64 |  64 |        323 |            641 |    5.5 |    37 |
| base64 | 256 |        915 |           2566 |   31.0 |    33 |
| base64 | 512 |       1674 |           5132 |   69.1 |    30 |

## Negative controls (default limits, 512 MiB, concurrency 4)

| platform | kind   | reason                                                                           | maxRSS MiB | wall s | spool clean |
| -------- | ------ | -------------------------------------------------------------------------------- | ---------: | -----: | ----------- |
| macOS    | xml    | `payload/payload.too-large` (decompressed output exceeds `maxDecompressedBytes`) |        402 |    2.0 | yes         |
| macOS    | base64 | `mime/body.too-large` (request exceeds `maxRequestBytes`)                        |        399 |    0.4 | yes         |
| Linux    | xml    | `payload/payload.too-large`                                                      |        334 |    4.4 | yes         |
| Linux    | base64 | `mime/body.too-large`                                                            |        358 |    1.4 | yes         |

Both fail with a size-limit reason, leave the spool empty and are far faster than
the positive runs. The `xml` control still peaks high because it decrypts and
decompresses up to the 256 MiB `maxDecompressedBytes` before failing.

## Findings

The contract's memory assertions are **not met** by this revision on either
platform. Every run is functionally correct (payload verified, spooled and cleaned
up), but peak process memory grows with the message size rather than staying flat,
and it exceeds the provisional 384 MiB ceiling before 512 MiB.

| #   | Assertion                          | macOS         | Linux          |
| --- | ---------------------------------- | ------------- | -------------- |
| 1   | ceiling ≤ 384 MiB, xml-512         | **FAIL** 421  | 346 (pass)     |
| 2   | ceiling ≤ 384 MiB, base64-256      | **FAIL** 682  | **FAIL** 915   |
| 3   | ceiling ≤ 384 MiB, base64-512      | **FAIL** 1298 | **FAIL** 1674  |
| 4   | flatness ≤ 64 MiB, xml (64→512)    | **FAIL** +198 | **FAIL** +157  |
| 5   | flatness ≤ 64 MiB, base64 (64→512) | **FAIL** +926 | **FAIL** +1350 |

Observations that localise the growth:

- It is off-heap: peak `heapUsed` stayed flat at ~35 MB in every run, while peak
  `external`/`arrayBuffers` tracked the message size (e.g. at 512 MiB,
  sampled peak `external` ≈ 228 MB at base64-512 vs ≈ 35 MB at base64-64).
- It scales with concurrency and with the wire/ciphertext size, not the recovered
  size: a single receive of xml-512 peaked at 239 MiB; four concurrent receives of
  the same message peaked at 421 MiB, and the base64 (wire ≈ recovered) runs peak
  far above the xml ones (wire ≈ recovered/9.6).
- Early-failing runs still peak high: the xml negative control (fails during
  decompression after reading a 53 MiB request) hit 402 MiB (macOS) / 334 MiB
  (Linux).

This points at memory retained per concurrent receive scaling with the request/
ciphertext size rather than a fixed working set. Because Item 5 is measurement
only, this is recorded as a finding for a follow-up fix; no `src/` change was made
and the provisional ceiling was **not** raised.

## Command

```bash
# macOS
AS4_MEASURE_DIR=/tmp/as4-measure-dev \
  AS4_MEASURE_SIZES=64,256,512 AS4_MEASURE_KINDS=xml,base64 AS4_MEASURE_CONCURRENCY=4 \
  npm run measure:receive

# Linux (Docker), node:22 in the container, host node_modules kept out of the way
docker run --rm -v "$PWD":/repo -v as4-measure-nm:/repo/node_modules -w /repo \
  -e AS4_MEASURE_DIR=/tmp/as4-measure-linux \
  node:22-bookworm bash -lc "npm ci --no-audit --no-fund && node --import tsx test/measure-receive.ts"
```
