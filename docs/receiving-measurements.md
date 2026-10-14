# Receiving measurements: the 500 MiB contract

Measured evidence for the contract in
[receiving-limits.md](receiving-limits.md#a-500-mib-document-contract). Regenerate
with `npm run measure:receive` (see that section for the env variables). Raw JSON
is written to `measurements/` (gitignored).

The measured process runs **under plain `node`**, from a bundle the driver builds
with esbuild (`measurements/receive-child.mjs`), so the numbers reflect the
shipped code rather than the tsx loader. The fixture generator still runs under
tsx; it is not measured.

## Environment

|                     | macOS run                              | Linux run                                |
| ------------------- | -------------------------------------- | ---------------------------------------- |
| Node                | v22.13.1                               | v22.23.3                                 |
| Platform            | macOS 26.0 (25A5338b), Apple M3, arm64 | Linux (Docker `node:22-bookworm`), arm64 |
| RAM                 | 16 GiB                                 | 5.76 GiB VM limit, 4 vCPU                |
| Disk                | APFS, ~14 GiB free                     | container overlay                        |
| Container           | none                                   | Docker Desktop VM on the same host       |
| `maxRSS` unit check | +261 MiB for a 256 MiB `Buffer`        | +261 MiB for a 256 MiB `Buffer`          |

Both unit checks confirm `process.resourceUsage().maxRSS` is in kilobytes.

## Fixtures

The request body is a real signed `multipart/related` message whose payload is a
valid SBDH document followed by streamed invoice content. The content is
deterministic, so both platforms produced byte-identical fixtures. `xml` is
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
was left in `os.tmpdir()`. "signal" means `openAs4Message` was passed a
(never-aborting) `AbortSignal`, as a production caller would. `MiB/s` is an
**aggregate** throughput: recovered bytes across all four receives divided by
wall time (not per-receive).

### macOS

| kind   | MiB | signal | maxRSS MiB | spool peak MiB | wall s | MiB/s |
| ------ | --: | ------ | ---------: | -------------: | -----: | ----: |
| xml    |  64 | no     |        159 |            310 |    9.5 |    27 |
| xml    |  64 | yes    |        178 |            310 |    9.6 |    27 |
| xml    | 256 | no     |        176 |           1238 |   39.1 |    26 |
| xml    | 256 | yes    |        180 |           1238 |   37.5 |    27 |
| xml    | 512 | no     |        144 |           2474 |   87.9 |    23 |
| xml    | 512 | yes    |        183 |           2474 |   78.2 |    26 |
| base64 |  64 | no     |        160 |            641 |    4.9 |    52 |
| base64 |  64 | yes    |        163 |            641 |    4.9 |    52 |
| base64 | 256 | no     |        154 |           2566 |   23.5 |    44 |
| base64 | 256 | yes    |        160 |           2566 |   27.1 |    38 |
| base64 | 512 | no     |        119 |           5132 |   77.3 |    26 |
| base64 | 512 | yes    |        140 |           5132 |   74.6 |    27 |

### Linux (Docker `node:22-bookworm`, 5.76 GiB, 4 vCPU)

| kind   | MiB | signal | maxRSS MiB | spool peak MiB | wall s | MiB/s |
| ------ | --: | ------ | ---------: | -------------: | -----: | ----: |
| xml    |  64 | no     |        153 |            310 |   12.5 |    20 |
| xml    |  64 | yes    |        148 |            310 |   12.1 |    21 |
| xml    | 256 | no     |        152 |           1238 |   54.8 |    19 |
| xml    | 256 | yes    |        153 |           1238 |   50.9 |    20 |
| xml    | 512 | no     |        149 |           2474 |  114.6 |    18 |
| xml    | 512 | yes    |        152 |           2474 |  121.4 |    17 |
| base64 |  64 | no     |        134 |            641 |    6.3 |    41 |
| base64 |  64 | yes    |        151 |            641 |    6.5 |    39 |
| base64 | 256 | no     |        166 |           2566 |   25.6 |    40 |
| base64 | 256 | yes    |        153 |           2566 |   29.4 |    35 |
| base64 | 512 | no     |        158 |           5132 |   49.7 |    41 |
| base64 | 512 | yes    |        143 |           5132 |   62.5 |    33 |

Peak RSS is flat at 119–183 MiB across every size and both signal variants on
both platforms. Flatness (`maxRSS(512) − maxRSS(64)`) per kind × signal is
−40…+6 MiB on macOS and −8…+25 MiB on Linux, all within the 64 MiB tolerance; the
ceiling is 384 MiB.

## Negative controls (default limits, 512 MiB, concurrency 4)

| platform | kind   | signal | reason                      | maxRSS MiB | wall s | spool clean |
| -------- | ------ | ------ | --------------------------- | ---------: | -----: | ----------- |
| macOS    | xml    | no     | `payload/payload.too-large` |        139 |    3.5 | yes         |
| macOS    | xml    | yes    | `payload/payload.too-large` |        142 |    3.4 | yes         |
| macOS    | base64 | no     | `mime/body.too-large`       |         91 |    2.3 | yes         |
| macOS    | base64 | yes    | `mime/body.too-large`       |         98 |    0.8 | yes         |
| Linux    | xml    | no     | `payload/payload.too-large` |        105 |    5.5 | yes         |
| Linux    | xml    | yes    | `payload/payload.too-large` |        102 |    5.4 | yes         |
| Linux    | base64 | no     | `mime/body.too-large`       |         95 |    0.6 | yes         |
| Linux    | base64 | yes    | `mime/body.too-large`       |         95 |    0.7 | yes         |

Both fail with a size-limit reason, leave the spool empty, and stay under
~142 MiB — well below the ceiling and the positive 512 MiB runs.

## History

Commit `0a4d56f` (the first Item 5 measurement) reported peak RSS growing with
message size, up to 1298 MiB (macOS) / 1674 MiB (Linux) at 512 MiB, and exceeding
the 384 MiB ceiling from 256 MiB. Two causes were found and fixed in commit
`2a2684c`:

- `abortableStream` raced every chunk read against a long-lived abort promise, so
  every consumed chunk stayed reachable until the stream ended. The MIME parser
  always passes a signal, so it retained the whole request body while parsing,
  before authentication.
- The measured child ran under the tsx loader, which added ~110 MiB of peak
  memory.

These runs (bundled child under plain `node`, retention fixed) show flat, bounded
peak memory on both platforms.

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
