# Peppol test-network receipt captures

These are our own captures of AS4 receipts returned by real access points on the
Peppol **test** network, used by `test/captures.test.ts`. They are public data
(signed signal messages and the signers' public certificates) produced by this
project's own send path — not code from any other project, and no third-party
licence applies.

| File                         | Receiver participant                   | Signer CN   | Access point         | Captured   |
| ---------------------------- | -------------------------------------- | ----------- | -------------------- | ---------- |
| `oxalis-maventa.receipt.xml` | `iso6523-actorid-upis::0192:996220567` | `PNO000063` | Oxalis-NG (Jetty 11) | 2026-10-12 |
| `helger.receipt.xml`         | `iso6523-actorid-upis::9915:helger`    | `POP000306` | phase4               | 2026-10-12 |

Each file is the raw SOAP signal message exactly as received (no HTTP headers).

To add another capture, send to the receiver with `--out <dir>`, copy the
resulting `receipt.xml` here as `<name>.receipt.xml` (the name must end in
`.receipt.xml`), and it is picked up automatically — the test derives the message
id, signer and validation time from the file itself.
