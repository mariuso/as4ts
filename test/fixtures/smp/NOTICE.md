# Peppol test-network SMP captures

These are raw SML/SMP discovery responses fetched from real SMP implementations
on the Peppol **test** network, used by `test/lookup-captures.test.ts`. They are
public service-metadata responses and the signers' public certificates — not code
from any other project, and no third-party licence applies.

| Name     | Participant                            | SMP                       | Captured   |
| -------- | -------------------------------------- | ------------------------- | ---------- |
| `helger` | `iso6523-actorid-upis::9915:helger`    | `smp.helger.com` (phase4) | 2026-10-12 |
| `elma`   | `iso6523-actorid-upis::0192:996220567` | `test-smp.elma-smp.no`    | 2026-10-12 |

Each capture has two files: `<name>.group.xml` is the `ServiceGroup` response and
`<name>.signed.xml` is the signed `SignedServiceMetadata` response, exactly as
served (no HTTP headers). `manifest.json` records the participant, document type
and process the recorded service metadata serves.

To add another capture, run:

```bash
node --import tsx examples/record-smp.ts \
  --participant 'iso6523-actorid-upis::<value>' \
  --doc-type '<document type value>' \
  --process '<process value>' \
  --env test --name <name>
```

then add the entry to `manifest.json`. The test verifies each response with the
bundled G3 test anchors and checks that a signed-for endpoint comes back.
