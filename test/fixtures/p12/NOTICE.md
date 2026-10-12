# PKCS#12 test fixtures

Throwaway material for `test/credentials.test.ts`, generated with OpenSSL 3.6.1.
None of it is a secret or is used outside these tests.

| File            | Contents                                                     |
| --------------- | ------------------------------------------------------------ |
| `leaf-key.pem`  | The private key, matching `leaf-cert.pem`.                   |
| `leaf-cert.pem` | The AP/leaf certificate (`CN=POP000001`, `CA:FALSE`).        |
| `ca-cert.pem`   | The self-signed CA that issued the leaf.                     |
| `modern.p12`    | Leaf + CA, modern PBES2 (the OpenSSL 3 default).             |
| `legacy.p12`    | Leaf + CA, `-legacy` (PBE-SHA1-3DES / RC2-40).               |
| `ca-first.p12`  | Leaf + CA with the CA listed first (see `make-ca-first.ts`). |

All containers use the passphrase `secret`.

## How they were made

```sh
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca-key.pem -out ca-cert.pem \
  -days 3650 -subj "/CN=AS4 P12 Test CA"

openssl req -newkey rsa:2048 -nodes -keyout leaf-key.pem -out leaf.csr \
  -subj "/CN=POP000001"

openssl x509 -req -in leaf.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
  -out leaf-cert.pem -days 3650 \
  -extfile <(printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n")

openssl pkcs12 -export -out modern.p12 \
  -inkey leaf-key.pem -in leaf-cert.pem -certfile ca-cert.pem -passout pass:secret

openssl pkcs12 -export -legacy -out legacy.p12 \
  -inkey leaf-key.pem -in leaf-cert.pem -certfile ca-cert.pem -passout pass:secret

node --import tsx test/fixtures/p12/make-ca-first.ts   # writes ca-first.p12
```
