import { Readable } from 'node:stream';
import { signerFromKey, peppolProfile, type SendAs4Input } from '../../src/index.js';
import {
  createCertificateValidator,
  defaultRevocationPolicy,
  type RevocationPolicy,
} from '../../src/certificate-validator.js';
import type { ValidateCertificate } from '../../src/types.js';
import type { TestPki } from './pki.js';

/** A validator bound to the given test PKI. Revocation is off by default. */
export function testValidator(
  pki: TestPki,
  options: {
    readonly roots?: readonly string[];
    readonly intermediates?: readonly string[];
    readonly revocation?: RevocationPolicy;
    readonly extraRevokedSerials?: Readonly<Record<string, readonly string[]>>;
  } = {},
): ValidateCertificate {
  const validator = createCertificateValidator({
    roots: options.roots ?? [pki.root.certPem],
    intermediates: options.intermediates ?? [pki.intermediate.certPem],
    revocation: options.revocation ?? defaultRevocationPolicy({ ocsp: false, crl: false }),
    ...(options.extraRevokedSerials ? { extraRevokedSerials: options.extraRevokedSerials } : {}),
  });
  return (input) => validator.validate(input);
}

export function baseInput(
  pki: TestPki,
  endpointUrl: string,
  caPem: string | null,
  overrides: Partial<SendAs4Input> = {},
): SendAs4Input {
  const base: SendAs4Input = {
    payload: Readable.from(Buffer.from('<?xml version="1.0"?><StandardBusinessDocument/>', 'utf8')),
    endpointUrl,
    transportProfile: 'peppol-transport-as4-v2_0',
    receiverCertificate: pki.receiver.certPem,
    senderParticipant: { scheme: 'iso6523-actorid-upis', value: '0192:111111111' },
    receiverParticipant: { scheme: 'iso6523-actorid-upis', value: '0192:222222222' },
    documentType: {
      scheme: 'busdox-docid-qns',
      value:
        'urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice##urn:www.cenbii.eu:transaction:biitrns010:ver2.0:extended:urn:www.peppol.eu:bis:peppol5a:ver2.0::2.1',
    },
    process: { scheme: 'cenbii-procid-ubl', value: 'urn:www.cenbii.eu:profile:bii05:ver2.0' },
    as4MessageId: 'test-message@as4-sender.test',
    signer: signerFromKey(pki.sender.keyObject, pki.sender.certPem),
    validateCertificate: testValidator(pki),
    profile: peppolProfile,
    http: { connectMs: 5_000, totalMs: 15_000, ...(caPem ? { ca: [caPem] } : {}) },
    now: () => new Date(),
  };
  return { ...base, ...overrides };
}
