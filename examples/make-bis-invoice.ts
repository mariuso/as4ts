#!/usr/bin/env node
/**
 * Generate a Peppol BIS Billing 3.0 invoice wrapped in an SBDH, ready to hand to
 * send-one as --file. This is caller-side tooling: the SBDH belongs to the
 * platform, not the sender library.
 *
 *   npm run make-invoice -- \
 *     --seller iso6523-actorid-upis:0192:111111111 \
 *     --buyer  iso6523-actorid-upis:0192:222222222 \
 *     --out invoice.sbdh.xml
 *
 * Values are placeholders; validate the result with your document validator
 * (schema + Peppol BIS 3.0 schematron) before relying on it.
 */
import { writeFileSync } from 'node:fs';

const UBL_INVOICE = 'urn:oasis:names:specification:ubl:schema:xsd:Invoice-2';
const CBC = 'urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2';
const CAC = 'urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2';
const SBDH = 'http://www.unece.org/cefact/namespaces/StandardBusinessDocumentHeader';

// Peppol BIS Billing 3.0 identifiers ([PEPPOL-BIS-BILLING-3] §5.1.2).
const CUSTOMIZATION_ID = 'urn:cen.eu:en16931:2017#compliant#urn:fdc:peppol.eu:2017:poacc:billing:3.0';
const PROFILE_ID = 'urn:fdc:peppol.eu:2017:poacc:billing:01:1.0';
// AS4 document type identifier VALUE (no scheme). The scheme ("busdox-docid-qns")
// appears only in the AS4 eb:Action; the SBDH BusinessScope/DOCUMENTID carries
// the value alone ([PEPPOLAS4] §4.6, [PEPPOL-Envelope]).
const DOCUMENT_TYPE_SCHEME = 'busdox-docid-qns';
const DOCUMENT_TYPE = `${UBL_INVOICE}::Invoice##${CUSTOMIZATION_ID}::2.1`;

function flags(argv: readonly string[]): Map<string, string> {
  const map = new Map<string, string>();
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i]!;
    if (!token.startsWith('--')) continue;
    const key = token.slice(2);
    const next = argv[i + 1];
    if (next !== undefined && !next.startsWith('--')) {
      map.set(key, next);
      i += 1;
    } else map.set(key, 'true');
  }
  return map;
}

function esc(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/** `iso6523-actorid-upis:0192:222222222` -> { scheme, value, icd, identifier }. */
function parseParty(input: string): { scheme: string; value: string; icd: string; identifier: string } {
  const firstColon = input.indexOf(':');
  const scheme = firstColon > 0 ? input.slice(0, firstColon) : 'iso6523-actorid-upis';
  const value = firstColon > 0 ? input.slice(firstColon + 1) : input;
  const [icd, ...rest] = value.split(':');
  return { scheme, value, icd: icd ?? '', identifier: rest.join(':') || value };
}

function partyXml(
  role: 'AccountingSupplierParty' | 'AccountingCustomerParty',
  p: ReturnType<typeof parseParty>,
  name: string,
  country: string,
  street: string,
  city: string,
  postal: string,
  vat: string,
): string {
  return `
    <cac:${role}>
      <cac:Party>
        <cbc:EndpointID schemeID="${esc(p.icd)}">${esc(p.identifier)}</cbc:EndpointID>
        <cac:PartyName><cbc:Name>${esc(name)}</cbc:Name></cac:PartyName>
        <cac:PostalAddress>
          <cbc:StreetName>${esc(street)}</cbc:StreetName>
          <cbc:CityName>${esc(city)}</cbc:CityName>
          <cbc:PostalZone>${esc(postal)}</cbc:PostalZone>
          <cac:Country><cbc:IdentificationCode>${esc(country)}</cbc:IdentificationCode></cac:Country>
        </cac:PostalAddress>
        <cac:PartyTaxScheme>
          <cbc:CompanyID>${esc(vat)}</cbc:CompanyID>
          <cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme>
        </cac:PartyTaxScheme>
        <cac:PartyLegalEntity>
          <cbc:RegistrationName>${esc(name)}</cbc:RegistrationName>
          <cbc:CompanyID>${esc(p.value)}</cbc:CompanyID>
        </cac:PartyLegalEntity>
      </cac:Party>
    </cac:${role}>`;
}

function main(): void {
  const args = flags(process.argv.slice(2));
  if (args.has('help') || !args.get('seller') || !args.get('buyer')) {
    console.log(
      'usage: --seller scheme:icd:id --buyer scheme:icd:id [--invoice-id ID] [--currency EUR] [--amount 1000.00] [--vat 25] [--country NO] [--date YYYY-MM-DD] --out FILE',
    );
    process.exit(args.has('help') ? 0 : 2);
  }

  const seller = parseParty(args.get('seller')!);
  const buyer = parseParty(args.get('buyer')!);
  const invoiceId = args.get('invoice-id') ?? `INV-${Date.now()}`;
  const currency = args.get('currency') ?? 'EUR';
  const amount = Number(args.get('amount') ?? 1000).toFixed(2);
  const vatRate = Number(args.get('vat') ?? 25);
  const country = args.get('country') ?? (seller.icd === '0192' ? 'NO' : 'NO');
  const date = args.get('date') ?? new Date().toISOString().slice(0, 10);
  const tax = (Number(amount) * (vatRate / 100)).toFixed(2);
  const total = (Number(amount) + Number(tax)).toFixed(2);
  const countryCode1 = buyer.icd === '0192' ? 'NO' : country;
  const now = new Date().toISOString();

  const invoice = `<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="${UBL_INVOICE}"
         xmlns:cac="${CAC}"
         xmlns:cbc="${CBC}">
  <cbc:CustomizationID>${CUSTOMIZATION_ID}</cbc:CustomizationID>
  <cbc:ProfileID>${PROFILE_ID}</cbc:ProfileID>
  <cbc:ID>${esc(invoiceId)}</cbc:ID>
  <cbc:IssueDate>${esc(date)}</cbc:IssueDate>
  <cbc:DueDate>${esc(date)}</cbc:DueDate>
  <cbc:InvoiceTypeCode>380</cbc:InvoiceTypeCode>
  <cbc:DocumentCurrencyCode>${esc(currency)}</cbc:DocumentCurrencyCode>
  <cbc:BuyerReference>${esc(invoiceId)}</cbc:BuyerReference>
${partyXml('AccountingSupplierParty', seller, 'AS4 Sender Test Supplier', country, 'Testveien 1', 'Oslo', '0001', `NO${seller.identifier}MVA`)}
${partyXml('AccountingCustomerParty', buyer, 'AS4 Sender Test Buyer', countryCode1, 'Testgata 2', 'Oslo', '0002', `NO${buyer.identifier}MVA`)}
  <cac:PaymentMeans>
    <cbc:PaymentMeansCode>30</cbc:PaymentMeansCode>
    <cbc:PaymentDueDate>${esc(date)}</cbc:PaymentDueDate>
    <cbc:PaymentID>${esc(invoiceId)}</cbc:PaymentID>
  </cac:PaymentMeans>
  <cac:TaxTotal>
    <cbc:TaxAmount currencyID="${esc(currency)}">${tax}</cbc:TaxAmount>
    <cac:TaxSubtotal>
      <cbc:TaxableAmount currencyID="${esc(currency)}">${amount}</cbc:TaxableAmount>
      <cbc:TaxAmount currencyID="${esc(currency)}">${tax}</cbc:TaxAmount>
      <cac:TaxCategory>
        <cbc:ID>S</cbc:ID>
        <cbc:Percent>${vatRate.toFixed(2)}</cbc:Percent>
        <cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme>
      </cac:TaxCategory>
    </cac:TaxSubtotal>
  </cac:TaxTotal>
  <cac:LegalMonetaryTotal>
    <cbc:LineExtensionAmount currencyID="${esc(currency)}">${amount}</cbc:LineExtensionAmount>
    <cbc:TaxExclusiveAmount currencyID="${esc(currency)}">${amount}</cbc:TaxExclusiveAmount>
    <cbc:TaxInclusiveAmount currencyID="${esc(currency)}">${total}</cbc:TaxInclusiveAmount>
    <cbc:PayableAmount currencyID="${esc(currency)}">${total}</cbc:PayableAmount>
  </cac:LegalMonetaryTotal>
  <cac:InvoiceLine>
    <cbc:ID>1</cbc:ID>
    <cbc:InvoicedQuantity unitCode="EA">1</cbc:InvoicedQuantity>
    <cbc:LineExtensionAmount currencyID="${esc(currency)}">${amount}</cbc:LineExtensionAmount>
    <cac:Item>
      <cbc:Name>Consulting services</cbc:Name>
      <cac:ClassifiedTaxCategory>
        <cbc:ID>S</cbc:ID>
        <cbc:Percent>${vatRate.toFixed(2)}</cbc:Percent>
        <cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme>
      </cac:ClassifiedTaxCategory>
    </cac:Item>
    <cac:Price>
      <cbc:PriceAmount currencyID="${esc(currency)}">${amount}</cbc:PriceAmount>
    </cac:Price>
  </cac:InvoiceLine>
</Invoice>`;

  const sbdh = `<?xml version="1.0" encoding="UTF-8"?>
<StandardBusinessDocument xmlns="${SBDH}">
  <StandardBusinessDocumentHeader>
    <HeaderVersion>1.0</HeaderVersion>
    <Sender>
      <Identifier Authority="${esc(seller.scheme)}">${esc(seller.value)}</Identifier>
    </Sender>
    <Receiver>
      <Identifier Authority="${esc(buyer.scheme)}">${esc(buyer.value)}</Identifier>
    </Receiver>
    <DocumentIdentification>
      <Standard>${UBL_INVOICE}</Standard>
      <TypeVersion>2.1</TypeVersion>
      <InstanceIdentifier>${esc(invoiceId)}</InstanceIdentifier>
      <Type>Invoice</Type>
      <CreationDateAndTime>${now}</CreationDateAndTime>
    </DocumentIdentification>
    <BusinessScope>
      <Scope>
        <Type>DOCUMENTID</Type>
        <InstanceIdentifier>${esc(DOCUMENT_TYPE)}</InstanceIdentifier>
      </Scope>
      <Scope>
        <Type>PROCESSID</Type>
        <InstanceIdentifier>${PROFILE_ID}</InstanceIdentifier>
      </Scope>
      <Scope>
        <Type>COUNTRY_C1</Type>
        <InstanceIdentifier>${esc(countryCode1)}</InstanceIdentifier>
      </Scope>
    </BusinessScope>
  </StandardBusinessDocumentHeader>
${invoice.replace(/^<\?xml[^>]*\?>\n/, '')}
</StandardBusinessDocument>`;

  const out = args.get('out');
  if (!out) {
    process.stdout.write(sbdh);
    return;
  }
  writeFileSync(out, sbdh);
  console.log(`wrote ${out}`);
  console.log(`SBDH DOCUMENTID: ${DOCUMENT_TYPE}`);
  console.log(`AS4 Action:      ${DOCUMENT_TYPE_SCHEME}::${DOCUMENT_TYPE}`);
  console.log(`AS4 Service:     ${PROFILE_ID}`);
}

main();
