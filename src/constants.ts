/**
 * Protocol constants.
 *
 * Every URI here is taken from a specification. The reference after each value
 * points at the document and section listed in README.md "Specification
 * references".
 */

// SOAP 1.2. [SOAP12] §2.
export const SOAP_ENV_NS = 'http://www.w3.org/2003/05/soap-envelope';

// ebMS 3.0 core. [EBMS3CORE] §2.2.
export const EBMS_NS = 'http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/';
export const EBMS_ROLE_INITIATOR = `${EBMS_NS}initiator`;
export const EBMS_ROLE_RESPONDER = `${EBMS_NS}responder`;
export const EBMS_MPC_DEFAULT = `${EBMS_NS}defaultMPC`;
export const EBMS_MEP_ONE_WAY = `${EBMS_NS}oneWay`;
export const EBMS_MEP_BINDING_PUSH = `${EBMS_NS}push`;

// Peppol AS4 Profile v2.0.3. [PEPPOLAS4] Table 3, Table 4, §5.
export const PEPPOL_PARTY_ID_TYPE = 'urn:fdc:peppol.eu:2017:identifiers:ap';
export const PEPPOL_AGREEMENT_REF = 'urn:fdc:peppol.eu:2017:agreements:tia:ap_provider';
export const PEPPOL_TRANSPORT_PROFILE = 'peppol-transport-as4-v2_0';

// WS-Security 1.0 / 1.1.1. [WSSSMS] §4, [WSSSWA] §5.
export const WSSE_NS = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
export const WSU_NS = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';
export const WSSE11_NS = 'http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd';
export const XMLNS_NS = 'http://www.w3.org/2000/xmlns/';

// XML Signature. [XMLDSIG1] §6.
export const DS_NS = 'http://www.w3.org/2000/09/xmldsig#';

// XML Encryption / Encryption 1.1. [XMLENC], [XMLENC11].
export const XENC_NS = 'http://www.w3.org/2001/04/xmlenc#';
export const XENC11_NS = 'http://www.w3.org/2009/xmlenc11#';

// Algorithms. [CEFEAS4] §3.2.6 (mandated set for the eDelivery common profile).
export const ALGO_EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';
export const ALGO_RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
export const ALGO_SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';
export const ALGO_AES128_GCM = 'http://www.w3.org/2009/xmlenc11#aes128-gcm';
export const ALGO_RSA_OAEP = 'http://www.w3.org/2009/xmlenc11#rsa-oaep';
export const ALGO_MGF1_SHA256 = 'http://www.w3.org/2009/xmlenc11#mgf1sha256';

// SOAP with Attachments profile 1.1 (SwA). [WSSSWA].
export const SWA_TRANSFORM_SIGNATURE =
  'http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Signature-Transform';
export const SWA_TRANSFORM_CIPHERTEXT =
  'http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Ciphertext-Transform';
export const SWA_ATTACHMENT_CONTENT_ONLY =
  'http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Only';

// WS-Security token types. [WSSX509], [WSSSMS].
export const WSS_BASE64_ENCODING =
  'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary';
export const WSS_X509_V3 = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3';
export const WSS_ENCRYPTED_KEY_TOKEN_TYPE =
  'http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKey';

// AS4 compression feature. [AS4PROFILE] §3.1, [CEFEAS4] §3.3.
export const AS4_COMPRESSION_TYPE = 'application/gzip';

// ebBP signals 2.0 (NonRepudiationInformation). [EBMS3CORE] §A.3 namespace table.
export const EBBP_SIGNALS_NS = 'http://docs.oasis-open.org/ebxml-bp/ebbp-signals-2.0';

// ebMS error meta. [EBMS3CORE] §6.2.
export const EBMS_ERROR_CODE_NOT_SERVICED_DETAIL = 'PEPPOL:NOT_SERVICED';

export const SOAP_XML_MEDIA_TYPE = 'application/soap+xml';
export const OCTET_STREAM_MEDIA_TYPE = 'application/octet-stream';
