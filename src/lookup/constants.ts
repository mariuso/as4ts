/**
 * SMP / SML constants, from the Peppol specifications. See README "SMP/SML
 * lookup" for the versions followed. Sender-independent: the lookup entry point
 * never imports the sender.
 */

// Peppol SMP v1.4.0, Appendix A (target namespace).
export const SMP_NS = 'http://busdox.org/serviceMetadata/publishing/1.0/';
// Peppol identifiers schema (shared by SML and SMP).
export const IDS_NS = 'http://busdox.org/transport/identifiers/1.0/';
// WS-Addressing 1.0, used by the EndpointReference.
export const WSA_NS = 'http://www.w3.org/2005/08/addressing';

// Peppol SMP v1.4.0 §5.5.1 mandates these exact algorithms.
export const ALGO_INCLUSIVE_C14N = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
export const ALGO_ENVELOPED_SIGNATURE = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';
export const ALGO_RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
export const ALGO_SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';

// The NAPTR service tag; SML v1.3.0 §2.1.1 (service field is case-insensitive).
export const SML_NAPTR_SERVICE = 'meta:smp';

// The Peppol participant identifier meta scheme; Policy for use of Identifiers
// v4.4.0 POLICY 5.
export const PARTICIPANT_META_SCHEME = 'iso6523-actorid-upis';

// Document type identifier schemes; Policy for use of Identifiers v4.4.0 §5.1.
export const BUSDOC_DOCID_QNS = 'busdox-docid-qns';
export const PEPPOL_DOCTYPE_WILDCARD = 'peppol-doctype-wildcard';

export const EXPECTED_SMP_MEDIA_TYPES = ['text/xml', 'application/xml'];
