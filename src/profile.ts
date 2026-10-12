import {
  AS4_COMPRESSION_TYPE,
  EBMS_MPC_DEFAULT,
  EBMS_ROLE_INITIATOR,
  EBMS_ROLE_RESPONDER,
  PEPPOL_AGREEMENT_REF,
  PEPPOL_PARTY_ID_TYPE,
} from './constants.js';
import type { Profile } from './types.js';

/**
 * The Peppol AS4 profile constants, in one place. [PEPPOLAS4] fixes the party id
 * type, roles, agreement and default MPC; the MimeType part property is required
 * by [AS4PROFILE] §3.1 but not pinned by Peppol (see README "Open questions").
 */
export const peppolProfile: Profile = {
  partyIdType: PEPPOL_PARTY_ID_TYPE,
  agreementRef: PEPPOL_AGREEMENT_REF,
  initiatorRole: EBMS_ROLE_INITIATOR,
  responderRole: EBMS_ROLE_RESPONDER,
  mpc: EBMS_MPC_DEFAULT,
  mimeType: 'application/xml',
};

/** Compression is an AS4 feature, not a profile constant; exported for callers. */
export { AS4_COMPRESSION_TYPE };

export default peppolProfile;
