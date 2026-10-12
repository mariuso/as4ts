import type { ParticipantId, Profile, ScopedId } from '../types.js';
import { defaultEntropy, hexToken, type Entropy } from '../entropy.js';
import { element, append } from './nodes.js';

export interface UserMessageParams {
  readonly messageId: string;
  /** ISO-8601 UTC timestamp, e.g. 2026-10-12T09:07:36.000Z. */
  readonly timestamp: string;
  /** Value of the sender AP certificate CN. [PEPPOLAS4] §4.5. */
  readonly fromPartyId: string;
  /** Value of the receiver AP certificate CN. [PEPPOLAS4] §4.5. */
  readonly toPartyId: string;
  /** Network constants (party id type, agreement, roles, MPC, MimeType). */
  readonly profile: Profile;
  readonly service: ScopedId;
  /** Already assembled as `<documentType.scheme>::<documentType.value>`. [PEPPOLAS4] §4.6. */
  readonly action: string;
  readonly originalSender: ParticipantId;
  readonly finalRecipient: ParticipantId;
  /** href of the payload part, `cid:<id>`. [AS4PROFILE] §5.2. */
  readonly payloadHref: string;
  readonly compressionType: string;
}

export interface BuiltUserMessage {
  readonly messaging: Element;
  readonly messagingId: string;
  readonly body: Element;
  readonly bodyId: string;
}

/**
 * Build the eb:Messaging/eb:UserMessage and the empty SOAP Body.
 *
 * Peppol AS4 [PEPPOLAS4] §4.5/§4.6/§4.8 fixes the party id type, the roles, the
 * agreement and the (optional) default MPC through the profile. PartyId values
 * are the access point certificate CNs. Service/Action carry the caller-supplied
 * process and document type identifiers; their schemes are never hardcoded.
 */
export function buildUserMessage(
  doc: Document,
  p: UserMessageParams,
  entropy: Entropy = defaultEntropy(),
): BuiltUserMessage {
  const messagingId = `_${hexToken(entropy, 16)}`;
  const bodyId = `_${hexToken(entropy, 16)}`;

  const userMessage = element(doc, 'eb', 'UserMessage', { mpc: p.profile.mpc });

  const messageInfo = element(doc, 'eb', 'MessageInfo');
  append(
    messageInfo,
    element(doc, 'eb', 'Timestamp', {}, p.timestamp),
    element(doc, 'eb', 'MessageId', {}, p.messageId),
  );
  append(userMessage, messageInfo);

  const partyInfo = element(doc, 'eb', 'PartyInfo');
  const from = element(doc, 'eb', 'From');
  append(from, element(doc, 'eb', 'PartyId', { type: p.profile.partyIdType }, p.fromPartyId));
  append(from, element(doc, 'eb', 'Role', {}, p.profile.initiatorRole));
  const to = element(doc, 'eb', 'To');
  append(to, element(doc, 'eb', 'PartyId', { type: p.profile.partyIdType }, p.toPartyId));
  append(to, element(doc, 'eb', 'Role', {}, p.profile.responderRole));
  append(partyInfo, from, to);
  append(userMessage, partyInfo);

  const collaborationInfo = element(doc, 'eb', 'CollaborationInfo');
  append(collaborationInfo, element(doc, 'eb', 'AgreementRef', {}, p.profile.agreementRef));
  append(collaborationInfo, element(doc, 'eb', 'Service', { type: p.service.scheme }, p.service.value));
  append(collaborationInfo, element(doc, 'eb', 'Action', {}, p.action));
  append(collaborationInfo, element(doc, 'eb', 'ConversationId', {}, p.messageId));
  append(userMessage, collaborationInfo);

  const properties = element(doc, 'eb', 'MessageProperties');
  append(
    properties,
    element(doc, 'eb', 'Property', { name: 'originalSender', type: p.originalSender.scheme }, p.originalSender.value),
  );
  append(
    properties,
    element(doc, 'eb', 'Property', { name: 'finalRecipient', type: p.finalRecipient.scheme }, p.finalRecipient.value),
  );
  append(userMessage, properties);

  const payloadInfo = element(doc, 'eb', 'PayloadInfo');
  const partInfo = element(doc, 'eb', 'PartInfo', { href: p.payloadHref });
  const partProperties = element(doc, 'eb', 'PartProperties');
  append(partProperties, element(doc, 'eb', 'Property', { name: 'MimeType' }, p.profile.mimeType));
  append(partProperties, element(doc, 'eb', 'Property', { name: 'CompressionType' }, p.compressionType));
  append(partInfo, partProperties);
  append(payloadInfo, partInfo);
  append(userMessage, payloadInfo);

  const messaging = element(doc, 'eb', 'Messaging', {
    'env:mustUnderstand': 'true',
    'wsu:Id': messagingId,
  });
  append(messaging, userMessage);

  const body = element(doc, 'env', 'Body', { 'wsu:Id': bodyId });

  return { messaging, messagingId, body, bodyId };
}
