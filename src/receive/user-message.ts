import { AS4_COMPRESSION_TYPE, EBMS_NS } from '../constants.js';
import type { Profile, ScopedId } from '../types.js';
import type { InboundFailureReason } from './types.js';

/**
 * Read the ebMS headers of an inbound `UserMessage` and check them against the
 * profile (Phase 3). Facts are read only from the expected elements in the
 * expected position; a message whose roles, agreement, MPC or identifiers do not
 * match the profile is rejected with `addressing.*`.
 */
export class AddressingFault extends Error {
  constructor(
    readonly reason: InboundFailureReason,
    message: string,
  ) {
    super(message);
    this.name = 'AddressingFault';
  }
}

export interface UserMessageFacts {
  readonly messageId: string;
  readonly timestamp: string;
  readonly fromPartyId: string;
  readonly toPartyId: string;
  readonly service: ScopedId;
  readonly action: string;
  readonly agreement: string | null;
  readonly conversationId: string | null;
  readonly mpc: string | null;
  readonly originalSender: string;
  readonly finalRecipient: string;
  readonly compressionType: string | null;
  readonly partHref: string;
}

function directChildren(node: Element | null, ns: string, localName: string): Element[] {
  const out: Element[] = [];
  const children = node?.childNodes;
  if (!children) return out;
  for (let i = 0; i < children.length; i += 1) {
    const child = children.item(i);
    if (!child || child.nodeType !== 1) continue;
    const element = child as Element;
    if (element.namespaceURI === ns && element.localName === localName) out.push(element);
  }
  return out;
}

function direct(node: Element | null, ns: string, localName: string): Element | null {
  return directChildren(node, ns, localName)[0] ?? null;
}

function text(element: Element | null): string | null {
  const value = element?.textContent;
  return value === null || value === undefined || value === '' ? null : value;
}

function requiredText(element: Element | null, what: string): string {
  const value = text(element);
  if (value === null) throw new AddressingFault('addressing.unsupported', `missing ${what}`);
  return value;
}

/** Read the `Property` with the given `@name` from an eb:MessageProperties/PartProperties. */
function propertyValue(properties: Element | null, name: string): string | null {
  for (const property of directChildren(properties, EBMS_NS, 'Property')) {
    if (property.getAttribute('name') === name) return text(property);
  }
  return null;
}

export function readUserMessage(envelope: Document, profile: Profile): UserMessageFacts {
  const header = direct(envelope.documentElement, envelope.documentElement.namespaceURI ?? '', 'Header');
  const messaging = direct(header, EBMS_NS, 'Messaging');
  const userMessage = direct(messaging, EBMS_NS, 'UserMessage');
  if (!messaging || !userMessage) {
    throw new AddressingFault('addressing.unsupported', 'no eb:UserMessage in the Header');
  }

  const messageInfo = direct(userMessage, EBMS_NS, 'MessageInfo');
  const messageId = requiredText(direct(messageInfo, EBMS_NS, 'MessageId'), 'MessageId');
  const timestamp = requiredText(direct(messageInfo, EBMS_NS, 'Timestamp'), 'Timestamp');

  const partyInfo = direct(userMessage, EBMS_NS, 'PartyInfo');
  const from = direct(partyInfo, EBMS_NS, 'From');
  const to = direct(partyInfo, EBMS_NS, 'To');
  const fromPartyId = requiredText(direct(from, EBMS_NS, 'PartyId'), 'From/PartyId');
  const toPartyId = requiredText(direct(to, EBMS_NS, 'PartyId'), 'To/PartyId');
  if (text(direct(from, EBMS_NS, 'Role')) !== profile.initiatorRole) {
    throw new AddressingFault('addressing.unsupported', 'From/Role is not the initiator role');
  }
  if (text(direct(to, EBMS_NS, 'Role')) !== profile.responderRole) {
    throw new AddressingFault('addressing.unsupported', 'To/Role is not the responder role');
  }

  const collaboration = direct(userMessage, EBMS_NS, 'CollaborationInfo');
  const serviceElement = direct(collaboration, EBMS_NS, 'Service');
  const serviceScheme = serviceElement?.getAttribute('type');
  const serviceValue = text(serviceElement);
  if (!serviceScheme || !serviceValue) {
    throw new AddressingFault('addressing.unsupported', 'missing CollaborationInfo/Service');
  }
  const action = requiredText(direct(collaboration, EBMS_NS, 'Action'), 'Action');
  const agreement = text(direct(collaboration, EBMS_NS, 'AgreementRef'));
  if (agreement !== null && agreement !== profile.agreementRef) {
    throw new AddressingFault('addressing.unsupported', 'AgreementRef is not the profile agreement');
  }
  const conversationId = text(direct(collaboration, EBMS_NS, 'ConversationId'));

  const mpc = userMessage.getAttribute('mpc');
  if (mpc !== null && mpc !== '' && mpc !== profile.mpc) {
    throw new AddressingFault('addressing.mpc', `unsupported MPC ${mpc}`);
  }

  const properties = direct(userMessage, EBMS_NS, 'MessageProperties');
  const originalSender = propertyValue(properties, 'originalSender');
  const finalRecipient = propertyValue(properties, 'finalRecipient');
  if (originalSender === null || finalRecipient === null) {
    throw new AddressingFault('addressing.unsupported', 'missing originalSender or finalRecipient property');
  }

  const payloadInfo = direct(userMessage, EBMS_NS, 'PayloadInfo');
  const partInfo = direct(payloadInfo, EBMS_NS, 'PartInfo');
  const partHref = partInfo?.getAttribute('href') ?? null;
  if (!partHref) throw new AddressingFault('addressing.unsupported', 'missing PayloadInfo/PartInfo href');
  const partProperties = direct(partInfo, EBMS_NS, 'PartProperties');
  const compressionType = propertyValue(partProperties, 'CompressionType');

  return {
    messageId,
    timestamp,
    fromPartyId,
    toPartyId,
    service: { scheme: serviceScheme, value: serviceValue },
    action,
    agreement,
    conversationId,
    mpc,
    originalSender,
    finalRecipient,
    compressionType,
    partHref,
  };
}

/** Whether a compression declaration is supported by the constrained profile. */
export function isSupportedCompression(compressionType: string | null): boolean {
  return compressionType === null || compressionType === AS4_COMPRESSION_TYPE;
}
