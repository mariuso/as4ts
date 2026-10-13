import { AS4_COMPRESSION_TYPE, EBMS_NS } from '../constants.js';
import type { Profile, ScopedId } from '../types.js';
import type { InboundFailureReason } from './types.js';

/**
 * Read the ebMS headers of an inbound `UserMessage` and check them against the
 * profile (Phase 3). The structure is established by cardinality (exactly one
 * UserMessage, PartyInfo, Service, PartInfo, ...), never by "the first match",
 * and the AP identifier type is fixed by the profile. A message that does not
 * match is rejected with `addressing.*`.
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
  readonly originalSender: ScopedId;
  readonly finalRecipient: ScopedId;
  readonly compressionType: string | null;
  readonly partHref: string;
}

function directChildren(node: Element | null | undefined, ns: string, localName: string): Element[] {
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

function exactly(node: Element | null | undefined, ns: string, localName: string, what: string): Element {
  const matches = directChildren(node, ns, localName);
  if (matches.length === 0) throw new AddressingFault('addressing.unsupported', `missing ${what}`);
  if (matches.length > 1) throw new AddressingFault('addressing.unsupported', `more than one ${what}`);
  return matches[0]!;
}

function atMostOne(node: Element | null | undefined, ns: string, localName: string, what: string): Element | null {
  const matches = directChildren(node, ns, localName);
  if (matches.length > 1) throw new AddressingFault('addressing.unsupported', `more than one ${what}`);
  return matches[0] ?? null;
}

function text(element: Element | null): string | null {
  const value = element?.textContent;
  return value === null || value === undefined || value === '' ? null : value;
}

function requiredText(node: Element | null | undefined, ns: string, localName: string, what: string): string {
  const value = text(exactly(node, ns, localName, what));
  if (value === null) throw new AddressingFault('addressing.unsupported', `empty ${what}`);
  return value;
}

/** The named properties of an eb:MessageProperties/PartProperties, requiring uniqueness. */
function namedProperties(properties: Element | null | undefined, what: string): Map<string, Element> {
  const map = new Map<string, Element>();
  for (const property of directChildren(properties, EBMS_NS, 'Property')) {
    const name = property.getAttribute('name');
    if (!name) throw new AddressingFault('addressing.unsupported', `a ${what} Property has no name`);
    if (map.has(name)) throw new AddressingFault('addressing.unsupported', `duplicate ${what} Property ${name}`);
    map.set(name, property);
  }
  return map;
}

export function readUserMessage(envelope: Document, profile: Profile): UserMessageFacts {
  const root = envelope.documentElement;
  const soapNamespace = root.namespaceURI ?? '';
  const header = exactly(root, soapNamespace, 'Header', 'SOAP Header');
  const messaging = exactly(header, EBMS_NS, 'Messaging', 'eb:Messaging');
  const userMessage = exactly(messaging, EBMS_NS, 'UserMessage', 'eb:UserMessage');

  const messageInfo = exactly(userMessage, EBMS_NS, 'MessageInfo', 'MessageInfo');
  const messageId = requiredText(messageInfo, EBMS_NS, 'MessageId', 'MessageId');
  const timestamp = requiredText(messageInfo, EBMS_NS, 'Timestamp', 'Timestamp');

  const partyInfo = exactly(userMessage, EBMS_NS, 'PartyInfo', 'PartyInfo');
  const from = exactly(partyInfo, EBMS_NS, 'From', 'From');
  const to = exactly(partyInfo, EBMS_NS, 'To', 'To');
  const fromPartyIdElement = exactly(from, EBMS_NS, 'PartyId', 'From/PartyId');
  const toPartyIdElement = exactly(to, EBMS_NS, 'PartyId', 'To/PartyId');
  // Peppol fixes the access point identifier type.
  for (const [element, what] of [
    [fromPartyIdElement, 'From/PartyId'],
    [toPartyIdElement, 'To/PartyId'],
  ] as const) {
    if (element.getAttribute('type') !== profile.partyIdType) {
      throw new AddressingFault('addressing.unsupported', `${what} type is not the profile party id type`);
    }
  }
  const fromPartyId = text(fromPartyIdElement);
  const toPartyId = text(toPartyIdElement);
  if (fromPartyId === null || toPartyId === null) {
    throw new AddressingFault('addressing.unsupported', 'empty PartyId');
  }
  if (text(exactly(from, EBMS_NS, 'Role', 'From/Role')) !== profile.initiatorRole) {
    throw new AddressingFault('addressing.unsupported', 'From/Role is not the initiator role');
  }
  if (text(exactly(to, EBMS_NS, 'Role', 'To/Role')) !== profile.responderRole) {
    throw new AddressingFault('addressing.unsupported', 'To/Role is not the responder role');
  }

  const collaboration = exactly(userMessage, EBMS_NS, 'CollaborationInfo', 'CollaborationInfo');
  const serviceElement = exactly(collaboration, EBMS_NS, 'Service', 'CollaborationInfo/Service');
  const serviceScheme = serviceElement.getAttribute('type');
  const serviceValue = text(serviceElement);
  if (!serviceScheme || !serviceValue) {
    throw new AddressingFault('addressing.unsupported', 'missing CollaborationInfo/Service');
  }
  const action = requiredText(collaboration, EBMS_NS, 'Action', 'CollaborationInfo/Action');
  const agreement = text(atMostOne(collaboration, EBMS_NS, 'AgreementRef', 'AgreementRef'));
  if (agreement !== null && agreement !== profile.agreementRef) {
    throw new AddressingFault('addressing.unsupported', 'AgreementRef is not the profile agreement');
  }
  const conversationId = text(atMostOne(collaboration, EBMS_NS, 'ConversationId', 'ConversationId'));

  const mpc = userMessage.getAttribute('mpc');
  if (mpc !== null && mpc !== '' && mpc !== profile.mpc) {
    throw new AddressingFault('addressing.mpc', `unsupported MPC ${mpc}`);
  }

  const properties = namedProperties(
    exactly(userMessage, EBMS_NS, 'MessageProperties', 'MessageProperties'),
    'Message',
  );
  const originalSenderElement = properties.get('originalSender');
  const finalRecipientElement = properties.get('finalRecipient');
  if (!originalSenderElement || !finalRecipientElement) {
    throw new AddressingFault('addressing.unsupported', 'missing originalSender or finalRecipient property');
  }
  const originalSender = participantProperty(originalSenderElement, 'originalSender');
  const finalRecipient = participantProperty(finalRecipientElement, 'finalRecipient');

  const payloadInfo = exactly(userMessage, EBMS_NS, 'PayloadInfo', 'PayloadInfo');
  const partInfo = exactly(payloadInfo, EBMS_NS, 'PartInfo', 'PayloadInfo/PartInfo');
  const partHref = partInfo.getAttribute('href');
  if (!partHref) throw new AddressingFault('addressing.unsupported', 'missing PayloadInfo/PartInfo href');
  const partProperties = atMostOne(partInfo, EBMS_NS, 'PartProperties', 'PartProperties');
  const compressionType = partProperties
    ? text(namedProperties(partProperties, 'Part').get('CompressionType') ?? null)
    : null;

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

function participantProperty(property: Element, what: string): ScopedId {
  const scheme = property.getAttribute('type');
  const value = text(property);
  if (!scheme || value === null) {
    throw new AddressingFault('addressing.unsupported', `${what} property has no type or value`);
  }
  return { scheme, value };
}

/** Whether a compression declaration is supported by the constrained profile. */
export function isSupportedCompression(compressionType: string | null): boolean {
  return compressionType === null || compressionType === AS4_COMPRESSION_TYPE;
}
