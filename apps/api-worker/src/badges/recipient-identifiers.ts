import type {
  RecipientIdentifierInput,
  RecipientIdentifierType,
} from '@credtrail/db';
import type { ManualIssueBadgeRequest } from '@credtrail/validation';

export type DirectIssueBadgeRequest = Pick<
  ManualIssueBadgeRequest,
  | 'badgeTemplateId'
  | 'recipientIdentity'
  | 'recipientIdentityType'
  | 'recipientIdentifiers'
  | 'idempotencyKey'
>;

const normalizeRecipientIdentifierValue = (
  identifierType: RecipientIdentifierType,
  identifierValue: string,
): string => {
  const trimmedValue = identifierValue.trim();

  if (identifierType === 'emailAddress') {
    return trimmedValue.toLowerCase();
  }

  return trimmedValue;
};

const toDbRecipientIdentifierInput = (entry: {
  identifierType: RecipientIdentifierType;
  identifier: string;
}): RecipientIdentifierInput | null => {
  const normalizedValue = normalizeRecipientIdentifierValue(entry.identifierType, entry.identifier);

  if (normalizedValue.length === 0) {
    return null;
  }

  return {
    identifierType: entry.identifierType,
    identifierValue: normalizedValue,
  };
};

const uniqueRecipientIdentifierInputs = (
  entries: readonly RecipientIdentifierInput[],
): RecipientIdentifierInput[] => {
  const seen = new Set<string>();
  const uniqueEntries: RecipientIdentifierInput[] = [];

  for (const entry of entries) {
    const normalizedValue = normalizeRecipientIdentifierValue(
      entry.identifierType,
      entry.identifierValue,
    );

    if (normalizedValue.length === 0) {
      continue;
    }

    const dedupeKey = entry.identifierType + '::' + normalizedValue;

    if (seen.has(dedupeKey)) {
      continue;
    }

    seen.add(dedupeKey);
    uniqueEntries.push({
      identifierType: entry.identifierType,
      identifierValue: normalizedValue,
    });
  }

  return uniqueEntries;
};

const recipientIdentifiersFromIdentityAliases = (
  identityType: 'email' | 'email_sha256' | 'did' | 'url' | 'saml_subject' | 'sourced_id',
  identityValue: string,
): RecipientIdentifierInput | null => {
  switch (identityType) {
    case 'email':
      return toDbRecipientIdentifierInput({
        identifierType: 'emailAddress',
        identifier: identityValue,
      });
    case 'did':
      return toDbRecipientIdentifierInput({
        identifierType: 'did',
        identifier: identityValue,
      });
    case 'sourced_id':
      return toDbRecipientIdentifierInput({
        identifierType: 'sourcedId',
        identifier: identityValue,
      });
    case 'email_sha256':
    case 'url':
    case 'saml_subject':
      return null;
  }
};

export const recipientIdentifiersForIssueRequest = (
  request: DirectIssueBadgeRequest,
  learnerProfileId: string,
  learnerIdentities: readonly {
    identityType: 'email' | 'email_sha256' | 'did' | 'url' | 'saml_subject' | 'sourced_id';
    identityValue: string;
  }[],
): RecipientIdentifierInput[] => {
  const entries: RecipientIdentifierInput[] = [];

  const stableLearnerIdentifier = toDbRecipientIdentifierInput({
    identifierType: 'studentId',
    identifier: learnerProfileId,
  });

  if (stableLearnerIdentifier !== null) {
    entries.push(stableLearnerIdentifier);
  }

  const requestPrimaryIdentifierType =
    request.recipientIdentityType === 'email'
      ? 'emailAddress'
      : request.recipientIdentityType === 'did'
        ? 'did'
        : null;

  if (requestPrimaryIdentifierType !== null) {
    const requestPrimaryIdentifier = toDbRecipientIdentifierInput({
      identifierType: requestPrimaryIdentifierType,
      identifier: request.recipientIdentity,
    });

    if (requestPrimaryIdentifier !== null) {
      entries.push(requestPrimaryIdentifier);
    }
  }

  for (const identity of learnerIdentities) {
    const mappedIdentifier = recipientIdentifiersFromIdentityAliases(
      identity.identityType,
      identity.identityValue,
    );

    if (mappedIdentifier !== null) {
      entries.push(mappedIdentifier);
    }
  }

  for (const requestIdentifier of request.recipientIdentifiers ?? []) {
    const mappedRequestIdentifier = toDbRecipientIdentifierInput({
      identifierType: requestIdentifier.identifierType,
      identifier: requestIdentifier.identifier,
    });

    if (mappedRequestIdentifier !== null) {
      entries.push(mappedRequestIdentifier);
    }
  }

  return uniqueRecipientIdentifierInputs(entries);
};
