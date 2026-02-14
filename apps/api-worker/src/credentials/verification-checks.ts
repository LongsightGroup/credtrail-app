import type { JsonObject } from '@credtrail/core-domain';

export interface CredentialStatusListReference extends JsonObject {
  id: string;
  type: string;
  statusPurpose: 'revocation';
  statusListIndex: string;
  statusListCredential: string;
}

export interface CredentialVerificationCheckSummary {
  status: 'valid' | 'invalid' | 'unchecked';
  reason: string | null;
}

export interface CredentialDateVerificationCheckSummary extends CredentialVerificationCheckSummary {
  validFrom: string | null;
  validUntil: string | null;
}

export interface CredentialStatusVerificationCheckSummary extends CredentialVerificationCheckSummary {
  type: string | null;
  statusPurpose: string | null;
  statusListIndex: string | null;
  statusListCredential: string | null;
  revoked: boolean | null;
}

export interface CredentialVerificationChecksSummary {
  jsonLdSafeMode: CredentialVerificationCheckSummary;
  credentialSchema: CredentialVerificationCheckSummary;
  credentialSubject: CredentialVerificationCheckSummary;
  dates: CredentialDateVerificationCheckSummary;
  credentialStatus: CredentialStatusVerificationCheckSummary;
}

export interface CredentialLifecycleVerificationSummary {
  state: 'active' | 'expired' | 'revoked';
  reason: string | null;
  checkedAt: string;
  expiresAt: string | null;
  revokedAt: string | null;
}

export const VC_DATA_MODEL_CONTEXT_URL = 'https://www.w3.org/ns/credentials/v2';

const JSON_LD_KEYWORDS = new Set([
  '@base',
  '@container',
  '@context',
  '@direction',
  '@graph',
  '@id',
  '@import',
  '@included',
  '@index',
  '@json',
  '@language',
  '@list',
  '@nest',
  '@none',
  '@prefix',
  '@propagate',
  '@protected',
  '@reverse',
  '@set',
  '@type',
  '@value',
  '@version',
  '@vocab',
]);

const OB3_SAFE_MODE_KNOWN_TERMS = new Set([
  'id',
  'type',
  'name',
  'description',
  'issuer',
  'image',
  'narrative',
  'criteria',
  'alignment',
  'achievement',
  'achievementType',
  'awardedDate',
  'validFrom',
  'validUntil',
  'issuanceDate',
  'expirationDate',
  'credentialSubject',
  'credentialStatus',
  'credentialSchema',
  'proof',
  'proofPurpose',
  'proofValue',
  'verificationMethod',
  'cryptosuite',
  'created',
  'nonce',
  'challenge',
  'domain',
  'statusPurpose',
  'statusListIndex',
  'statusListCredential',
  'encodedList',
  'identifier',
  'identifierType',
  'result',
  'resultDescription',
  'resultType',
  'evidence',
  'url',
  'endorsement',
  'endorsementJwt',
  'subject',
]);

interface CreateCredentialVerificationChecksInput<ContextType> {
  asJsonObject: (value: unknown) => JsonObject | null;
  asNonEmptyString: (value: unknown) => string | null;
  loadJsonObjectFromUrl: (
    context: ContextType,
    resourceUrl: string,
    acceptHeader: string,
  ) => Promise<{ status: 'ok'; value: JsonObject } | { status: 'error'; reason: string }>;
  parseStatusListIndex: (value: string) => number | null;
  decodedRevocationStatusBit: (
    encodedList: string,
    statusListIndex: number,
  ) => Promise<boolean | null>;
}

export interface CredentialVerificationChecksHelpers<ContextType> {
  collectContextUrls: (value: unknown, output: string[]) => void;
  normalizedStringValues: (value: unknown) => string[];
  summarizeCredentialLifecycleVerification: (
    credential: JsonObject,
    revokedAt: string | null,
    checkedAt: string,
  ) => CredentialLifecycleVerificationSummary;
  summarizeCredentialVerificationChecks: (request: {
    context: ContextType;
    credential: JsonObject;
    checkedAt: string;
    expectedStatusList: CredentialStatusListReference | null;
  }) => Promise<CredentialVerificationChecksSummary>;
}

const parseTimestampMilliseconds = (value: string): number | null => {
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : parsed;
};

export const createCredentialVerificationChecks = <ContextType>(
  input: CreateCredentialVerificationChecksInput<ContextType>,
): CredentialVerificationChecksHelpers<ContextType> => {
  const expirationTimestampFromCredential = (credential: JsonObject): string | null => {
    return (
      input.asNonEmptyString(credential.validUntil) ?? input.asNonEmptyString(credential.expirationDate)
    );
  };

  const summarizeCredentialLifecycleVerification = (
    credential: JsonObject,
    revokedAt: string | null,
    checkedAt: string,
  ): CredentialLifecycleVerificationSummary => {
    const expiresAt = expirationTimestampFromCredential(credential);
    const checkedAtMilliseconds = parseTimestampMilliseconds(checkedAt) ?? Date.now();

    if (revokedAt !== null) {
      return {
        state: 'revoked',
        reason: 'credential has been revoked by issuer',
        checkedAt,
        expiresAt,
        revokedAt,
      };
    }

    if (expiresAt !== null) {
      const expiresAtMilliseconds = parseTimestampMilliseconds(expiresAt);

      if (expiresAtMilliseconds !== null && expiresAtMilliseconds <= checkedAtMilliseconds) {
        return {
          state: 'expired',
          reason: 'credential validUntil/expirationDate has passed',
          checkedAt,
          expiresAt,
          revokedAt: null,
        };
      }
    }

    return {
      state: 'active',
      reason: null,
      checkedAt,
      expiresAt,
      revokedAt: null,
    };
  };

  const collectContextUrls = (value: unknown, output: string[]): void => {
    const stringValue = input.asNonEmptyString(value);

    if (stringValue !== null) {
      output.push(stringValue);
      return;
    }

    if (!Array.isArray(value)) {
      return;
    }

    for (const entry of value) {
      collectContextUrls(entry, output);
    }
  };

  const collectInlineContextTerms = (value: unknown, terms: Set<string>): void => {
    if (Array.isArray(value)) {
      for (const entry of value) {
        collectInlineContextTerms(entry, terms);
      }
      return;
    }

    const contextObject = input.asJsonObject(value);

    if (contextObject === null) {
      return;
    }

    for (const key of Object.keys(contextObject)) {
      if (key.startsWith('@')) {
        continue;
      }

      const normalizedKey = key.trim();

      if (normalizedKey.length > 0) {
        terms.add(normalizedKey);
      }
    }
  };

  const collectUnknownJsonLdTerms = (
    value: unknown,
    path: string,
    knownTerms: ReadonlySet<string>,
    unknownTermPaths: string[],
  ): void => {
    if (Array.isArray(value)) {
      for (const [index, entry] of value.entries()) {
        collectUnknownJsonLdTerms(entry, `${path}[${String(index)}]`, knownTerms, unknownTermPaths);
      }
      return;
    }

    const valueObject = input.asJsonObject(value);

    if (valueObject === null) {
      return;
    }

    for (const [key, entryValue] of Object.entries(valueObject)) {
      if (key.startsWith('@')) {
        if (!JSON_LD_KEYWORDS.has(key)) {
          unknownTermPaths.push(`${path}.${key}`);
        }
      } else if (!key.includes(':') && !knownTerms.has(key)) {
        unknownTermPaths.push(`${path}.${key}`);
      }

      collectUnknownJsonLdTerms(entryValue, `${path}.${key}`, knownTerms, unknownTermPaths);
    }
  };

  const verifyCredentialJsonLdSafeModeSummary = (
    credential: JsonObject,
  ): CredentialVerificationCheckSummary => {
    const context = credential['@context'];

    if (context === undefined) {
      return {
        status: 'invalid',
        reason: 'credential is missing @context',
      };
    }

    const contextUrls: string[] = [];
    collectContextUrls(context, contextUrls);

    if (!contextUrls.includes(VC_DATA_MODEL_CONTEXT_URL)) {
      return {
        status: 'invalid',
        reason: 'credential @context must include https://www.w3.org/ns/credentials/v2',
      };
    }

    const knownTerms = new Set<string>(OB3_SAFE_MODE_KNOWN_TERMS);
    collectInlineContextTerms(context, knownTerms);

    const unknownTermPaths: string[] = [];
    collectUnknownJsonLdTerms(credential, '$', knownTerms, unknownTermPaths);

    if (unknownTermPaths.length > 0) {
      return {
        status: 'invalid',
        reason: `credential contains terms not defined by known JSON-LD context entries (${unknownTermPaths
          .slice(0, 3)
          .join(', ')})`,
      };
    }

    return {
      status: 'valid',
      reason: null,
    };
  };

  const normalizedStringValues = (value: unknown): string[] => {
    const singular = input.asNonEmptyString(value);

    if (singular !== null) {
      return [singular];
    }

    if (!Array.isArray(value)) {
      return [];
    }

    return value
      .map((entry) => input.asNonEmptyString(entry))
      .filter((entry): entry is string => entry !== null);
  };

  const schemaRequiredPropertyNames = (schemaObject: JsonObject): string[] => {
    const requiredValue = schemaObject.required;

    if (!Array.isArray(requiredValue)) {
      return [];
    }

    return requiredValue
      .map((entry) => input.asNonEmptyString(entry))
      .filter((entry): entry is string => entry !== null);
  };

  const verifyCredentialSchemaSummary = async (
    context: ContextType,
    credential: JsonObject,
  ): Promise<CredentialVerificationCheckSummary> => {
    const credentialSchemaValue = credential.credentialSchema;

    if (credentialSchemaValue === undefined) {
      return {
        status: 'unchecked',
        reason: null,
      };
    }

    const entries = Array.isArray(credentialSchemaValue)
      ? credentialSchemaValue
      : [credentialSchemaValue];

    if (entries.length === 0) {
      return {
        status: 'invalid',
        reason: 'credentialSchema must include at least one schema entry when present',
      };
    }

    let has1EdTechJsonSchemaValidator = false;

    for (const [index, entry] of entries.entries()) {
      const schemaEntry = input.asJsonObject(entry);

      if (schemaEntry === null) {
        return {
          status: 'invalid',
          reason: `credentialSchema[${String(index)}] must be a JSON object`,
        };
      }

      const schemaId = input.asNonEmptyString(schemaEntry.id);
      const schemaTypes = normalizedStringValues(schemaEntry.type);

      if (schemaId === null) {
        return {
          status: 'invalid',
          reason: `credentialSchema[${String(index)}] is missing a non-empty id`,
        };
      }

      if (schemaTypes.length === 0) {
        return {
          status: 'invalid',
          reason: `credentialSchema[${String(index)}] is missing a non-empty type`,
        };
      }

      if (schemaTypes.includes('1EdTechJsonSchemaValidator2019')) {
        has1EdTechJsonSchemaValidator = true;

        const loadedSchema = await input.loadJsonObjectFromUrl(
          context,
          schemaId,
          'application/schema+json, application/json',
        );

        if (loadedSchema.status !== 'ok') {
          return {
            status: 'invalid',
            reason: `credentialSchema[${String(index)}] schema could not be loaded (${loadedSchema.reason})`,
          };
        }

        const requiredPropertyNames = schemaRequiredPropertyNames(loadedSchema.value);
        const missingRequiredProperties = requiredPropertyNames.filter((propertyName) => {
          return !(propertyName in credential);
        });

        if (missingRequiredProperties.length > 0) {
          return {
            status: 'invalid',
            reason: `credential does not satisfy credentialSchema[${String(index)}] required properties (${missingRequiredProperties
              .slice(0, 3)
              .join(', ')})`,
          };
        }
      }
    }

    if (!has1EdTechJsonSchemaValidator) {
      return {
        status: 'invalid',
        reason: "credentialSchema must include a schema with type '1EdTechJsonSchemaValidator2019'",
      };
    }

    return {
      status: 'valid',
      reason: null,
    };
  };

  const hasCredentialSubjectIdentifier = (credentialSubject: JsonObject): boolean => {
    const identifierValue = credentialSubject.identifier;

    if (input.asNonEmptyString(identifierValue) !== null) {
      return true;
    }

    if (Array.isArray(identifierValue)) {
      return identifierValue.some((entry) => {
        const identifierEntryAsString = input.asNonEmptyString(entry);

        if (identifierEntryAsString !== null) {
          return true;
        }

        const identifierEntryAsObject = input.asJsonObject(entry);
        return input.asNonEmptyString(identifierEntryAsObject?.identifier) !== null;
      });
    }

    const identifierEntryAsObject = input.asJsonObject(identifierValue);
    return input.asNonEmptyString(identifierEntryAsObject?.identifier) !== null;
  };

  const verifyCredentialSubjectSummary = (
    credential: JsonObject,
  ): CredentialVerificationCheckSummary => {
    const credentialSubject = input.asJsonObject(credential.credentialSubject);

    if (credentialSubject === null) {
      return {
        status: 'invalid',
        reason: 'credentialSubject must be an object',
      };
    }

    const subjectId = input.asNonEmptyString(credentialSubject.id);
    const hasIdentifier = hasCredentialSubjectIdentifier(credentialSubject);

    if (subjectId === null && !hasIdentifier) {
      return {
        status: 'invalid',
        reason: 'credentialSubject must include id or at least one identifier',
      };
    }

    const credentialTypes = normalizedStringValues(credential.type);

    if (credentialTypes.includes('OpenBadgeCredential')) {
      const achievement = input.asJsonObject(credentialSubject.achievement);

      if (achievement === null) {
        return {
          status: 'invalid',
          reason: 'credentialSubject.achievement must be an object for OpenBadgeCredential',
        };
      }

      const achievementTypes = normalizedStringValues(achievement.type);

      if (!achievementTypes.includes('Achievement')) {
        return {
          status: 'invalid',
          reason:
            'credentialSubject.achievement.type must include Achievement for OpenBadgeCredential',
        };
      }
    }

    return {
      status: 'valid',
      reason: null,
    };
  };

  const validFromTimestampFromCredential = (credential: JsonObject): string | null => {
    return input.asNonEmptyString(credential.validFrom) ?? input.asNonEmptyString(credential.issuanceDate);
  };

  const verifyCredentialDatesSummary = (
    credential: JsonObject,
    checkedAt: string,
  ): CredentialDateVerificationCheckSummary => {
    const validFrom = validFromTimestampFromCredential(credential);
    const validUntil = expirationTimestampFromCredential(credential);

    if (validFrom === null) {
      return {
        status: 'invalid',
        reason: 'credential must include validFrom or issuanceDate',
        validFrom,
        validUntil,
      };
    }

    const validFromMilliseconds = parseTimestampMilliseconds(validFrom);

    if (validFromMilliseconds === null) {
      return {
        status: 'invalid',
        reason: 'credential validFrom/issuanceDate must be a valid ISO timestamp',
        validFrom,
        validUntil,
      };
    }

    const validUntilMilliseconds =
      validUntil === null ? null : parseTimestampMilliseconds(validUntil);

    if (validUntil !== null && validUntilMilliseconds === null) {
      return {
        status: 'invalid',
        reason: 'credential validUntil/expirationDate must be a valid ISO timestamp',
        validFrom,
        validUntil,
      };
    }

    if (validUntilMilliseconds !== null && validUntilMilliseconds < validFromMilliseconds) {
      return {
        status: 'invalid',
        reason:
          'credential validUntil/expirationDate must not be earlier than validFrom/issuanceDate',
        validFrom,
        validUntil,
      };
    }

    const checkedAtMilliseconds = parseTimestampMilliseconds(checkedAt) ?? Date.now();

    if (validFromMilliseconds > checkedAtMilliseconds) {
      return {
        status: 'invalid',
        reason: 'credential validFrom/issuanceDate is in the future',
        validFrom,
        validUntil,
      };
    }

    return {
      status: 'valid',
      reason: null,
      validFrom,
      validUntil,
    };
  };

  const loadStatusListCredentialForVerification = async (
    context: ContextType,
    statusListCredentialUrl: string,
  ): Promise<{ status: 'ok'; credential: JsonObject } | { status: 'error'; reason: string }> => {
    const loadedCredential = await input.loadJsonObjectFromUrl(
      context,
      statusListCredentialUrl,
      'application/ld+json, application/json',
    );

    if (loadedCredential.status !== 'ok') {
      return {
        status: 'error',
        reason: `credential status list could not be retrieved (${loadedCredential.reason})`,
      };
    }

    return {
      status: 'ok',
      credential: loadedCredential.value,
    };
  };

  const verifyCredentialStatusSummary = async (
    context: ContextType,
    credential: JsonObject,
    expectedStatusList: CredentialStatusListReference | null,
  ): Promise<CredentialStatusVerificationCheckSummary> => {
    const credentialStatus = credential.credentialStatus;

    if (credentialStatus === undefined) {
      return {
        status: expectedStatusList === null ? 'unchecked' : 'invalid',
        reason:
          expectedStatusList === null
            ? null
            : 'credentialStatus is required when revocation metadata is configured',
        type: null,
        statusPurpose: null,
        statusListIndex: null,
        statusListCredential: null,
        revoked: null,
      };
    }

    const credentialStatusObject = input.asJsonObject(credentialStatus);

    if (credentialStatusObject === null) {
      return {
        status: 'invalid',
        reason: 'credentialStatus must be a JSON object',
        type: null,
        statusPurpose: null,
        statusListIndex: null,
        statusListCredential: null,
        revoked: null,
      };
    }

    const statusType = input.asNonEmptyString(credentialStatusObject.type);
    const statusPurpose = input.asNonEmptyString(credentialStatusObject.statusPurpose);
    const statusListIndex = input.asNonEmptyString(credentialStatusObject.statusListIndex);
    const statusListCredential = input.asNonEmptyString(credentialStatusObject.statusListCredential);

    if (expectedStatusList === null) {
      return {
        status: 'invalid',
        reason: 'credentialStatus is present but no revocation metadata exists for this credential',
        type: statusType,
        statusPurpose,
        statusListIndex,
        statusListCredential,
        revoked: null,
      };
    }

    if (
      statusType === null ||
      statusListIndex === null ||
      statusListCredential === null ||
      (statusPurpose !== null && statusPurpose !== 'revocation')
    ) {
      return {
        status: 'invalid',
        reason: 'credentialStatus is missing required Bitstring status list fields',
        type: statusType,
        statusPurpose,
        statusListIndex,
        statusListCredential,
        revoked: null,
      };
    }

    if (statusType !== 'BitstringStatusListEntry' && statusType !== '1EdTechRevocationList') {
      return {
        status: 'invalid',
        reason: 'credentialStatus type must be BitstringStatusListEntry or 1EdTechRevocationList',
        type: statusType,
        statusPurpose,
        statusListIndex,
        statusListCredential,
        revoked: null,
      };
    }

    if (statusListIndex !== expectedStatusList.statusListIndex) {
      return {
        status: 'invalid',
        reason:
          'credentialStatus statusListIndex does not match the expected credential revocation index',
        type: statusType,
        statusPurpose,
        statusListIndex,
        statusListCredential,
        revoked: null,
      };
    }

    if (statusListCredential !== expectedStatusList.statusListCredential) {
      return {
        status: 'invalid',
        reason:
          'credentialStatus statusListCredential does not match the expected revocation list URL',
        type: statusType,
        statusPurpose,
        statusListIndex,
        statusListCredential,
        revoked: null,
      };
    }

    const normalizedStatusListIndex = input.parseStatusListIndex(statusListIndex);

    if (normalizedStatusListIndex === null) {
      return {
        status: 'invalid',
        reason: 'credentialStatus statusListIndex must be a non-negative integer string',
        type: statusType,
        statusPurpose,
        statusListIndex,
        statusListCredential,
        revoked: null,
      };
    }

    const statusListCredentialResult = await loadStatusListCredentialForVerification(
      context,
      statusListCredential,
    );

    if (statusListCredentialResult.status !== 'ok') {
      return {
        status: 'invalid',
        reason: statusListCredentialResult.reason,
        type: statusType,
        statusPurpose,
        statusListIndex,
        statusListCredential,
        revoked: null,
      };
    }

    const statusListCredentialSubject = input.asJsonObject(
      statusListCredentialResult.credential.credentialSubject,
    );
    const encodedList = input.asNonEmptyString(statusListCredentialSubject?.encodedList);

    if (encodedList === null) {
      return {
        status: 'invalid',
        reason: 'credential status list is missing credentialSubject.encodedList',
        type: statusType,
        statusPurpose,
        statusListIndex,
        statusListCredential,
        revoked: null,
      };
    }

    const revoked = await input.decodedRevocationStatusBit(encodedList, normalizedStatusListIndex);

    if (revoked === null) {
      return {
        status: 'invalid',
        reason:
          'credential status list encodedList could not be decoded for the specified statusListIndex',
        type: statusType,
        statusPurpose,
        statusListIndex,
        statusListCredential,
        revoked: null,
      };
    }

    return {
      status: 'valid',
      reason: null,
      type: statusType,
      statusPurpose: statusPurpose ?? 'revocation',
      statusListIndex,
      statusListCredential,
      revoked,
    };
  };

  const summarizeCredentialVerificationChecks = async (request: {
    context: ContextType;
    credential: JsonObject;
    checkedAt: string;
    expectedStatusList: CredentialStatusListReference | null;
  }): Promise<CredentialVerificationChecksSummary> => {
    return {
      jsonLdSafeMode: verifyCredentialJsonLdSafeModeSummary(request.credential),
      credentialSchema: await verifyCredentialSchemaSummary(request.context, request.credential),
      credentialSubject: verifyCredentialSubjectSummary(request.credential),
      dates: verifyCredentialDatesSummary(request.credential, request.checkedAt),
      credentialStatus: await verifyCredentialStatusSummary(
        request.context,
        request.credential,
        request.expectedStatusList,
      ),
    };
  };

  return {
    collectContextUrls,
    normalizedStringValues,
    summarizeCredentialLifecycleVerification,
    summarizeCredentialVerificationChecks,
  };
};
