import type {
  LTIDynamicRegistrationSession,
  LTISession,
  OpenIDConfiguration,
} from "@lti-tool/core";
import { LTI13JwtPayloadSchema, LTI_CLAIM_PLATFORM_CONFIGURATION } from "@lti-tool/core";

const asRecord = (value: unknown): Record<string, unknown> | undefined => {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }

  return value as Record<string, unknown>;
};

const asString = (value: unknown): string | undefined => {
  return typeof value === "string" ? value : undefined;
};

const asBoolean = (value: unknown): boolean | undefined => {
  return typeof value === "boolean" ? value : undefined;
};

const asStringArray = (value: unknown): string[] | undefined => {
  if (!Array.isArray(value)) {
    return undefined;
  }

  return value.every((entry) => typeof entry === "string") ? value : undefined;
};

const asStringRecord = (value: unknown): Record<string, string> | undefined => {
  const record = asRecord(value);

  if (record === undefined) {
    return undefined;
  }

  const entries = Object.entries(record);

  if (!entries.every(([, entry]) => typeof entry === "string")) {
    return undefined;
  }

  return Object.fromEntries(entries) as Record<string, string>;
};

const optionalStringFieldIsValid = (record: Record<string, unknown>, key: string): boolean => {
  return !(key in record) || asString(record[key]) !== undefined;
};

const parseStoredJson = (dataJson: string): unknown => {
  try {
    return JSON.parse(dataJson) as unknown;
  } catch {
    return undefined;
  }
};

const parseLtiJwtPayload = (value: unknown): LTISession["jwtPayload"] | undefined => {
  const parsedPayload = LTI13JwtPayloadSchema.safeParse(value);

  if (!parsedPayload.success) {
    return undefined;
  }

  // SAFETY: LTI13JwtPayloadSchema validates the LTI launch claims, which are the JWT
  // payload shape stored on LTISession. The cast avoids exactOptionalPropertyTypes friction
  // between Zod optional output and jose's JWTPayload optional-field contract.
  return parsedPayload.data as LTISession["jwtPayload"];
};

const parseLtiSessionUser = (value: unknown): LTISession["user"] | undefined => {
  const user = asRecord(value);
  const id = asString(user?.id);
  const roles = asStringArray(user?.roles);

  if (
    user === undefined ||
    id === undefined ||
    roles === undefined ||
    !optionalStringFieldIsValid(user, "name") ||
    !optionalStringFieldIsValid(user, "email") ||
    !optionalStringFieldIsValid(user, "familyName") ||
    !optionalStringFieldIsValid(user, "givenName")
  ) {
    return undefined;
  }

  const name = asString(user.name);
  const email = asString(user.email);
  const familyName = asString(user.familyName);
  const givenName = asString(user.givenName);

  return {
    id,
    ...(name === undefined ? {} : { name }),
    ...(email === undefined ? {} : { email }),
    ...(familyName === undefined ? {} : { familyName }),
    ...(givenName === undefined ? {} : { givenName }),
    roles,
  };
};

const parseRequiredStringObject = <TKeys extends readonly string[]>(
  value: unknown,
  keys: TKeys,
): { [TKey in TKeys[number]]: string } | undefined => {
  const record = asRecord(value);

  if (record === undefined) {
    return undefined;
  }

  const parsedEntries = keys.map((key) => [key, asString(record[key])] as const);

  if (parsedEntries.some(([, entry]) => entry === undefined)) {
    return undefined;
  }

  return Object.fromEntries(parsedEntries) as { [TKey in TKeys[number]]: string };
};

const parseLtiSessionResourceLink = (value: unknown): LTISession["resourceLink"] | undefined => {
  const record = asRecord(value);
  const id = asString(record?.id);

  if (record === undefined || id === undefined || !optionalStringFieldIsValid(record, "title")) {
    return undefined;
  }

  const title = asString(record.title);

  return {
    id,
    ...(title === undefined ? {} : { title }),
  };
};

const parseLtiSessionServices = (value: unknown): LTISession["services"] | undefined => {
  const services = asRecord(value);

  if (services === undefined) {
    return undefined;
  }

  const parsed: NonNullable<LTISession["services"]> = {};

  if (services.ags !== undefined) {
    const ags = asRecord(services.ags);
    const scopes = asStringArray(ags?.scopes);

    if (
      ags === undefined ||
      scopes === undefined ||
      !optionalStringFieldIsValid(ags, "lineitem") ||
      !optionalStringFieldIsValid(ags, "lineitems")
    ) {
      return undefined;
    }

    const lineitem = asString(ags.lineitem);
    const lineitems = asString(ags.lineitems);

    parsed.ags = {
      ...(lineitem === undefined ? {} : { lineitem }),
      ...(lineitems === undefined ? {} : { lineitems }),
      scopes,
    };
  }

  if (services.nrps !== undefined) {
    const nrpsRecord = asRecord(services.nrps);
    const nrps = parseRequiredStringObject(services.nrps, ["membershipUrl"] as const);
    const versions = asStringArray(nrpsRecord?.versions);

    if (nrps === undefined || versions === undefined) {
      return undefined;
    }

    parsed.nrps = {
      membershipUrl: nrps.membershipUrl,
      versions,
    };
  }

  if (services.deepLinking !== undefined) {
    const deepLinking = parseRequiredStringObject(services.deepLinking, ["returnUrl"] as const);
    const deepLinkingRecord = asRecord(services.deepLinking);
    const acceptTypes = asStringArray(deepLinkingRecord?.acceptTypes);
    const acceptPresentationDocumentTargets = asStringArray(
      deepLinkingRecord?.acceptPresentationDocumentTargets,
    );
    const acceptMultiple = asBoolean(deepLinkingRecord?.acceptMultiple);
    const autoCreate = asBoolean(deepLinkingRecord?.autoCreate);

    if (
      deepLinking === undefined ||
      deepLinkingRecord === undefined ||
      acceptTypes === undefined ||
      acceptPresentationDocumentTargets === undefined ||
      acceptMultiple === undefined ||
      autoCreate === undefined ||
      !optionalStringFieldIsValid(deepLinkingRecord, "acceptMediaTypes") ||
      !optionalStringFieldIsValid(deepLinkingRecord, "data")
    ) {
      return undefined;
    }

    const acceptMediaTypes = asString(deepLinkingRecord.acceptMediaTypes);
    const data = asString(deepLinkingRecord.data);

    parsed.deepLinking = {
      returnUrl: deepLinking.returnUrl,
      acceptTypes,
      acceptPresentationDocumentTargets,
      ...(acceptMediaTypes === undefined ? {} : { acceptMediaTypes }),
      acceptMultiple,
      autoCreate,
      ...(data === undefined ? {} : { data }),
    };
  }

  return parsed;
};

export const parsePersistedLtiSession = (dataJson: string): LTISession | undefined => {
  const parsedJson = parseStoredJson(dataJson);
  const session = asRecord(parsedJson);

  if (session === undefined) {
    return undefined;
  }

  const jwtPayload = parseLtiJwtPayload(session.jwtPayload);
  const id = asString(session.id);
  const user = parseLtiSessionUser(session.user);
  const context = parseRequiredStringObject(session.context, ["id", "label", "title"] as const);
  const platform = parseRequiredStringObject(session.platform, [
    "issuer",
    "clientId",
    "deploymentId",
    "name",
  ] as const);
  const launch = parseRequiredStringObject(session.launch, ["target"] as const);
  const resourceLink =
    session.resourceLink === undefined
      ? undefined
      : parseLtiSessionResourceLink(session.resourceLink);
  const services =
    session.services === undefined ? undefined : parseLtiSessionServices(session.services);
  const customParameters = asStringRecord(session.customParameters);
  const isAdmin = asBoolean(session.isAdmin);
  const isInstructor = asBoolean(session.isInstructor);
  const isStudent = asBoolean(session.isStudent);
  const isAssignmentAndGradesAvailable = asBoolean(session.isAssignmentAndGradesAvailable);
  const isDeepLinkingAvailable = asBoolean(session.isDeepLinkingAvailable);
  const isNameAndRolesAvailable = asBoolean(session.isNameAndRolesAvailable);

  if (
    jwtPayload === undefined ||
    id === undefined ||
    user === undefined ||
    context === undefined ||
    platform === undefined ||
    launch === undefined ||
    (session.resourceLink !== undefined && resourceLink === undefined) ||
    (session.services !== undefined && services === undefined) ||
    customParameters === undefined ||
    isAdmin === undefined ||
    isInstructor === undefined ||
    isStudent === undefined ||
    isAssignmentAndGradesAvailable === undefined ||
    isDeepLinkingAvailable === undefined ||
    isNameAndRolesAvailable === undefined
  ) {
    return undefined;
  }

  return {
    jwtPayload,
    id,
    user,
    context,
    platform,
    launch,
    ...(resourceLink === undefined ? {} : { resourceLink }),
    ...(services === undefined ? {} : { services }),
    customParameters,
    isAdmin,
    isInstructor,
    isStudent,
    isAssignmentAndGradesAvailable,
    isDeepLinkingAvailable,
    isNameAndRolesAvailable,
  };
};

const isAbsoluteUrlString = (value: unknown): value is string => {
  if (typeof value !== "string") {
    return false;
  }

  try {
    new URL(value);
    return true;
  } catch {
    return false;
  }
};

const parseOpenIdConfiguration = (value: unknown): OpenIDConfiguration | undefined => {
  const configuration = asRecord(value);
  const platformConfiguration = asRecord(configuration?.[LTI_CLAIM_PLATFORM_CONFIGURATION]);
  const messagesSupported = platformConfiguration?.messages_supported;

  if (
    configuration === undefined ||
    !isAbsoluteUrlString(configuration.issuer) ||
    !isAbsoluteUrlString(configuration.authorization_endpoint) ||
    !isAbsoluteUrlString(configuration.registration_endpoint) ||
    !isAbsoluteUrlString(configuration.jwks_uri) ||
    !isAbsoluteUrlString(configuration.token_endpoint) ||
    asStringArray(configuration.token_endpoint_auth_methods_supported) === undefined ||
    asStringArray(configuration.token_endpoint_auth_signing_alg_values_supported) === undefined ||
    asStringArray(configuration.scopes_supported) === undefined ||
    asStringArray(configuration.response_types_supported) === undefined ||
    asStringArray(configuration.id_token_signing_alg_values_supported) === undefined ||
    asStringArray(configuration.claims_supported) === undefined ||
    asStringArray(configuration.subject_types_supported) === undefined ||
    (configuration.authorization_server !== undefined &&
      asString(configuration.authorization_server) === undefined) ||
    platformConfiguration === undefined ||
    asString(platformConfiguration.product_family_code) === undefined ||
    asString(platformConfiguration.version) === undefined ||
    !Array.isArray(messagesSupported) ||
    !messagesSupported.every((message) => asString(asRecord(message)?.type) !== undefined) ||
    (platformConfiguration.variables !== undefined &&
      asStringArray(platformConfiguration.variables) === undefined)
  ) {
    return undefined;
  }

  // SAFETY: The checks above validate every required OpenIDConfiguration field used by
  // @lti-tool/core while preserving any loose provider-specific discovery fields.
  return configuration as OpenIDConfiguration;
};

export const parsePersistedLtiDynamicRegistrationSession = (
  dataJson: string,
): LTIDynamicRegistrationSession | undefined => {
  const parsedJson = parseStoredJson(dataJson);
  const session = asRecord(parsedJson);

  if (session === undefined) {
    return undefined;
  }

  const openIdConfiguration = parseOpenIdConfiguration(session.openIdConfiguration);
  const registrationToken = asString(session.registrationToken);
  const expiresAt = session.expiresAt;

  if (
    openIdConfiguration === undefined ||
    ("registrationToken" in session && registrationToken === undefined) ||
    typeof expiresAt !== "number"
  ) {
    return undefined;
  }

  return {
    openIdConfiguration,
    ...(registrationToken === undefined ? {} : { registrationToken }),
    expiresAt,
  };
};
