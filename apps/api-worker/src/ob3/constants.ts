export const OAUTH_AUTHORIZATION_CODE_TTL_SECONDS = 5 * 60;
export const OAUTH_ACCESS_TOKEN_TTL_SECONDS = 60 * 60;
export const OAUTH_REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;

export const OB3_BASE_PATH = '/ims/ob/v3p0';
export const OB3_DISCOVERY_PATH = `${OB3_BASE_PATH}/discovery`;
export const OB3_OAUTH_SCOPE_CREDENTIAL_READONLY =
  'https://purl.imsglobal.org/spec/ob/v3p0/scope/credential.readonly';
export const OB3_OAUTH_SCOPE_CREDENTIAL_UPSERT =
  'https://purl.imsglobal.org/spec/ob/v3p0/scope/credential.upsert';
export const OB3_OAUTH_SCOPE_PROFILE_READONLY =
  'https://purl.imsglobal.org/spec/ob/v3p0/scope/profile.readonly';
export const OB3_OAUTH_SCOPE_PROFILE_UPDATE =
  'https://purl.imsglobal.org/spec/ob/v3p0/scope/profile.update';
export const OB3_OAUTH_SUPPORTED_SCOPE_URIS = [
  OB3_OAUTH_SCOPE_CREDENTIAL_READONLY,
  OB3_OAUTH_SCOPE_CREDENTIAL_UPSERT,
  OB3_OAUTH_SCOPE_PROFILE_READONLY,
  OB3_OAUTH_SCOPE_PROFILE_UPDATE,
] as const;
export const OB3_OAUTH_SUPPORTED_SCOPE_SET = new Set<string>(OB3_OAUTH_SUPPORTED_SCOPE_URIS);
export const OAUTH_GRANT_TYPE_AUTHORIZATION_CODE = 'authorization_code';
export const OAUTH_GRANT_TYPE_REFRESH_TOKEN = 'refresh_token';
export const OAUTH_RESPONSE_TYPE_CODE = 'code';
export const OAUTH_TOKEN_ENDPOINT_AUTH_METHOD_CLIENT_SECRET_BASIC = 'client_secret_basic';
export const OAUTH_TOKEN_TYPE_HINT_ACCESS_TOKEN = 'access_token';
export const OAUTH_TOKEN_TYPE_HINT_REFRESH_TOKEN = 'refresh_token';
export const OAUTH_PKCE_CODE_CHALLENGE_METHOD_S256 = 'S256';
export const OAUTH_PKCE_CODE_CHALLENGE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
export const OAUTH_PKCE_CODE_VERIFIER_PATTERN = /^[A-Za-z0-9._~-]{43,128}$/;
export const OB3_OAUTH_SCOPE_DESCRIPTIONS: Record<string, string> = {
  [OB3_OAUTH_SCOPE_CREDENTIAL_READONLY]:
    'Permission to read AchievementCredentials for the authenticated entity.',
  [OB3_OAUTH_SCOPE_CREDENTIAL_UPSERT]:
    'Permission to create or update AchievementCredentials for the authenticated entity.',
  [OB3_OAUTH_SCOPE_PROFILE_READONLY]:
    'Permission to read the profile for the authenticated entity.',
  [OB3_OAUTH_SCOPE_PROFILE_UPDATE]:
    'Permission to update the profile for the authenticated entity.',
};
export const OB3_DISCOVERY_CACHE_CONTROL = 'public, max-age=300';
