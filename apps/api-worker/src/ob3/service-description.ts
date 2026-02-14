import type { JsonObject } from '@credtrail/core-domain';
import {
  OB3_BASE_PATH,
  OB3_OAUTH_SCOPE_CREDENTIAL_READONLY,
  OB3_OAUTH_SCOPE_CREDENTIAL_UPSERT,
  OB3_OAUTH_SCOPE_DESCRIPTIONS,
  OB3_OAUTH_SCOPE_PROFILE_READONLY,
  OB3_OAUTH_SCOPE_PROFILE_UPDATE,
} from './constants';

interface Ob3ServiceDescriptionInput {
  requestUrl: string;
  discoveryTitle?: string | undefined;
  termsOfServiceUrl?: string | undefined;
  privacyPolicyUrl?: string | undefined;
  imageUrl?: string | undefined;
  oauthRegistrationUrl?: string | undefined;
  oauthAuthorizationUrl?: string | undefined;
  oauthTokenUrl?: string | undefined;
  oauthRefreshUrl?: string | undefined;
}

const resolveAbsoluteUrl = (requestUrl: string, configuredValue: string): string => {
  const trimmedValue = configuredValue.trim();

  if (trimmedValue.length === 0) {
    throw new Error('Expected non-empty URL value');
  }

  return new URL(trimmedValue, requestUrl).toString();
};

export const ob3ServiceDescriptionDocument = (input: Ob3ServiceDescriptionInput): JsonObject => {
  const serverUrl = resolveAbsoluteUrl(input.requestUrl, OB3_BASE_PATH);
  const configuredTitle = input.discoveryTitle?.trim();
  const title =
    configuredTitle === undefined || configuredTitle.length === 0
      ? 'CredTrail Open Badges API'
      : configuredTitle;
  const termsOfService = resolveAbsoluteUrl(
    input.requestUrl,
    input.termsOfServiceUrl ?? '/terms',
  );
  const privacyPolicyUrl = resolveAbsoluteUrl(
    input.requestUrl,
    input.privacyPolicyUrl ?? '/privacy',
  );
  const imageUrl = resolveAbsoluteUrl(input.requestUrl, input.imageUrl ?? '/credtrail-logo.png');
  const registrationUrl = resolveAbsoluteUrl(
    input.requestUrl,
    input.oauthRegistrationUrl ?? `${OB3_BASE_PATH}/oauth/register`,
  );
  const authorizationUrl = resolveAbsoluteUrl(
    input.requestUrl,
    input.oauthAuthorizationUrl ?? `${OB3_BASE_PATH}/oauth/authorize`,
  );
  const tokenUrl = resolveAbsoluteUrl(
    input.requestUrl,
    input.oauthTokenUrl ?? `${OB3_BASE_PATH}/oauth/token`,
  );
  const refreshUrl = resolveAbsoluteUrl(
    input.requestUrl,
    input.oauthRefreshUrl ?? `${OB3_BASE_PATH}/oauth/refresh`,
  );

  return {
    openapi: '3.0.1',
    info: {
      title,
      description: 'Open Badges v3.0 Service Description Document',
      version: '3.0',
      termsOfService,
      'x-imssf-privacyPolicyUrl': privacyPolicyUrl,
      'x-imssf-image': imageUrl,
    },
    servers: [
      {
        url: serverUrl,
        description: 'Open Badges v3.0 service endpoint',
      },
    ],
    tags: [
      {
        name: 'OpenBadgeCredentials',
        description: 'Exchange OpenBadgeCredentials and Profile resources.',
      },
      {
        name: 'Discovery',
        description: 'Service Description Document metadata endpoint.',
      },
    ],
    paths: {
      '/credentials': {
        get: {
          tags: ['OpenBadgeCredentials'],
          summary: 'Get credentials for the authenticated entity.',
          operationId: 'getCredentials',
          responses: {
            200: {
              description: 'Credentials returned.',
            },
            default: {
              description: 'Request was invalid or cannot be served.',
            },
          },
          security: [
            {
              OAuth2ACG: [OB3_OAUTH_SCOPE_CREDENTIAL_READONLY],
            },
          ],
        },
        post: {
          tags: ['OpenBadgeCredentials'],
          summary: 'Create or update a credential for the authenticated entity.',
          operationId: 'upsertCredential',
          responses: {
            200: {
              description: 'Credential replaced.',
            },
            201: {
              description: 'Credential created.',
            },
            default: {
              description: 'Request was invalid or cannot be served.',
            },
          },
          security: [
            {
              OAuth2ACG: [OB3_OAUTH_SCOPE_CREDENTIAL_UPSERT],
            },
          ],
        },
      },
      '/profile': {
        get: {
          tags: ['OpenBadgeCredentials'],
          summary: 'Get profile for the authenticated entity.',
          operationId: 'getProfile',
          responses: {
            200: {
              description: 'Profile returned.',
            },
            default: {
              description: 'Request was invalid or cannot be served.',
            },
          },
          security: [
            {
              OAuth2ACG: [OB3_OAUTH_SCOPE_PROFILE_READONLY],
            },
          ],
        },
        put: {
          tags: ['OpenBadgeCredentials'],
          summary: 'Update profile for the authenticated entity.',
          operationId: 'putProfile',
          responses: {
            200: {
              description: 'Profile updated.',
            },
            default: {
              description: 'Request was invalid or cannot be served.',
            },
          },
          security: [
            {
              OAuth2ACG: [OB3_OAUTH_SCOPE_PROFILE_UPDATE],
            },
          ],
        },
      },
      '/discovery': {
        get: {
          tags: ['Discovery'],
          summary: 'Get the service description document.',
          operationId: 'getServiceDescription',
          responses: {
            200: {
              description: 'Service description document returned.',
            },
            default: {
              description: 'Request was invalid or cannot be served.',
            },
          },
        },
      },
    },
    components: {
      securitySchemes: {
        OAuth2ACG: {
          type: 'oauth2',
          'x-imssf-registrationUrl': registrationUrl,
          flows: {
            authorizationCode: {
              authorizationUrl,
              tokenUrl,
              refreshUrl,
              scopes: OB3_OAUTH_SCOPE_DESCRIPTIONS,
            },
          },
        },
      },
    },
  };
};
