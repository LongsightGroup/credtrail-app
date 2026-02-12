import { z } from 'zod';

export const LTI_CLAIM_MESSAGE_TYPE = 'https://purl.imsglobal.org/spec/lti/claim/message_type';
export const LTI_CLAIM_VERSION = 'https://purl.imsglobal.org/spec/lti/claim/version';
export const LTI_CLAIM_DEPLOYMENT_ID = 'https://purl.imsglobal.org/spec/lti/claim/deployment_id';
export const LTI_CLAIM_TARGET_LINK_URI = 'https://purl.imsglobal.org/spec/lti/claim/target_link_uri';
export const LTI_CLAIM_ROLES = 'https://purl.imsglobal.org/spec/lti/claim/roles';
export const LTI_CLAIM_RESOURCE_LINK = 'https://purl.imsglobal.org/spec/lti/claim/resource_link';
export const LTI_CLAIM_CONTEXT = 'https://purl.imsglobal.org/spec/lti/claim/context';
export const LTI_CLAIM_LIS = 'https://purl.imsglobal.org/spec/lti/claim/lis';

export const LTI_MESSAGE_TYPE_RESOURCE_LINK_REQUEST = 'LtiResourceLinkRequest';
export const LTI_MESSAGE_TYPE_DEEP_LINKING_REQUEST = 'LtiDeepLinkingRequest';
export const LTI_VERSION_1P3P0 = '1.3.0';

export const ltiOidcLoginInitiationRequestSchema = z.object({
  iss: z.string().url(),
  login_hint: z.string().min(1),
  target_link_uri: z.string().url(),
  client_id: z.string().min(1).optional(),
  lti_message_hint: z.string().min(1).optional(),
  lti_deployment_id: z.string().min(1).optional(),
});

const ltiResourceLinkClaimSchema = z
  .object({
    id: z.string().min(1),
    title: z.string().min(1).optional(),
    description: z.string().min(1).optional(),
  })
  .passthrough();

const ltiContextClaimSchema = z
  .object({
    id: z.string().min(1).optional(),
    label: z.string().min(1).optional(),
    title: z.string().min(1).optional(),
    type: z.array(z.string().min(1)).optional(),
  })
  .passthrough();

const ltiLisClaimSchema = z
  .object({
    person_sourcedid: z.string().min(1).optional(),
    course_section_sourcedid: z.string().min(1).optional(),
  })
  .passthrough();

export const ltiLaunchClaimsSchema = z
  .object({
    iss: z.string().url(),
    sub: z.string().min(1),
    aud: z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]),
    exp: z.number().int().positive(),
    iat: z.number().int().positive(),
    nonce: z.string().min(1),
    [LTI_CLAIM_DEPLOYMENT_ID]: z.string().min(1),
    [LTI_CLAIM_MESSAGE_TYPE]: z.string().min(1),
    [LTI_CLAIM_VERSION]: z.literal(LTI_VERSION_1P3P0),
    [LTI_CLAIM_TARGET_LINK_URI]: z.string().url().optional(),
    [LTI_CLAIM_ROLES]: z.array(z.string().min(1)).default([]),
    [LTI_CLAIM_RESOURCE_LINK]: ltiResourceLinkClaimSchema.optional(),
    [LTI_CLAIM_CONTEXT]: ltiContextClaimSchema.optional(),
    [LTI_CLAIM_LIS]: ltiLisClaimSchema.optional(),
  })
  .passthrough();

const INSTRUCTOR_ROLE_URIS = new Set<string>([
  'http://purl.imsglobal.org/vocab/lis/v2/membership#instructor',
  'http://purl.imsglobal.org/vocab/lis/v2/membership#teachingassistant',
  'http://purl.imsglobal.org/vocab/lis/v2/membership#contentdeveloper',
  'http://purl.imsglobal.org/vocab/lis/v2/institution/person#administrator',
  'http://purl.imsglobal.org/vocab/lis/v2/institution/person#faculty',
]);

const LEARNER_ROLE_URIS = new Set<string>([
  'http://purl.imsglobal.org/vocab/lis/v2/membership#learner',
  'http://purl.imsglobal.org/vocab/lis/v2/membership#student',
]);

export type LtiOidcLoginInitiationRequest = z.infer<typeof ltiOidcLoginInitiationRequestSchema>;
export type LtiLaunchClaims = z.infer<typeof ltiLaunchClaimsSchema>;
export type LtiRoleKind = 'instructor' | 'learner' | 'unknown';

export const parseLtiOidcLoginInitiationRequest = (
  input: unknown,
): LtiOidcLoginInitiationRequest => {
  return ltiOidcLoginInitiationRequestSchema.parse(input);
};

export const parseLtiLaunchClaims = (input: unknown): LtiLaunchClaims => {
  return ltiLaunchClaimsSchema.parse(input);
};

export const resolveLtiRoleKind = (claims: LtiLaunchClaims): LtiRoleKind => {
  const normalizedRoles = claims[LTI_CLAIM_ROLES].map((role) => role.trim().toLowerCase());

  if (normalizedRoles.some((role) => INSTRUCTOR_ROLE_URIS.has(role))) {
    return 'instructor';
  }

  if (normalizedRoles.some((role) => LEARNER_ROLE_URIS.has(role))) {
    return 'learner';
  }

  return 'unknown';
};
