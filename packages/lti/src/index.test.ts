import { describe, expect, it } from 'vitest';

import {
  LTI_CLAIM_DEPLOYMENT_ID,
  LTI_CLAIM_LIS,
  LTI_CLAIM_MESSAGE_TYPE,
  LTI_CLAIM_ROLES,
  LTI_CLAIM_VERSION,
  LTI_MESSAGE_TYPE_RESOURCE_LINK_REQUEST,
  parseLtiLaunchClaims,
  parseLtiOidcLoginInitiationRequest,
  resolveLtiRoleKind,
} from './index';

describe('parseLtiOidcLoginInitiationRequest', () => {
  it('parses required OIDC login initiation parameters', () => {
    const parsed = parseLtiOidcLoginInitiationRequest({
      iss: 'https://canvas.example.edu',
      login_hint: 'opaque-login-hint',
      target_link_uri: 'https://tool.example.edu/v1/lti/launch',
    });

    expect(parsed.iss).toBe('https://canvas.example.edu');
    expect(parsed.login_hint).toBe('opaque-login-hint');
    expect(parsed.target_link_uri).toBe('https://tool.example.edu/v1/lti/launch');
  });

  it('rejects payloads that omit required fields', () => {
    expect(() =>
      parseLtiOidcLoginInitiationRequest({
        iss: 'https://canvas.example.edu',
        target_link_uri: 'https://tool.example.edu/v1/lti/launch',
      }),
    ).toThrow();
  });
});

describe('parseLtiLaunchClaims', () => {
  it('parses a valid LTI 1.3 launch claims payload', () => {
    const parsed = parseLtiLaunchClaims({
      iss: 'https://canvas.example.edu',
      sub: 'user-123',
      aud: 'client-123',
      exp: 1_800_000_000,
      iat: 1_700_000_000,
      nonce: 'nonce-123',
      [LTI_CLAIM_DEPLOYMENT_ID]: 'deployment-123',
      [LTI_CLAIM_MESSAGE_TYPE]: LTI_MESSAGE_TYPE_RESOURCE_LINK_REQUEST,
      [LTI_CLAIM_VERSION]: '1.3.0',
      [LTI_CLAIM_ROLES]: ['http://purl.imsglobal.org/vocab/lis/v2/membership#Learner'],
      [LTI_CLAIM_LIS]: {
        person_sourcedid: 'student-sourced-id-123',
      },
    });

    expect(parsed[LTI_CLAIM_DEPLOYMENT_ID]).toBe('deployment-123');
    expect(parsed[LTI_CLAIM_MESSAGE_TYPE]).toBe('LtiResourceLinkRequest');
    expect(parsed[LTI_CLAIM_VERSION]).toBe('1.3.0');
    expect(parsed[LTI_CLAIM_LIS]?.person_sourcedid).toBe('student-sourced-id-123');
  });

  it('rejects unsupported LTI version values', () => {
    expect(() =>
      parseLtiLaunchClaims({
        iss: 'https://canvas.example.edu',
        sub: 'user-123',
        aud: 'client-123',
        exp: 1_800_000_000,
        iat: 1_700_000_000,
        nonce: 'nonce-123',
        [LTI_CLAIM_DEPLOYMENT_ID]: 'deployment-123',
        [LTI_CLAIM_MESSAGE_TYPE]: LTI_MESSAGE_TYPE_RESOURCE_LINK_REQUEST,
        [LTI_CLAIM_VERSION]: '1.2.0',
      }),
    ).toThrow();
  });
});

describe('resolveLtiRoleKind', () => {
  it('returns instructor when instructor role is present', () => {
    const role = resolveLtiRoleKind(
      parseLtiLaunchClaims({
        iss: 'https://canvas.example.edu',
        sub: 'user-123',
        aud: 'client-123',
        exp: 1_800_000_000,
        iat: 1_700_000_000,
        nonce: 'nonce-123',
        [LTI_CLAIM_DEPLOYMENT_ID]: 'deployment-123',
        [LTI_CLAIM_MESSAGE_TYPE]: LTI_MESSAGE_TYPE_RESOURCE_LINK_REQUEST,
        [LTI_CLAIM_VERSION]: '1.3.0',
        [LTI_CLAIM_ROLES]: ['http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor'],
      }),
    );

    expect(role).toBe('instructor');
  });

  it('returns learner when learner role is present', () => {
    const role = resolveLtiRoleKind(
      parseLtiLaunchClaims({
        iss: 'https://canvas.example.edu',
        sub: 'user-123',
        aud: 'client-123',
        exp: 1_800_000_000,
        iat: 1_700_000_000,
        nonce: 'nonce-123',
        [LTI_CLAIM_DEPLOYMENT_ID]: 'deployment-123',
        [LTI_CLAIM_MESSAGE_TYPE]: LTI_MESSAGE_TYPE_RESOURCE_LINK_REQUEST,
        [LTI_CLAIM_VERSION]: '1.3.0',
        [LTI_CLAIM_ROLES]: ['http://purl.imsglobal.org/vocab/lis/v2/membership#Learner'],
      }),
    );

    expect(role).toBe('learner');
  });
});
