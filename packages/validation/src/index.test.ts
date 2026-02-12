import { describe, expect, it } from 'vitest';

import {
  parseAdminDeleteLtiIssuerRegistrationRequest,
  parseAdminUpsertLtiIssuerRegistrationRequest,
  parseAdminUpsertTenantSigningRegistrationRequest,
  parseAdminUpsertTenantMembershipRoleRequest,
  parseBadgeTemplateListQuery,
  parseBadgeTemplatePathParams,
  parseCredentialPathParams,
  parseCreateBadgeTemplateRequest,
  parseIssueBadgeRequest,
  parseIssueSakaiCommitBadgeRequest,
  parseManualIssueBadgeRequest,
  parseLearnerIdentityLinkRequest,
  parseLearnerIdentityLinkVerifyRequest,
  parseMagicLinkRequest,
  parseMagicLinkVerifyRequest,
  parseProcessQueueRequest,
  parseQueueJob,
  parseRevokeBadgeRequest,
  parseSignCredentialRequest,
  parseTenantUserPathParams,
  parseTenantSigningRegistry,
  parseUpdateBadgeTemplateRequest,
} from './index';

describe('parseQueueJob', () => {
  it('accepts a valid issue_badge queue payload', () => {
    const job = parseQueueJob({
      jobType: 'issue_badge',
      tenantId: 'tenant_123',
      payload: {
        assertionId: 'assertion_456',
        badgeTemplateId: 'badge_template_001',
        recipientIdentity: 'learner@example.edu',
        recipientIdentityType: 'email',
        requestedAt: '2026-02-10T15:00:00.000Z',
      },
      idempotencyKey: 'idem_abc',
    });

    expect(job.jobType).toBe('issue_badge');
  });

  it('accepts issue_badge queue payload with recipient identifiers', () => {
    const job = parseQueueJob({
      jobType: 'issue_badge',
      tenantId: 'tenant_123',
      payload: {
        assertionId: 'assertion_456',
        badgeTemplateId: 'badge_template_001',
        recipientIdentity: 'learner@example.edu',
        recipientIdentityType: 'email',
        recipientIdentifiers: [
          {
            identifierType: 'emailAddress',
            identifier: 'learner@example.edu',
          },
          {
            identifierType: 'studentId',
            identifier: 'student-123',
          },
        ],
        requestedAt: '2026-02-10T15:00:00.000Z',
      },
      idempotencyKey: 'idem_abc',
    });

    expect(job.jobType).toBe('issue_badge');

    if (job.jobType !== 'issue_badge') {
      throw new Error('Expected issue_badge queue payload');
    }

    expect(job.payload.recipientIdentifiers).toHaveLength(2);
  });

  it('accepts a valid revoke_badge queue payload', () => {
    const job = parseQueueJob({
      jobType: 'revoke_badge',
      tenantId: 'tenant_123',
      payload: {
        revocationId: 'revocation_456',
        assertionId: 'assertion_456',
        reason: 'Issued in error',
        requestedAt: '2026-02-10T15:00:00.000Z',
      },
      idempotencyKey: 'idem_def',
    });

    expect(job.jobType).toBe('revoke_badge');
  });

  it('rejects malformed queue jobs', () => {
    expect(() => {
      parseQueueJob({
        tenantId: 'tenant_123',
      });
    }).toThrowError();
  });
});

describe('issue/revoke request parsers', () => {
  it('accepts a valid issue request', () => {
    const request = parseIssueBadgeRequest({
      tenantId: 'tenant_123',
      badgeTemplateId: 'badge_template_001',
      recipientIdentity: 'learner@example.edu',
      recipientIdentityType: 'email',
    });

    expect(request.tenantId).toBe('tenant_123');
  });

  it('accepts a valid issue request with recipient identifiers', () => {
    const request = parseIssueBadgeRequest({
      tenantId: 'tenant_123',
      badgeTemplateId: 'badge_template_001',
      recipientIdentity: 'learner@example.edu',
      recipientIdentityType: 'email',
      recipientIdentifiers: [
        {
          identifierType: 'emailAddress',
          identifier: 'learner@example.edu',
        },
        {
          identifierType: 'sourcedId',
          identifier: 'canvas-user-44',
        },
      ],
    });

    expect(request.recipientIdentifiers).toHaveLength(2);
  });

  it('rejects invalid recipient identifier entries', () => {
    expect(() => {
      parseIssueBadgeRequest({
        tenantId: 'tenant_123',
        badgeTemplateId: 'badge_template_001',
        recipientIdentity: 'learner@example.edu',
        recipientIdentityType: 'email',
        recipientIdentifiers: [
          {
            identifierType: 'emailAddress',
            identifier: '',
          },
        ],
      });
    }).toThrowError();
  });

  it('accepts a valid revoke request', () => {
    const request = parseRevokeBadgeRequest({
      tenantId: 'tenant_123',
      assertionId: 'assertion_456',
      reason: 'Revoked by issuer',
    });

    expect(request.assertionId).toBe('assertion_456');
  });

  it('rejects revoke requests without a reason', () => {
    expect(() => {
      parseRevokeBadgeRequest({
        tenantId: 'tenant_123',
        assertionId: 'assertion_456',
        reason: '',
      });
    }).toThrowError();
  });

  it('accepts a valid manual issue request', () => {
    const request = parseManualIssueBadgeRequest({
      badgeTemplateId: 'badge_template_001',
      recipientIdentity: 'learner@example.edu',
      recipientIdentityType: 'email',
    });

    expect(request.badgeTemplateId).toBe('badge_template_001');
  });

  it('accepts a valid Sakai commit issue request', () => {
    const request = parseIssueSakaiCommitBadgeRequest({
      badgeTemplateId: 'badge_template_001',
      githubUsername: 'sakai-dev',
    });

    expect(request.githubUsername).toBe('sakai-dev');
  });

  it('rejects invalid GitHub usernames for Sakai commit issue request', () => {
    expect(() => {
      parseIssueSakaiCommitBadgeRequest({
        badgeTemplateId: 'badge_template_001',
        githubUsername: '-invalid-',
      });
    }).toThrowError();
  });
});

describe('process queue request parser', () => {
  it('accepts an empty payload', () => {
    const request = parseProcessQueueRequest({});
    expect(request.limit).toBeUndefined();
  });

  it('accepts bounded queue processor settings', () => {
    const request = parseProcessQueueRequest({
      limit: 25,
      leaseSeconds: 30,
      retryDelaySeconds: 120,
    });

    expect(request.limit).toBe(25);
    expect(request.leaseSeconds).toBe(30);
    expect(request.retryDelaySeconds).toBe(120);
  });

  it('rejects invalid queue processor settings', () => {
    expect(() => {
      parseProcessQueueRequest({
        limit: 0,
      });
    }).toThrowError();
  });
});

describe('magic link request parsers', () => {
  it('accepts a valid magic link request', () => {
    const request = parseMagicLinkRequest({
      tenantId: 'tenant_123',
      email: 'learner@example.edu',
    });

    expect(request.email).toBe('learner@example.edu');
  });

  it('rejects invalid email values', () => {
    expect(() => {
      parseMagicLinkRequest({
        tenantId: 'tenant_123',
        email: 'not-an-email',
      });
    }).toThrowError();
  });

  it('accepts a valid magic link verify payload', () => {
    const verify = parseMagicLinkVerifyRequest({
      token: '0123456789012345678901234567890123456789',
    });

    expect(verify.token.length).toBeGreaterThan(20);
  });
});

describe('learner identity link parsers', () => {
  it('accepts a valid learner identity link request', () => {
    const request = parseLearnerIdentityLinkRequest({
      email: 'learner@gmail.com',
    });

    expect(request.email).toBe('learner@gmail.com');
  });

  it('accepts a valid learner identity link verify payload', () => {
    const request = parseLearnerIdentityLinkVerifyRequest({
      token: '0123456789012345678901234567890123456789',
    });

    expect(request.token.length).toBeGreaterThan(20);
  });

  it('rejects invalid learner identity link email values', () => {
    expect(() => {
      parseLearnerIdentityLinkRequest({
        email: 'invalid',
      });
    }).toThrowError();
  });
});

describe('admin LTI issuer registration parsers', () => {
  it('accepts a valid upsert payload', () => {
    const request = parseAdminUpsertLtiIssuerRegistrationRequest({
      issuer: 'https://canvas.example.edu',
      tenantId: 'tenant_123',
      authorizationEndpoint: 'https://canvas.example.edu/api/lti/authorize_redirect',
      clientId: 'canvas-client-123',
      allowUnsignedIdToken: true,
    });

    expect(request.issuer).toBe('https://canvas.example.edu');
    expect(request.tenantId).toBe('tenant_123');
    expect(request.allowUnsignedIdToken).toBe(true);
  });

  it('accepts a valid delete payload', () => {
    const request = parseAdminDeleteLtiIssuerRegistrationRequest({
      issuer: 'https://canvas.example.edu',
    });

    expect(request.issuer).toBe('https://canvas.example.edu');
  });

  it('rejects invalid issuer URLs', () => {
    expect(() => {
      parseAdminUpsertLtiIssuerRegistrationRequest({
        issuer: 'not-a-url',
        tenantId: 'tenant_123',
        authorizationEndpoint: 'https://canvas.example.edu/api/lti/authorize_redirect',
        clientId: 'canvas-client-123',
      });
    }).toThrowError();
  });
});

describe('parseSignCredentialRequest', () => {
  it('accepts a valid did:web signing request', () => {
    const payload = parseSignCredentialRequest({
      did: 'did:web:issuers.credtrail.org:tenant-a',
      credential: {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiableCredential'],
      },
    });

    expect(payload.did).toBe('did:web:issuers.credtrail.org:tenant-a');
  });

  it('accepts DataIntegrity signing requests with cryptosuite', () => {
    const payload = parseSignCredentialRequest({
      did: 'did:web:issuers.credtrail.org:tenant-a',
      credential: {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiableCredential'],
      },
      proofType: 'DataIntegrityProof',
      cryptosuite: 'ecdsa-sd-2023',
    });

    expect(payload.proofType).toBe('DataIntegrityProof');
    expect(payload.cryptosuite).toBe('ecdsa-sd-2023');
  });

  it('rejects non did:web identifiers', () => {
    expect(() => {
      parseSignCredentialRequest({
        did: 'did:key:z6Mk...',
        credential: {
          id: 'urn:vc:1',
        },
      });
    }).toThrowError();
  });

  it('rejects DataIntegrity signing requests without cryptosuite', () => {
    expect(() => {
      parseSignCredentialRequest({
        did: 'did:web:issuers.credtrail.org:tenant-a',
        credential: {
          id: 'urn:vc:1',
        },
        proofType: 'DataIntegrityProof',
      });
    }).toThrowError();
  });

  it('rejects cryptosuite when proofType is not DataIntegrityProof', () => {
    expect(() => {
      parseSignCredentialRequest({
        did: 'did:web:issuers.credtrail.org:tenant-a',
        credential: {
          id: 'urn:vc:1',
        },
        cryptosuite: 'eddsa-rdfc-2022',
      });
    }).toThrowError();
  });
});

describe('parseTenantSigningRegistry', () => {
  it('accepts tenant registry entries', () => {
    const registry = parseTenantSigningRegistry({
      'did:web:issuers.credtrail.org:tenant-a': {
        tenantId: 'tenant_a',
        keyId: 'key-1',
        publicJwk: {
          kty: 'OKP',
          crv: 'Ed25519',
          x: '11qYAYLef1f99sL4fY49fN7kP8Yw6s9w8lY9Yd6n8oE',
        },
        privateJwk: {
          kty: 'OKP',
          crv: 'Ed25519',
          x: '11qYAYLef1f99sL4fY49fN7kP8Yw6s9w8lY9Yd6n8oE',
          d: 'nWGxne_9WmZ8QfQwJdK2fNn_Ef3FQk7xU4mS1sM3x2U',
        },
      },
    });

    expect(Object.keys(registry)).toHaveLength(1);
  });

  it('accepts P-256 tenant registry entries', () => {
    const registry = parseTenantSigningRegistry({
      'did:web:issuers.credtrail.org:tenant-b': {
        tenantId: 'tenant_b',
        keyId: 'key-p256',
        publicJwk: {
          kty: 'EC',
          crv: 'P-256',
          x: 'X'.repeat(43),
          y: 'Y'.repeat(43),
        },
        privateJwk: {
          kty: 'EC',
          crv: 'P-256',
          x: 'X'.repeat(43),
          y: 'Y'.repeat(43),
          d: 'D'.repeat(43),
        },
      },
    });

    expect(Object.keys(registry)).toHaveLength(1);
  });

  it('rejects tenant registry entries with mismatched key types', () => {
    expect(() => {
      parseTenantSigningRegistry({
        'did:web:issuers.credtrail.org:tenant-c': {
          tenantId: 'tenant_c',
          keyId: 'key-mismatch',
          publicJwk: {
            kty: 'OKP',
            crv: 'Ed25519',
            x: '11qYAYLef1f99sL4fY49fN7kP8Yw6s9w8lY9Yd6n8oE',
          },
          privateJwk: {
            kty: 'EC',
            crv: 'P-256',
            x: 'X'.repeat(43),
            y: 'Y'.repeat(43),
            d: 'D'.repeat(43),
          },
        },
      });
    }).toThrowError();
  });
});

describe('badge template parsers', () => {
  it('accepts a valid create request', () => {
    const payload = parseCreateBadgeTemplateRequest({
      slug: 'intro-to-ts',
      title: 'Intro to TypeScript',
      description: 'Awarded for completing TypeScript basics.',
      criteriaUri: 'https://example.edu/badges/intro-to-ts/criteria',
      imageUri: 'https://cdn.example.edu/badges/intro-to-ts.png',
    });

    expect(payload.slug).toBe('intro-to-ts');
  });

  it('rejects invalid slugs', () => {
    expect(() => {
      parseCreateBadgeTemplateRequest({
        slug: 'Intro To TS',
        title: 'Intro to TypeScript',
      });
    }).toThrowError();
  });

  it('accepts update requests with nullable optional fields', () => {
    const payload = parseUpdateBadgeTemplateRequest({
      description: null,
      imageUri: null,
    });

    expect(payload.description).toBeNull();
  });

  it('rejects empty update payloads', () => {
    expect(() => {
      parseUpdateBadgeTemplateRequest({});
    }).toThrowError();
  });

  it('parses path params for badge template routes', () => {
    const params = parseBadgeTemplatePathParams({
      tenantId: 'tenant_123',
      badgeTemplateId: 'tmpl_456',
    });

    expect(params.badgeTemplateId).toBe('tmpl_456');
  });

  it('parses path params for public credential verification route', () => {
    const params = parseCredentialPathParams({
      credentialId: 'tenant_123:assertion_456',
    });

    expect(params.credentialId).toBe('tenant_123:assertion_456');
  });

  it('parses tenant/user path params for membership role routes', () => {
    const params = parseTenantUserPathParams({
      tenantId: 'tenant_123',
      userId: 'usr_456',
    });

    expect(params.tenantId).toBe('tenant_123');
    expect(params.userId).toBe('usr_456');
  });

  it('defaults includeArchived to false in list query', () => {
    const query = parseBadgeTemplateListQuery({});

    expect(query.includeArchived).toBe(false);
  });
});

describe('admin request parsers', () => {
  it('accepts P-256 tenant signing registration payloads', () => {
    const payload = parseAdminUpsertTenantSigningRegistrationRequest({
      keyId: 'key-p256',
      publicJwk: {
        kty: 'EC',
        crv: 'P-256',
        x: 'X'.repeat(43),
        y: 'Y'.repeat(43),
      },
      privateJwk: {
        kty: 'EC',
        crv: 'P-256',
        x: 'X'.repeat(43),
        y: 'Y'.repeat(43),
        d: 'D'.repeat(43),
      },
    });

    expect(payload.keyId).toBe('key-p256');
  });

  it('rejects signing registration payloads with mismatched key types', () => {
    expect(() => {
      parseAdminUpsertTenantSigningRegistrationRequest({
        keyId: 'key-mismatch',
        publicJwk: {
          kty: 'OKP',
          crv: 'Ed25519',
          x: '11qYAYLef1f99sL4fY49fN7kP8Yw6s9w8lY9Yd6n8oE',
        },
        privateJwk: {
          kty: 'EC',
          crv: 'P-256',
          x: 'X'.repeat(43),
          y: 'Y'.repeat(43),
          d: 'D'.repeat(43),
        },
      });
    }).toThrowError();
  });

  it('accepts valid membership role updates', () => {
    const payload = parseAdminUpsertTenantMembershipRoleRequest({
      role: 'admin',
    });

    expect(payload.role).toBe('admin');
  });

  it('rejects invalid membership roles', () => {
    expect(() => {
      parseAdminUpsertTenantMembershipRoleRequest({
        role: 'superadmin',
      });
    }).toThrowError();
  });
});
