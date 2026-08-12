import { describe, expect, it } from "vitest";

import {
  parseAssertionLifecycleTransitionRequest,
  parseIssueBadgeRequest,
  parseManualIssueBadgeRequest,
  parsePresentationCreateRequest,
  parsePresentationVerifyRequest,
  parseProgrammaticIssueBadgeRequest,
  parseProgrammaticRevokeBadgeRequest,
  parseRevokeBadgeRequest,
} from "./credentials.js";
import { parseAssertionPathParams } from "./path-params.js";

describe("issue/revoke request parsers", () => {
  it("accepts a valid issue request", () => {
    const request = parseIssueBadgeRequest({
      tenantId: "tenant_123",
      badgeTemplateId: "badge_template_001",
      recipientIdentity: "learner@example.edu",
      recipientIdentityType: "email",
    });

    expect(request.tenantId).toBe("tenant_123");
  });

  it("accepts a valid issue request with recipient identifiers", () => {
    const request = parseIssueBadgeRequest({
      tenantId: "tenant_123",
      badgeTemplateId: "badge_template_001",
      recipientIdentity: "learner@example.edu",
      recipientIdentityType: "email",
      recipientIdentifiers: [
        {
          identifierType: "emailAddress",
          identifier: "learner@example.edu",
        },
        {
          identifierType: "sourcedId",
          identifier: "canvas-user-44",
        },
      ],
      recipientDisplayName: "Learner Example",
      issuerImageUri: "https://issuer.example.edu/logo.svg",
    });

    expect(request.recipientIdentifiers).toHaveLength(2);
    expect(request.recipientDisplayName).toBe("Learner Example");
    expect(request.issuerImageUri).toBe("https://issuer.example.edu/logo.svg");
  });

  it("rejects invalid recipient identifier entries", () => {
    expect(() => {
      parseIssueBadgeRequest({
        tenantId: "tenant_123",
        badgeTemplateId: "badge_template_001",
        recipientIdentity: "learner@example.edu",
        recipientIdentityType: "email",
        recipientIdentifiers: [
          {
            identifierType: "emailAddress",
            identifier: "",
          },
        ],
      });
    }).toThrow(/./);
  });

  it("accepts a valid revoke request", () => {
    const request = parseRevokeBadgeRequest({
      tenantId: "tenant_123",
      assertionId: "assertion_456",
      reason: "Revoked by issuer",
    });

    expect(request.assertionId).toBe("assertion_456");
  });

  it("rejects revoke requests without a reason", () => {
    expect(() => {
      parseRevokeBadgeRequest({
        tenantId: "tenant_123",
        assertionId: "assertion_456",
        reason: "",
      });
    }).toThrow(/./);
  });

  it("accepts a valid manual issue request", () => {
    const request = parseManualIssueBadgeRequest({
      badgeTemplateId: "badge_template_001",
      recipientIdentity: "learner@example.edu",
      recipientIdentityType: "email",
    });

    expect(request.badgeTemplateId).toBe("badge_template_001");
  });

  it("requires idempotencyKey for programmatic issue requests", () => {
    expect(() => {
      parseProgrammaticIssueBadgeRequest({
        tenantId: "tenant_123",
        badgeTemplateId: "badge_template_001",
        recipientIdentity: "learner@example.edu",
        recipientIdentityType: "email",
      });
    }).toThrow(/./);
  });

  it("accepts a valid programmatic issue request with idempotencyKey", () => {
    const request = parseProgrammaticIssueBadgeRequest({
      tenantId: "tenant_123",
      badgeTemplateId: "badge_template_001",
      recipientIdentity: "learner@example.edu",
      recipientIdentityType: "email",
      idempotencyKey: "idem_issue_123",
    });

    expect(request.idempotencyKey).toBe("idem_issue_123");
  });

  it("rejects caller-supplied governance provenance for programmatic issuance", () => {
    expect(() => {
      parseProgrammaticIssueBadgeRequest({
        tenantId: "tenant_123",
        badgeTemplateId: "badge_template_001",
        recipientIdentity: "learner@example.edu",
        recipientIdentityType: "email",
        idempotencyKey: "idem_issue_123",
        issuanceProvenance: {
          source: "rule_evaluate",
          ruleId: "rule_123",
          versionId: "version_123",
          provenanceJson: "{}",
        },
      });
    }).toThrow(/./);
  });

  it("requires idempotencyKey for programmatic revoke requests", () => {
    expect(() => {
      parseProgrammaticRevokeBadgeRequest({
        tenantId: "tenant_123",
        assertionId: "assertion_456",
        reason: "Revoked by issuer",
      });
    }).toThrow(/./);
  });

  it("accepts a valid programmatic revoke request with idempotencyKey", () => {
    const request = parseProgrammaticRevokeBadgeRequest({
      tenantId: "tenant_123",
      assertionId: "assertion_456",
      reason: "Revoked by issuer",
      idempotencyKey: "idem_revoke_123",
    });

    expect(request.idempotencyKey).toBe("idem_revoke_123");
  });
});

describe("presentation parser", () => {
  it("accepts a valid presentation create payload", () => {
    const request = parsePresentationCreateRequest({
      holderDid: "did:key:z6MknqT2qWnVYxR2s4cV8nH2uC6wYtQ5jT8kH7aX9mP2zR1",
      holderPrivateJwk: {
        kty: "OKP",
        crv: "Ed25519",
        x: "11qYAY7Y8A8kS0P3J-bwFTHlL8E8fQf6c3n2pP7Q9Q0",
        d: "nWGxne_9Wm7nP8aW8Q6BYfQhRj6iB-8Sn4Xc6D4J3vU",
      },
      credentialIds: ["tenant_123:assertion_456"],
    });

    expect(request.holderDid).toContain("did:key:");
    expect(request.credentialIds).toHaveLength(1);
  });

  it("rejects duplicate credential identifiers in create payload", () => {
    expect(() => {
      parsePresentationCreateRequest({
        holderDid: "did:key:z6MknqT2qWnVYxR2s4cV8nH2uC6wYtQ5jT8kH7aX9mP2zR1",
        holderPrivateJwk: {
          kty: "OKP",
          crv: "Ed25519",
          x: "11qYAY7Y8A8kS0P3J-bwFTHlL8E8fQf6c3n2pP7Q9Q0",
          d: "nWGxne_9Wm7nP8aW8Q6BYfQhRj6iB-8Sn4Xc6D4J3vU",
        },
        credentialIds: ["tenant_123:assertion_456", "tenant_123:assertion_456"],
      });
    }).toThrow(/./);
  });

  it("accepts a valid presentation verify payload", () => {
    const request = parsePresentationVerifyRequest({
      presentation: {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        type: ["VerifiablePresentation"],
        holder: "did:key:z6MknqT2qWnVYxR2s4cV8nH2uC6wYtQ5jT8kH7aX9mP2zR1",
        verifiableCredential: [],
      },
    });

    expect(request.presentation.type).toEqual(["VerifiablePresentation"]);
  });
});

describe("assertion lifecycle parsers", () => {
  it("accepts valid assertion lifecycle transition payloads", () => {
    const payload = parseAssertionLifecycleTransitionRequest({
      toState: "suspended",
      reasonCode: "administrative_hold",
      reason: "Pending registrar review",
      transitionSource: "manual",
      transitionedAt: "2026-02-12T23:00:00.000Z",
    });

    expect(payload.toState).toBe("suspended");
    expect(payload.reasonCode).toBe("administrative_hold");
    expect(payload.transitionSource).toBe("manual");
  });

  it("defaults transitionSource to manual when omitted", () => {
    const payload = parseAssertionLifecycleTransitionRequest({
      toState: "expired",
      reasonCode: "credential_expired",
    });

    expect(payload.transitionSource).toBe("manual");
  });

  it("rejects invalid assertion lifecycle state values", () => {
    expect(() => {
      parseAssertionLifecycleTransitionRequest({
        toState: "paused",
        reasonCode: "other",
      });
    }).toThrow(/./);
  });

  it("parses assertion path params", () => {
    const pathParams = parseAssertionPathParams({
      tenantId: "tenant_123",
      assertionId: "tenant_123:assertion_456",
    });

    expect(pathParams.tenantId).toBe("tenant_123");
    expect(pathParams.assertionId).toBe("tenant_123:assertion_456");
  });
});
