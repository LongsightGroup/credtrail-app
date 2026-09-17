import { expect, it } from "vitest";
import { manualIssueIdempotencyKey } from "./manual-issue-request";

it("reuses a submission key only for the same actor and issuance decisions", async () => {
  const request = {
    tenantId: "tenant",
    userId: "user",
    requestId: crypto.randomUUID(),
    badgeTemplateId: "badge",
    recipientIdentity: "learner@example.edu",
    pathwayHandoffId: undefined,
  };
  const key = await manualIssueIdempotencyKey(request);
  expect(
    await manualIssueIdempotencyKey({ ...request, recipientIdentity: " LEARNER@example.edu " }),
  ).toBe(key);
  for (const change of [
    { tenantId: "another-tenant" },
    { userId: "another-user" },
    { requestId: crypto.randomUUID() },
    { badgeTemplateId: "another-badge" },
    { recipientIdentity: "another@example.edu" },
    { pathwayHandoffId: "handoff" },
  ])
    expect(await manualIssueIdempotencyKey({ ...request, ...change })).not.toBe(key);
  expect(key).not.toContain(request.recipientIdentity);
});
