import { describe, expect, it } from "vitest";
import {
  runTenantMemberInviteWorkflow,
  type TenantMemberInviteAuditEvent,
  type TenantMemberInviteResult,
} from "./tenant-member-invite-workflow";

const workflowInput = {
  tenantId: "tenant_123",
  actorUserId: "usr_admin",
  actorRole: "admin",
  userId: "usr_member",
  email: "member@example.edu",
  role: "issuer",
} as const;

const runWithResult = async (
  result: TenantMemberInviteResult,
): Promise<{
  readonly returnedResult: TenantMemberInviteResult;
  readonly auditEvents: readonly TenantMemberInviteAuditEvent[];
}> => {
  const auditEvents: TenantMemberInviteAuditEvent[] = [];
  const returnedResult = await runTenantMemberInviteWorkflow(
    {
      requestDelivery: () => Promise.resolve(result),
      recordAudit: (event) => {
        auditEvents.push(event);
        return Promise.resolve();
      },
    },
    workflowInput,
  );

  return { returnedResult, auditEvents };
};

describe("runTenantMemberInviteWorkflow", () => {
  it("records a sent event after successful delivery", async () => {
    const result = { deliveryStatus: "sent", inviteKind: "magic_link" } as const;
    const execution = await runWithResult(result);

    expect(execution.returnedResult).toBe(result);
    expect(execution.auditEvents).toEqual([
      {
        ...workflowInput,
        action: "membership.invite_sent",
        invite: result,
      },
    ]);
  });

  it("records a failed event when delivery fails", async () => {
    const result = { deliveryStatus: "failed", inviteKind: "sso_notice" } as const;
    const execution = await runWithResult(result);

    expect(execution.returnedResult).toBe(result);
    expect(execution.auditEvents).toEqual([
      {
        ...workflowInput,
        action: "membership.invite_failed",
        invite: result,
      },
    ]);
  });

  it("does not record a delivery event when the invitation is skipped", async () => {
    const result = { deliveryStatus: "skipped", inviteKind: "magic_link" } as const;
    const execution = await runWithResult(result);

    expect(execution.returnedResult).toBe(result);
    expect(execution.auditEvents).toEqual([]);
  });
});
