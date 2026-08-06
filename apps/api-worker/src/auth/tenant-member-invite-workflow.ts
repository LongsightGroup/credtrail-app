import type { TenantMembershipRole } from "@credtrail/db";

/** Result of requesting delivery for a tenant-member invitation. */
export type TenantMemberInviteResult = {
  readonly deliveryStatus: "sent" | "skipped" | "failed";
  readonly inviteKind: "magic_link" | "sso_notice";
};

/** Truthful audit event produced after an invitation delivery attempt. */
export type TenantMemberInviteAuditEvent = {
  readonly tenantId: string;
  readonly actorUserId: string;
  readonly actorRole: TenantMembershipRole;
  readonly userId: string;
  readonly email: string;
  readonly role: TenantMembershipRole;
  readonly action: "membership.invite_sent" | "membership.invite_failed";
  readonly invite: TenantMemberInviteResult;
};

/** Dependencies that perform invitation delivery and persist its audit event. */
export type TenantMemberInviteWorkflowDependencies = {
  readonly requestDelivery: () => Promise<TenantMemberInviteResult>;
  readonly recordAudit: (event: TenantMemberInviteAuditEvent) => Promise<void>;
};

/** Context identifying the invitation actor and recipient. */
export type TenantMemberInviteWorkflowInput = {
  readonly tenantId: string;
  readonly actorUserId: string;
  readonly actorRole: TenantMembershipRole;
  readonly userId: string;
  readonly email: string;
  readonly role: TenantMembershipRole;
};

/** Requests an invitation and records its actual attempted-delivery outcome. */
export const runTenantMemberInviteWorkflow = async (
  dependencies: TenantMemberInviteWorkflowDependencies,
  input: TenantMemberInviteWorkflowInput,
): Promise<TenantMemberInviteResult> => {
  const invite = await dependencies.requestDelivery();

  if (invite.deliveryStatus === "skipped") {
    return invite;
  }

  await dependencies.recordAudit({
    ...input,
    action:
      invite.deliveryStatus === "sent" ? "membership.invite_sent" : "membership.invite_failed",
    invite,
  });

  return invite;
};
