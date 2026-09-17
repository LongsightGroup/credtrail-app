import { badgeRecordsReturnHref } from "../admin/learner-record-link";
import { findAssertionById, findBadgeTemplateById } from "@credtrail/db";
import { parseTenantPathParams, parseAssertionPathParams } from "@credtrail/validation";
import { z } from "zod";
import { issuanceReceiptPath } from "../admin/issuance-receipt-page";
import { setAdminListMessageFlash } from "../admin/admin-list-message-flash";
import { publicBadgePathForAssertion } from "../badges/public-badge-model";
import { canonicalAppUrl } from "../http/canonical-app-url";
import { retryFailedIssuanceEmail } from "../notifications/retry-issuance-email";
import { sendIssuanceEmailNotification } from "../notifications/send-issuance-email";
import type { RegisterTenantOperationsAdminRoutesInput } from "./tenant-operations-admin-routes";

export const registerTenantNotificationRetryAdminRoutes = (
  input: Pick<
    RegisterTenantOperationsAdminRoutesInput,
    | "app"
    | "resolveDatabase"
    | "resolveInstitutionAdminAdminRole"
    | "requireDelegatedIssuingAuthorityPermission"
  > & { send: typeof sendIssuanceEmailNotification },
): void => {
  input.app.post(
    "/tenants/:tenantId/admin/operations/issue/:assertionId/retry-notification",
    async (c) => {
      const { tenantId } = parseTenantPathParams(c.req.param());
      const { assertionId } = parseAssertionPathParams(c.req.param());
      const receiptPath = issuanceReceiptPath(tenantId, assertionId);
      const authorized = await input.resolveInstitutionAdminAdminRole(c, tenantId, receiptPath);
      if (authorized instanceof Response) return authorized;
      const db = input.resolveDatabase(c.env);
      const assertion = await findAssertionById(db, tenantId, assertionId);
      if (assertion === null) return c.text("Badge not found for this institution.", 404);
      const template = await findBadgeTemplateById(db, tenantId, assertion.badgeTemplateId);
      if (template === null) return c.text("Badge details are unavailable.", 404);
      const denied = await input.requireDelegatedIssuingAuthorityPermission(c, {
        db,
        tenantId,
        userId: authorized.principal.userId,
        membershipRole: authorized.membershipRole,
        ownerOrgUnitId: template.ownerOrgUnitId,
        badgeTemplateId: template.id,
        requiredAction: "issue_badge",
      });
      if (denied !== null) return denied;
      const form = await c.req.formData();
      const returnHref = badgeRecordsReturnHref(tenantId, form.get("returnTo"));
      const finish = async (message: string, tone: "success" | "error"): Promise<Response> => {
        await setAdminListMessageFlash(c, {
          tenantId,
          userId: authorized.principal.userId,
          workspace: "operations_manual_issue",
          tone,
          message,
        });
        return c.redirect(
          returnHref
            ? `${receiptPath}?${new URLSearchParams({ returnTo: returnHref })}`
            : receiptPath,
          303,
        );
      };
      const parsed = z
        .object({ failedAttemptId: z.string().trim().min(1).max(256) })
        .safeParse(Object.fromEntries(form));
      if (!parsed.success)
        return finish("Refresh the receipt before retrying this notification.", "error");
      if (
        assertion.recipientIdentityType !== "email" ||
        c.env.ISSUANCE_EMAIL_NOTIFICATIONS_ENABLED?.trim().toLowerCase() !== "true" ||
        c.env.EMAIL === undefined
      )
        return finish(
          "Email notifications are unavailable. Share the public badge link with the learner.",
          "error",
        );
      const badgePath = publicBadgePathForAssertion(assertion);
      const result = await retryFailedIssuanceEmail({
        db,
        tenantId,
        assertionId,
        actorUserId: authorized.principal.userId,
        failedAttemptId: parsed.data.failedAttemptId,
        send: () =>
          input.send({
            emailBinding: c.env.EMAIL,
            fromEmail: c.env.TRANSACTIONAL_EMAIL_FROM_ADDRESS,
            fromName: c.env.TRANSACTIONAL_EMAIL_FROM_NAME,
            recipientEmail: assertion.recipientIdentity,
            badgeTitle: assertion.achievementSnapshot.title,
            assertionId,
            tenantId,
            issuedAtIso: assertion.issuedAt,
            publicBadgeUrl: canonicalAppUrl(c.env.PUBLIC_APP_ORIGIN, badgePath),
            verificationUrl: canonicalAppUrl(c.env.PUBLIC_APP_ORIGIN, `${badgePath}/verification`),
            credentialDownloadUrl: canonicalAppUrl(c.env.PUBLIC_APP_ORIGIN, `${badgePath}/jsonld`),
          }),
      });
      return finish(
        result === "accepted"
          ? "The email service accepted the retry. No new credential was created."
          : result === "failed"
            ? "The notification could not be sent. You can retry again or share the badge link."
            : "This attempt has already been handled. Check the notification result below.",
        result === "failed" ? "error" : "success",
      );
    },
  );
};
