import {
  createAuditLog,
  createBadgeIssuanceRuleValueList,
  type SessionRecord,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import {
  parseCreateBadgeIssuanceRuleValueListRequest,
  parseTenantPathParams,
} from "@credtrail/validation";
import type { Hono } from "hono";
import { readOptionalFormField } from "../admin/admin-form-helpers";
import { setAdminListMessageFlash } from "../admin/admin-list-message-flash";
import {
  buildRuleValueListsAdminPath,
  tenantRuleValueListsAdminCreatePath,
} from "../admin/rule-value-lists-admin-helpers";
import { parseCommaSeparatedAdminValues } from "../admin/rule-value-lists-presentation";
import type { AppBindings, AppContext, AppEnv } from "../app";

interface RegisterTenantRuleValueListsAdminRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  resolveInstitutionAdminAdminRole: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ) => Promise<
    | Response
    | {
        session: SessionRecord;
        membershipRole: TenantMembershipRole;
      }
  >;
}

export const registerTenantRuleValueListsAdminRoutes = (
  input: RegisterTenantRuleValueListsAdminRoutesInput,
): void => {
  const { app, resolveDatabase, resolveInstitutionAdminAdminRole } = input;

  app.post("/tenants/:tenantId/admin/rules/value-lists", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const nextPath = tenantRuleValueListsAdminCreatePath(pathParams.tenantId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session } = roleCheck;
    const redirectToRules = async (
      tone: "success" | "error",
      message: string,
    ): Promise<Response> => {
      await setAdminListMessageFlash(c, {
        tenantId: pathParams.tenantId,
        userId: session.userId,
        workspace: "rule_value_lists",
        tone,
        message,
      });

      return c.redirect(buildRuleValueListsAdminPath(pathParams.tenantId), 303);
    };

    const formData = await c.req.formData();
    const label = readOptionalFormField(formData, "label") ?? "";
    const kind = readOptionalFormField(formData, "kind");
    const values = parseCommaSeparatedAdminValues(formData.get("values"));

    if (label.length === 0 || kind === undefined || values.length === 0) {
      return redirectToRules("error", "Label, list kind, and at least one value are required.");
    }

    let request: ReturnType<typeof parseCreateBadgeIssuanceRuleValueListRequest>;

    try {
      request = parseCreateBadgeIssuanceRuleValueListRequest({
        label,
        kind,
        values,
      });
    } catch {
      return redirectToRules("error", "Check the label, list kind, and values, then try again.");
    }

    const { membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const valueList = await createBadgeIssuanceRuleValueList(db, {
      tenantId: pathParams.tenantId,
      label: request.label,
      kind: request.kind,
      values: request.values,
      createdByUserId: session.userId,
    });

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: "badge_rule.value_list_created",
      targetType: "badge_rule_value_list",
      targetId: valueList.id,
      metadata: {
        role: membershipRole,
        kind: valueList.kind,
        valueCount: valueList.values.length,
      },
    });

    return redirectToRules("success", `Created reusable list “${valueList.label}”.`);
  });
};
