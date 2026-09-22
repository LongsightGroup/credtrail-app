import { renameBadgeIssuanceRule, resolveBadgeIssuanceRuleVersionSelection } from "@credtrail/db";
import { parseBadgeIssuanceRulePathParams } from "@credtrail/validation";
import { z } from "zod";
import type { Hono } from "hono";
import type { AppEnv } from "../app/types";
import type { ResolveDatabase } from "../app/route-deps";
import {
  buildBadgeRuleVersionDetailPath,
  buildRulesAdminPath,
} from "../admin/access-admin-helpers";
import { setAdminListMessageFlash } from "../admin/admin-list-message-flash";
import { badgeRuleVersionDisplayFields } from "../badges/badge-rule-presentation";
import {
  loadBadgeRuleVersionsPageContext,
  type ResolveBadgeRuleVersionPageActor,
} from "./badge-rule-version-page-context";

const renameForm = z.discriminatedUnion("mode", [
  z.object({
    mode: z.literal("custom"),
    name: z.string().trim().min(1).max(200),
    returnTo: z.string().max(2000),
  }),
  z.object({ mode: z.literal("automatic"), returnTo: z.string().max(2000) }),
]);

/** Registers the administrator-only metadata action; it never enters the approval workflow. */
export const registerTenantBadgeRuleNameAdminRoutes = (input: {
  readonly app: Hono<AppEnv>;
  readonly resolveDatabase: ResolveDatabase;
  readonly resolveInstitutionAdminAdminRole: ResolveBadgeRuleVersionPageActor;
}): void => {
  input.app.post("/tenants/:tenantId/admin/rules/:ruleId/name", async (c) => {
    const path = parseBadgeIssuanceRulePathParams(c.req.param());
    const listPath = buildRulesAdminPath(path.tenantId);
    const loaded = await loadBadgeRuleVersionsPageContext(c, {
      ...path,
      nextPath: listPath,
      resolveDatabase: input.resolveDatabase,
      resolveActor: input.resolveInstitutionAdminAdminRole,
    });
    if (loaded instanceof Response) return loaded;
    const form = renameForm.safeParse(Object.fromEntries(await c.req.formData()));
    if (!form.success) return c.json({ error: "Enter a name between 1 and 200 characters." }, 400);
    const selected = resolveBadgeIssuanceRuleVersionSelection(loaded).defaultVersion;
    if (selected === null) return c.json({ error: "This rule has no saved requirements." }, 409);
    const requestedReturn = URL.parse(form.data.returnTo, c.req.url);
    const allowedPaths = [
      listPath,
      ...loaded.versions.map((version) =>
        buildBadgeRuleVersionDetailPath(path.tenantId, path.ruleId, version.id),
      ),
    ];
    const returnTo =
      requestedReturn !== null &&
      requestedReturn.origin === new URL(c.req.url).origin &&
      allowedPaths.includes(requestedReturn.pathname)
        ? requestedReturn.pathname + requestedReturn.search
        : listPath;
    const renamed = await renameBadgeIssuanceRule(loaded.db, {
      ...path,
      actorUserId: loaded.principal.userId,
      customLabel: form.data.mode === "automatic" ? null : form.data.name,
      automaticName: badgeRuleVersionDisplayFields(selected, {
        customLabel: null,
      }).requirementSummary.slice(0, 200),
      automaticVersionId: selected.id,
    });
    if (renamed.status !== "renamed") {
      return c.json({ error: "The rule changed. Reload it and try again." }, 409);
    }
    await setAdminListMessageFlash(c, {
      tenantId: path.tenantId,
      userId: loaded.principal.userId,
      workspace: "rules",
      tone: "success",
      message:
        form.data.mode === "automatic" ? "The rule now uses its automatic name." : "Rule renamed.",
    });
    c.header("Cache-Control", "no-store");
    return c.req.header("Accept")?.includes("application/json")
      ? c.json({ redirectTo: returnTo })
      : c.redirect(returnTo, 303);
  });
};
