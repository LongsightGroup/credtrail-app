import {
  listBadgeIssuanceRuleVersionApprovalEvents,
  listBadgeIssuanceRuleVersionApprovalSteps,
  listBadgeIssuanceRuleVersions,
  listBadgeIssuanceRules,
  listBadgeTemplateOwnershipEvents,
  listBadgeTemplates,
  listPublicBadgeWallEntries,
  listTenantOrgUnits,
  recordAssertionEngagementEvent,
  resolveAssertionLifecycleState,
  type SqlDatabase,
} from "@credtrail/db";
import type { ImmutableCredentialStore, JsonObject } from "@credtrail/core-domain";
import type { Hono } from "hono";
import { parseTenantPathParams } from "@credtrail/validation";
import { badgeNameFromCredential, issuerNameFromCredential } from "../badges/credential-display";
import type { AppBindings, AppEnv } from "../app";
import { renderAppPage, type AppPage } from "../ui/render-page";
import type {
  PublicBadgeCriteriaRegistryViewModel,
  PublicBadgeCriteriaRuleViewRecord,
  PublicBadgeWallEntryViewRecord,
} from "../badges/public-badge-pages";
import { linkedInAddToProfileUrl } from "../utils/display-format";
import { asString } from "../utils/value-parsers";

interface PublicBadgeRouteValue {
  assertion: {
    id: string;
    tenantId: string;
    publicId: string | null;
    issuedAt: string;
  };
  credential: JsonObject;
}

interface RegisterPublicBadgeRoutesInput<PublicBadgeValue extends PublicBadgeRouteValue> {
  app: Hono<AppEnv>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  loadPublicBadgeViewModel: (
    db: SqlDatabase,
    badgeObjects: ImmutableCredentialStore,
    badgeIdentifier: string,
  ) => Promise<
    | {
        status: "not_found";
      }
    | {
        status: "redirect";
        canonicalPath: string;
      }
    | {
        status: "ok";
        value: PublicBadgeValue;
      }
  >;
  publicBadgeNotFoundPage: (requestUrl: string) => AppPage;
  publicBadgePage: (requestUrl: string, value: PublicBadgeValue) => AppPage;
  publicBadgeSummaryPayload: (
    requestUrl: string,
    value: PublicBadgeValue,
  ) => Record<string, unknown>;
  tenantBadgeWallPage: (
    requestUrl: string,
    tenantId: string,
    entries: readonly PublicBadgeWallEntryViewRecord[],
    badgeTemplateId: string | null,
  ) => AppPage;
  tenantBadgeCriteriaRegistryPage: (
    requestUrl: string,
    tenantId: string,
    model: PublicBadgeCriteriaRegistryViewModel,
    badgeTemplateId: string | null,
  ) => AppPage;
  asNonEmptyString: (value: unknown) => string | null;
  SAKAI_SHOWCASE_TENANT_ID: string;
  SAKAI_SHOWCASE_TEMPLATE_ID: string;
}

const buildPublicBadgeCriteriaRegistryViewModel = async (
  db: SqlDatabase,
  tenantId: string,
  badgeTemplateId: string | null,
): Promise<PublicBadgeCriteriaRegistryViewModel> => {
  const [templates, orgUnits, rules] = await Promise.all([
    listBadgeTemplates(db, {
      tenantId,
      includeArchived: false,
    }),
    listTenantOrgUnits(db, {
      tenantId,
      includeInactive: true,
    }),
    listBadgeIssuanceRules(db, {
      tenantId,
    }),
  ]);
  const filteredTemplates =
    badgeTemplateId === null
      ? templates
      : templates.filter((template) => template.id === badgeTemplateId);
  const orgUnitById = new Map(orgUnits.map((orgUnit) => [orgUnit.id, orgUnit]));
  const rulesByTemplateId = new Map<string, PublicBadgeCriteriaRuleViewRecord[]>();

  await Promise.all(
    rules.map(async (rule) => {
      const versions = await listBadgeIssuanceRuleVersions(db, {
        tenantId,
        ruleId: rule.id,
      });
      const latestVersion = versions[0] ?? null;
      const activeVersion =
        (rule.activeVersionId === null
          ? null
          : versions.find((version) => version.id === rule.activeVersionId)) ??
        versions.find((version) => version.status === "active") ??
        null;
      const governanceVersion = activeVersion ?? latestVersion;
      const [approvalSteps, approvalEvents] =
        governanceVersion === null
          ? [[], []]
          : await Promise.all([
              listBadgeIssuanceRuleVersionApprovalSteps(db, {
                tenantId,
                ruleId: rule.id,
                versionId: governanceVersion.id,
              }),
              listBadgeIssuanceRuleVersionApprovalEvents(db, {
                tenantId,
                ruleId: rule.id,
                versionId: governanceVersion.id,
              }),
            ]);
      const byTemplate = rulesByTemplateId.get(rule.badgeTemplateId);
      const ruleRecord: PublicBadgeCriteriaRuleViewRecord = {
        rule,
        latestVersion,
        activeVersion,
        approvalSteps,
        approvalEvents,
      };

      if (byTemplate === undefined) {
        rulesByTemplateId.set(rule.badgeTemplateId, [ruleRecord]);
        return;
      }

      byTemplate.push(ruleRecord);
    }),
  );

  const templateEntries = await Promise.all(
    filteredTemplates.map(async (template) => {
      const ownershipEvents = await listBadgeTemplateOwnershipEvents(db, {
        tenantId,
        badgeTemplateId: template.id,
        limit: 20,
      });
      const rulesForTemplate = rulesByTemplateId.get(template.id) ?? [];

      return {
        template,
        ownerOrgUnit: orgUnitById.get(template.ownerOrgUnitId) ?? null,
        ownershipEvents,
        rules: rulesForTemplate,
      };
    }),
  );

  return {
    orgUnits,
    templates: templateEntries,
  };
};

export const registerPublicBadgeRoutes = <PublicBadgeValue extends PublicBadgeRouteValue>(
  input: RegisterPublicBadgeRoutesInput<PublicBadgeValue>,
): void => {
  const {
    app,
    resolveDatabase,
    loadPublicBadgeViewModel,
    publicBadgeNotFoundPage,
    publicBadgePage,
    publicBadgeSummaryPayload,
    tenantBadgeWallPage,
    tenantBadgeCriteriaRegistryPage,
    asNonEmptyString,
    SAKAI_SHOWCASE_TENANT_ID,
    SAKAI_SHOWCASE_TEMPLATE_ID,
  } = input;

  const recordPublicEngagement = async (
    db: SqlDatabase,
    value: PublicBadgeValue,
    eventType: "public_badge_view" | "share_click",
    channel?: string,
  ): Promise<void> => {
    await recordAssertionEngagementEvent(db, {
      tenantId: value.assertion.tenantId,
      assertionId: value.assertion.id,
      eventType,
      actorType: "anonymous",
      ...(channel === undefined ? {} : { channel }),
      occurredAt: new Date().toISOString(),
    });
  };

  const shareRedirectUrlForChannel = (
    requestUrl: string,
    value: PublicBadgeValue,
    channel: string,
  ): string | null => {
    const publicBadgePath = `/badges/${encodeURIComponent(
      value.assertion.publicId ?? value.assertion.id,
    )}`;
    const publicBadgeUrl = new URL(publicBadgePath, requestUrl).toString();

    if (channel === "linkedin-feed") {
      const linkedInShareUrl = new URL("https://www.linkedin.com/sharing/share-offsite/");
      linkedInShareUrl.searchParams.set("url", publicBadgeUrl);
      return linkedInShareUrl.toString();
    }

    if (channel === "linkedin-profile") {
      return linkedInAddToProfileUrl({
        badgeName: badgeNameFromCredential(value.credential),
        issuerName: issuerNameFromCredential(value.credential),
        issuedAtIso: value.assertion.issuedAt,
        credentialUrl: publicBadgeUrl,
        credentialId: asString(value.credential.id) ?? value.assertion.id,
      });
    }

    return null;
  };

  app.get("/badges/:badgeIdentifier/public_url", (c) => {
    const badgeIdentifier = c.req.param("badgeIdentifier").trim();

    if (badgeIdentifier.length === 0) {
      return renderAppPage(c, publicBadgeNotFoundPage(c.req.url), 404);
    }

    return c.redirect(`/badges/${encodeURIComponent(badgeIdentifier)}`, 308);
  });

  app.get("/badges/:badgeIdentifier", async (c) => {
    const badgeIdentifier = c.req.param("badgeIdentifier");
    const result = await loadPublicBadgeViewModel(
      resolveDatabase(c.env),
      c.env.BADGE_OBJECTS,
      badgeIdentifier,
    );

    c.header("Cache-Control", "no-store");

    if (result.status === "not_found") {
      return renderAppPage(c, publicBadgeNotFoundPage(c.req.url), 404);
    }

    if (result.status === "redirect") {
      return c.redirect(result.canonicalPath, 308);
    }

    await recordPublicEngagement(resolveDatabase(c.env), result.value, "public_badge_view");
    return renderAppPage(c, publicBadgePage(c.req.url, result.value));
  });

  app.get("/badges/:badgeIdentifier/share/:channel", async (c) => {
    const badgeIdentifier = c.req.param("badgeIdentifier");
    const channel = c.req.param("channel");
    const db = resolveDatabase(c.env);
    const result = await loadPublicBadgeViewModel(db, c.env.BADGE_OBJECTS, badgeIdentifier);

    c.header("Cache-Control", "no-store");

    if (result.status === "not_found") {
      return renderAppPage(c, publicBadgeNotFoundPage(c.req.url), 404);
    }

    if (result.status === "redirect") {
      return c.redirect(`${result.canonicalPath}/share/${encodeURIComponent(channel)}`, 308);
    }

    const redirectUrl = shareRedirectUrlForChannel(c.req.url, result.value, channel);

    if (redirectUrl === null) {
      return c.text("Share action not supported", 404);
    }

    await recordPublicEngagement(db, result.value, "share_click", channel.replaceAll("-", "_"));
    return c.redirect(redirectUrl, 302);
  });

  app.get("/badges/:badgeIdentifier/summary", async (c) => {
    const badgeIdentifier = c.req.param("badgeIdentifier");
    const result = await loadPublicBadgeViewModel(
      resolveDatabase(c.env),
      c.env.BADGE_OBJECTS,
      badgeIdentifier,
    );

    c.header("Cache-Control", "no-store");

    if (result.status === "not_found") {
      return c.json(
        {
          error: "Badge not found",
        },
        404,
      );
    }

    if (result.status === "redirect") {
      if (result.canonicalPath.startsWith("/badges/")) {
        const canonicalBadgeIdentifier = result.canonicalPath.slice("/badges/".length);
        return c.redirect(`/badges/${canonicalBadgeIdentifier}/summary`, 308);
      }

      return c.json(
        {
          error: "Badge not found",
        },
        404,
      );
    }

    return c.json(publicBadgeSummaryPayload(c.req.url, result.value));
  });

  app.get("/showcase/:tenantId", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const requestedBadgeTemplateId = asNonEmptyString(c.req.query("badgeTemplateId"));
    const badgeTemplateId =
      requestedBadgeTemplateId ??
      (pathParams.tenantId === SAKAI_SHOWCASE_TENANT_ID ? SAKAI_SHOWCASE_TEMPLATE_ID : null);
    const db = resolveDatabase(c.env);
    const entries = await listPublicBadgeWallEntries(db, {
      tenantId: pathParams.tenantId,
      ...(badgeTemplateId === null ? {} : { badgeTemplateId }),
    });
    const entriesWithLifecycle: PublicBadgeWallEntryViewRecord[] = await Promise.all(
      entries.map(async (entry) => {
        const lifecycle = (await resolveAssertionLifecycleState(
          db,
          pathParams.tenantId,
          entry.assertionId,
        )) ?? {
          state: entry.revokedAt === null ? "active" : "revoked",
          source: entry.revokedAt === null ? "default_active" : "assertion_revocation",
          reasonCode: null,
          reason: null,
          transitionedAt: entry.revokedAt,
          revokedAt: entry.revokedAt,
        };

        return {
          ...entry,
          lifecycle,
        };
      }),
    );
    c.header("Cache-Control", "no-store");
    return renderAppPage(
      c,
      tenantBadgeWallPage(c.req.url, pathParams.tenantId, entriesWithLifecycle, badgeTemplateId),
    );
  });

  app.get("/showcase/:tenantId/criteria", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const requestedBadgeTemplateId = asNonEmptyString(c.req.query("badgeTemplateId"));
    const badgeTemplateId =
      requestedBadgeTemplateId ??
      (pathParams.tenantId === SAKAI_SHOWCASE_TENANT_ID ? SAKAI_SHOWCASE_TEMPLATE_ID : null);
    const db = resolveDatabase(c.env);
    const model = await buildPublicBadgeCriteriaRegistryViewModel(
      db,
      pathParams.tenantId,
      badgeTemplateId,
    );

    c.header("Cache-Control", "no-store");
    return renderAppPage(
      c,
      tenantBadgeCriteriaRegistryPage(c.req.url, pathParams.tenantId, model, badgeTemplateId),
    );
  });
};
