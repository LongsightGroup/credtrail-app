import type { ImmutableCredentialStore, JsonObject } from "@credtrail/core-domain";
import {
  indexBadgeIssuanceRuleVersionsByRuleId,
  listBadgeIssuanceRuleVersionApprovalEventsForVersions,
  listBadgeIssuanceRuleVersionApprovalStepsForVersions,
  listBadgeIssuanceRuleVersionsForRules,
  listBadgeIssuanceRules,
  listBadgeTemplateOwnershipEvents,
  listBadgeTemplates,
  listPublicBadgeWallEntries,
  listTenantOrgUnits,
  recordAssertionEngagementEvent,
  resolveBadgeIssuanceRuleVersionSelection,
  resolveAssertionLifecycleState,
  type SqlDatabase,
} from "@credtrail/db";
import { parseTenantPathParams } from "@credtrail/validation";
import type { Hono } from "hono";
import type { AppContext, AppEnv } from "../app";
import type { ResolveDatabase } from "../app/route-deps";
import { badgeNameFromCredential, issuerNameFromCredential } from "../badges/credential-display";
import type {
  PublicBadgeCriteriaRegistryViewModel,
  PublicBadgeCriteriaRuleViewRecord,
  PublicBadgeWallEntryViewRecord,
} from "../badges/public-badge-pages";
import { buildPublicBadgeWalletImportUrls } from "../badges/wallet-import-urls";
import { renderWalletQrCodeSvg, walletQrCodePayloadFromDeepLink } from "../badges/wallet-qr-code";
import { canonicalAppRequestUrl } from "../http/canonical-app-url";
import { renderAppPage, type AppPage } from "../ui/render-page";
import { linkedInAddToProfileUrl } from "../utils/display-format";
import { asString } from "../utils/value-parsers";

interface PublicBadgeRouteValue {
  assertion: {
    id: string;
    tenantId: string;
    publicId: string;
    issuedAt: string;
  };
  credential: JsonObject;
}

const publicRequestUrl = (c: AppContext): string => {
  return canonicalAppRequestUrl(c.env.PUBLIC_APP_ORIGIN, c.req.url);
};

interface RegisterPublicBadgeRoutesInput<PublicBadgeValue extends PublicBadgeRouteValue> {
  app: Hono<AppEnv>;
  resolveDatabase: ResolveDatabase;
  loadPublicBadgeViewModel: (
    db: SqlDatabase,
    badgeObjects: ImmutableCredentialStore,
    badgeIdentifier: string,
  ) => Promise<
    | {
        status: "not_found";
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

const indexRecordsByVersionId = <Record extends { readonly versionId: string }>(
  records: readonly Record[],
): ReadonlyMap<string, readonly Record[]> => {
  const recordsByVersionId = new Map<string, Record[]>();

  for (const record of records) {
    const indexedRecords = recordsByVersionId.get(record.versionId);

    if (indexedRecords === undefined) {
      recordsByVersionId.set(record.versionId, [record]);
      continue;
    }

    indexedRecords.push(record);
  }

  return recordsByVersionId;
};

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
  const versions = await listBadgeIssuanceRuleVersionsForRules(db, {
    tenantId,
    ruleIds: rules.map((rule) => rule.id),
  });
  const versionsByRuleId = indexBadgeIssuanceRuleVersionsByRuleId(versions);
  const ruleGovernanceSelections = rules.map((rule) => {
    const versionSelection = resolveBadgeIssuanceRuleVersionSelection({
      rule,
      versions: versionsByRuleId.get(rule.id) ?? [],
    });

    return {
      rule,
      versionSelection,
      governanceVersion: versionSelection.activeVersion ?? versionSelection.latestVersion,
    };
  });
  const governanceVersionIds = ruleGovernanceSelections.flatMap(({ governanceVersion }) =>
    governanceVersion === null ? [] : [governanceVersion.id],
  );
  const [approvalSteps, approvalEvents] = await Promise.all([
    listBadgeIssuanceRuleVersionApprovalStepsForVersions(db, {
      tenantId,
      versionIds: governanceVersionIds,
    }),
    listBadgeIssuanceRuleVersionApprovalEventsForVersions(db, {
      tenantId,
      versionIds: governanceVersionIds,
    }),
  ]);
  const approvalStepsByVersionId = indexRecordsByVersionId(approvalSteps);
  const approvalEventsByVersionId = indexRecordsByVersionId(approvalEvents);

  for (const { rule, versionSelection, governanceVersion } of ruleGovernanceSelections) {
    if (governanceVersion === null) {
      continue;
    }

    const badgeTemplateId = governanceVersion.snapshot.badgeTemplateId;
    const byTemplate = rulesByTemplateId.get(badgeTemplateId);
    const ruleRecord: PublicBadgeCriteriaRuleViewRecord = {
      rule,
      latestVersion: versionSelection.latestVersion,
      activeVersion: versionSelection.activeVersion,
      approvalSteps: approvalStepsByVersionId.get(governanceVersion.id) ?? [],
      approvalEvents: approvalEventsByVersionId.get(governanceVersion.id) ?? [],
    };

    if (byTemplate === undefined) {
      rulesByTemplateId.set(badgeTemplateId, [ruleRecord]);
      continue;
    }

    byTemplate.push(ruleRecord);
  }

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
    const publicBadgePath = `/badges/${encodeURIComponent(value.assertion.publicId)}`;
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

  app.get("/badges/:badgeIdentifier/wallet-qr.svg", async (c) => {
    const badgeIdentifier = c.req.param("badgeIdentifier");
    const result = await loadPublicBadgeViewModel(
      resolveDatabase(c.env),
      c.env.BADGE_OBJECTS,
      badgeIdentifier,
    );

    if (result.status === "not_found") {
      return c.text("Badge not found", 404);
    }

    const walletImportUrls = buildPublicBadgeWalletImportUrls(
      publicRequestUrl(c),
      result.value.assertion.publicId,
    );
    const svg = renderWalletQrCodeSvg(
      walletQrCodePayloadFromDeepLink(walletImportUrls.walletDeepLinkUrl),
    );

    c.header("Cache-Control", "public, max-age=300");
    c.header("Content-Type", "image/svg+xml; charset=utf-8");
    return c.body(svg);
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
      return renderAppPage(c, publicBadgeNotFoundPage(publicRequestUrl(c)), 404);
    }

    await recordPublicEngagement(resolveDatabase(c.env), result.value, "public_badge_view");
    return renderAppPage(c, publicBadgePage(publicRequestUrl(c), result.value));
  });

  app.get("/badges/:badgeIdentifier/share/:channel", async (c) => {
    const badgeIdentifier = c.req.param("badgeIdentifier");
    const channel = c.req.param("channel");
    const db = resolveDatabase(c.env);
    const result = await loadPublicBadgeViewModel(db, c.env.BADGE_OBJECTS, badgeIdentifier);

    c.header("Cache-Control", "no-store");

    if (result.status === "not_found") {
      return renderAppPage(c, publicBadgeNotFoundPage(publicRequestUrl(c)), 404);
    }

    const redirectUrl = shareRedirectUrlForChannel(publicRequestUrl(c), result.value, channel);

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

    return c.json(publicBadgeSummaryPayload(publicRequestUrl(c), result.value));
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
      tenantBadgeWallPage(
        publicRequestUrl(c),
        pathParams.tenantId,
        entriesWithLifecycle,
        badgeTemplateId,
      ),
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
      tenantBadgeCriteriaRegistryPage(
        publicRequestUrl(c),
        pathParams.tenantId,
        model,
        badgeTemplateId,
      ),
    );
  });
};
