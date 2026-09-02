import {
  findBadgeTemplateById,
  listBadgeTemplateImageRevisionCountsByTenant,
  listBadgeTemplateImageRevisions,
  listBadgeTemplates,
  type TenantMembershipRole,
} from "@credtrail/db";
import { consumeAdminListMessageFlash } from "../../admin/admin-list-message-flash";
import {
  buildBadgeTemplateListPath,
  parseBadgeTemplateListPageQuery,
} from "../../admin/badge-template-admin-helpers";
import {
  institutionAdminRuleTemplateEditorPage,
  institutionAdminRuleTemplatesPage,
} from "../../admin/institution-admin/page";
import type { BadgeTemplateHistoryPanel } from "../../admin/institution-admin-templates-page";
import type { AppContext } from "../../app/types";
import type { ResolveDatabase } from "../../app/route-deps";
import { loadBadgeTemplateHistoryPayload } from "../../badges/badge-template-history-payload";
import { resolveExpectedBadgeTemplateRevision } from "../../badges/badge-achievement-snapshot";
import { renderAppPage } from "../../ui/render-page";
import type { TenantGovernanceAdminAuth } from "./auth";
import type { TenantGovernanceAdminPageDataLoaders } from "./page-data";

type InstitutionAdminRuleTemplatesPageData = Parameters<
  typeof institutionAdminRuleTemplatesPage
>[0];

export const createTenantGovernanceTemplateAdminWorkspaces = (input: {
  resolveDatabase: ResolveDatabase;
  resolveInstitutionAdminAdminRole: TenantGovernanceAdminAuth["resolveInstitutionAdminAdminRole"];
  loadInstitutionAdminShellData: TenantGovernanceAdminPageDataLoaders["loadInstitutionAdminShellData"];
}) => {
  const { resolveDatabase, resolveInstitutionAdminAdminRole, loadInstitutionAdminShellData } =
    input;

  const loadInstitutionAdminTemplatesPageData = async (
    c: AppContext,
    tenantId: string,
    sessionUserId: string,
    membershipRole: TenantMembershipRole,
    input: {
      includeArchived: boolean;
    },
  ): Promise<InstitutionAdminRuleTemplatesPageData | Response> => {
    const shellData = await loadInstitutionAdminShellData(
      c,
      tenantId,
      sessionUserId,
      membershipRole,
    );

    if (shellData instanceof Response) {
      return shellData;
    }

    const db = resolveDatabase(c.env);
    const [badgeTemplates, badgeTemplateImageRevisionCounts] = await Promise.all([
      listBadgeTemplates(db, {
        tenantId,
        includeArchived: input.includeArchived,
      }),
      listBadgeTemplateImageRevisionCountsByTenant(db, tenantId),
    ]);
    const badgeTemplateImageRevisionCountsById = Object.fromEntries(
      badgeTemplateImageRevisionCounts.map((entry) => [entry.badgeTemplateId, entry.revisionCount]),
    );

    return {
      ...shellData,
      badgeTemplates,
      badgeTemplateImageRevisionCountsById,
      badgeTemplatesPage: {
        searchQuery: "",
        includeArchived: input.includeArchived,
        returnToRuleBuilder: false,
        deepLinkHistoryTemplateId: null,
        deepLinkHistoryUnavailable: null,
      },
    };
  };

  const renderInstitutionAdminTemplatesWorkspace = async (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ): Promise<Response> => {
    const roleCheck = await resolveInstitutionAdminAdminRole(c, tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { principal, membershipRole } = roleCheck;
    const searchQuery = (c.req.query("q") ?? "").trim();
    const includeArchived =
      c.req.query("includeArchived") === "1" || c.req.query("includeArchived") === "true";
    const returnToRuleBuilder = c.req.query("returnTo") === "rule-builder";
    const historyParam = c.req.query("history");
    const badgeTemplateIdParam = (c.req.query("badgeTemplateId") ?? "").trim();
    const historyDeepLinkRequested =
      (historyParam === "1" || historyParam === "true") && badgeTemplateIdParam.length > 0;

    if (historyDeepLinkRequested && !includeArchived) {
      const db = resolveDatabase(c.env);
      const deepLinkTemplate = await findBadgeTemplateById(db, tenantId, badgeTemplateIdParam);

      if (deepLinkTemplate?.isArchived === true) {
        const redirectUrl = new URL(c.req.url);
        redirectUrl.searchParams.set("includeArchived", "1");
        return c.redirect(redirectUrl.toString(), 302);
      }
    }

    let deepLinkHistoryTemplateId = historyDeepLinkRequested ? badgeTemplateIdParam : null;
    let deepLinkHistoryUnavailable: "not_found" | null = null;

    const pageData = await loadInstitutionAdminTemplatesPageData(
      c,
      tenantId,
      principal.userId,
      membershipRole,
      { includeArchived },
    );

    if (pageData instanceof Response) {
      return pageData;
    }

    // Title/slug/ID search is applied in memory after the tenant list loads. Replace with
    // DB-side filtering when template counts grow large (for example Sakai imports).
    const normalizedSearch = searchQuery.toLowerCase();
    let filteredTemplates =
      normalizedSearch.length === 0
        ? [...pageData.badgeTemplates]
        : pageData.badgeTemplates.filter((template) => {
            return (
              template.title.toLowerCase().includes(normalizedSearch) ||
              template.slug.toLowerCase().includes(normalizedSearch) ||
              template.id.toLowerCase().includes(normalizedSearch)
            );
          });

    if (deepLinkHistoryTemplateId !== null) {
      const deepLinkTemplate = pageData.badgeTemplates.find(
        (template) => template.id === deepLinkHistoryTemplateId,
      );

      if (deepLinkTemplate === undefined) {
        const db = resolveDatabase(c.env);
        const templateFromDb = await findBadgeTemplateById(db, tenantId, deepLinkHistoryTemplateId);

        if (templateFromDb === null) {
          deepLinkHistoryTemplateId = null;
          deepLinkHistoryUnavailable = "not_found";
        } else {
          filteredTemplates = [
            templateFromDb,
            ...filteredTemplates.filter((template) => template.id !== templateFromDb.id),
          ];
        }
      } else if (!filteredTemplates.some((template) => template.id === deepLinkTemplate.id)) {
        filteredTemplates = [
          deepLinkTemplate,
          ...filteredTemplates.filter((template) => template.id !== deepLinkTemplate.id),
        ];
      }
    }

    const autoOpenTemplateAuditTemplateId =
      deepLinkHistoryTemplateId !== null &&
      deepLinkHistoryUnavailable === null &&
      filteredTemplates.some((template) => template.id === deepLinkHistoryTemplateId)
        ? deepLinkHistoryTemplateId
        : null;

    let historyPanel: BadgeTemplateHistoryPanel | null = null;
    let historyLoadError: string | null = null;

    if (autoOpenTemplateAuditTemplateId !== null) {
      const historyTemplate =
        filteredTemplates.find((template) => template.id === autoOpenTemplateAuditTemplateId) ??
        (await findBadgeTemplateById(
          resolveDatabase(c.env),
          tenantId,
          autoOpenTemplateAuditTemplateId,
        ));

      if (historyTemplate === null) {
        historyLoadError = "Unable to load template history. Refresh and try again.";
      } else {
        const db = resolveDatabase(c.env);

        try {
          const [{ timeline, imageRevisionCount }, revisions] = await Promise.all([
            loadBadgeTemplateHistoryPayload(db, {
              tenantId,
              badgeTemplateId: historyTemplate.id,
              limit: 100,
            }),
            listBadgeTemplateImageRevisions(db, {
              tenantId,
              badgeTemplateId: historyTemplate.id,
              limit: 25,
            }),
          ]);

          historyPanel = {
            templateId: historyTemplate.id,
            templateTitle: historyTemplate.title,
            timeline,
            imageRevisionCount,
            revisions,
          };
        } catch {
          historyLoadError = "Unable to load template history. Refresh and try again.";
        }
      }
    }

    const flash = await consumeAdminListMessageFlash(c, {
      tenantId,
      userId: principal.userId,
      workspace: "badge_templates",
    });

    c.header("Cache-Control", "no-store");

    return renderAppPage(
      c,
      institutionAdminRuleTemplatesPage({
        ...pageData,
        badgeTemplates: filteredTemplates,
        badgeTemplatesPage: {
          searchQuery,
          includeArchived,
          returnToRuleBuilder,
          deepLinkHistoryTemplateId: autoOpenTemplateAuditTemplateId,
          deepLinkHistoryUnavailable,
          historyLoadError,
          listNotice: flash?.tone === "success" ? flash.message : null,
          listError: flash?.tone === "error" ? flash.message : null,
        },
        historyPanel,
      }),
    );
  };

  const parseBadgeTemplateEditorArtworkNotice = (
    query: Record<string, string | string[] | undefined>,
  ): { tone: "success" | "error"; message: string } | null => {
    const artworkErrorRaw = query["artworkError"];
    const artworkError =
      typeof artworkErrorRaw === "string"
        ? artworkErrorRaw.trim()
        : Array.isArray(artworkErrorRaw)
          ? (artworkErrorRaw[0]?.trim() ?? "")
          : "";

    if (artworkError.length > 0) {
      return { tone: "error", message: artworkError };
    }

    const artworkRaw = query["artwork"];
    const artwork =
      typeof artworkRaw === "string"
        ? artworkRaw.trim()
        : Array.isArray(artworkRaw)
          ? (artworkRaw[0]?.trim() ?? "")
          : "";

    if (artwork === "uploaded") {
      return { tone: "success", message: "Approved artwork uploaded." };
    }

    if (artwork === "applied") {
      return { tone: "success", message: "Generated draft applied as approved artwork." };
    }

    return null;
  };

  const parseBadgeTemplateEditorDetailsNotice = (
    query: Record<string, string | string[] | undefined>,
  ): { tone: "success" | "error"; message: string } | null => {
    const detailsErrorRaw = query["detailsError"];
    const detailsError =
      typeof detailsErrorRaw === "string"
        ? detailsErrorRaw.trim()
        : Array.isArray(detailsErrorRaw)
          ? (detailsErrorRaw[0]?.trim() ?? "")
          : "";

    if (detailsError.length > 0) {
      return { tone: "error", message: detailsError };
    }

    const detailsRaw = query["details"];
    const details =
      typeof detailsRaw === "string"
        ? detailsRaw.trim()
        : Array.isArray(detailsRaw)
          ? (detailsRaw[0]?.trim() ?? "")
          : "";

    if (details === "created") {
      return {
        tone: "success",
        message: "Badge template created. Add artwork before using it in rules.",
      };
    }

    if (details === "saved") {
      return { tone: "success", message: "Template details saved." };
    }

    return null;
  };

  const renderInstitutionAdminTemplateEditorWorkspace = async (
    c: AppContext,
    tenantId: string,
    badgeTemplateId: string,
    nextPath: string,
  ): Promise<Response> => {
    const roleCheck = await resolveInstitutionAdminAdminRole(c, tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { principal, membershipRole } = roleCheck;
    const shellData = await loadInstitutionAdminShellData(
      c,
      tenantId,
      principal.userId,
      membershipRole,
    );

    if (shellData instanceof Response) {
      return shellData;
    }

    const db = resolveDatabase(c.env);
    const [badgeTemplate, imageRevisionCounts] = await Promise.all([
      findBadgeTemplateById(db, tenantId, badgeTemplateId),
      listBadgeTemplateImageRevisionCountsByTenant(db, tenantId),
    ]);

    if (badgeTemplate === null) {
      return c.redirect(buildBadgeTemplateListPath(tenantId), 302);
    }

    const revisionCount =
      imageRevisionCounts.find((entry) => entry.badgeTemplateId === badgeTemplate.id)
        ?.revisionCount ?? 0;
    const artworkResolution = await resolveExpectedBadgeTemplateRevision({
      store: c.env.BADGE_OBJECTS,
      publicAppOrigin: c.env.PUBLIC_APP_ORIGIN,
      template: badgeTemplate,
    });

    c.header("Cache-Control", "no-store");

    return renderAppPage(
      c,
      institutionAdminRuleTemplateEditorPage({
        ...shellData,
        badgeTemplate,
        badgeTemplateImageRevisionCount: revisionCount,
        badgeTemplateArtworkReadiness: artworkResolution.status,
        returnToRuleBuilder: c.req.query("returnTo") === "rule-builder",
        listPageQuery: parseBadgeTemplateListPageQuery(c.req.query()),
        detailsNotice: parseBadgeTemplateEditorDetailsNotice(c.req.query()),
        artworkNotice: parseBadgeTemplateEditorArtworkNotice(c.req.query()),
      }),
    );
  };

  return {
    loadInstitutionAdminTemplatesPageData,
    renderInstitutionAdminTemplatesWorkspace,
    renderInstitutionAdminTemplateEditorWorkspace,
  };
};
