import {
  approveLearnerPathwayCompletionReview,
  createLearnerPathwayDraft,
  createNextLearnerPathwayDraft,
  findLearnerPathwayById,
  findLearnerPathwayDraft,
  findLearnerPathwayVersion,
  listBadgeTemplates,
  listLearnerPathwayAdminProgress,
  listLearnerPathwayRequirements,
  listLearnerPathways,
  listLearnerPathwayVersions,
  listTenantOrgUnits,
  LearnerPathwayCommandError,
  publishLearnerPathway,
  resolveLearnerProfileForIdentity,
  retireLearnerPathway,
  revokeLearnerPathwayRequirementWaiver,
  enrollLearnerInPathway,
  isLearnerPathwayCommandError,
  updateLearnerPathwayDraft,
  waiveLearnerPathwayRequirement,
  type BadgeTemplateRecord,
  type LearnerPathwayRequirementInput,
  type TenantMembershipRole,
  type TenantRecord,
} from "@credtrail/db";
import {
  parseCreateLearnerPathwayRequest,
  parseEnrollLearnerPathwayRequest,
  parseLearnerPathwayEnrollmentPathParams,
  parseLearnerPathwayPathParams,
  parseLearnerPathwayVersionPathParams,
  parseLearnerPathwayCompletionReviewRequest,
  parseRetireLearnerPathwayRequest,
  parseRevokeLearnerPathwayRequirementWaiverRequest,
  parseTenantPathParams,
  parseWaiveLearnerPathwayRequirementRequest,
} from "@credtrail/validation";
import type { Hono } from "hono";
import { z } from "zod";
import type { AppContext, AppEnv } from "../app";
import type { ResolveDatabase } from "../app/route-deps";
import {
  learnerPathwayBuilderPage,
  learnerPathwayDetailPage,
  learnerPathwaysAdminPage,
} from "../admin/learner-pathway-pages";
import { renderAppPage } from "../ui/render-page";

interface PathwayAdminShellData {
  tenant: TenantRecord;
  userId: string;
  userEmail?: string | undefined;
  membershipRole: TenantMembershipRole;
  switchOrganizationPath?: string | null | undefined;
}

interface RegisterTenantLearnerPathwayAdminRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: ResolveDatabase;
  resolveInstitutionAdminAdminRole: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ) => Promise<
    | Response
    | {
        principal: { userId: string };
        membershipRole: TenantMembershipRole;
      }
  >;
  loadInstitutionAdminShellData: (
    c: AppContext,
    tenantId: string,
    sessionUserId: string,
    membershipRole: TenantMembershipRole,
  ) => Promise<PathwayAdminShellData | Response>;
}

const noticeSchema = z
  .enum([
    "created",
    "updated",
    "published",
    "versioned",
    "retired",
    "enrolled",
    "waived",
    "waiver_revoked",
    "reviewed",
  ])
  .nullable()
  .catch(null);
const errorSchema = z
  .enum(["invalid", "not_found", "conflict", "not_ready"])
  .nullable()
  .catch(null);

const noticeMessage = (value: string | undefined): string | null => {
  switch (noticeSchema.parse(value ?? null)) {
    case "created":
      return "Pathway draft created. Review it before publishing.";
    case "updated":
      return "Pathway draft updated.";
    case "published":
      return "Pathway version published. Its definition is now immutable.";
    case "versioned":
      return "A new draft version is ready to edit.";
    case "retired":
      return "Pathway retired. Existing learner history remains available.";
    case "enrolled":
      return "Learner enrolled and evaluated against current evidence.";
    case "waived":
      return "Approved exception recorded and pathway progress recalculated.";
    case "waiver_revoked":
      return "Approved exception revoked and pathway progress recalculated.";
    case "reviewed":
      return "Completion review approved. The final credential is eligible for administrator issuance.";
    case null:
      return null;
  }
};

const errorMessage = (value: string | undefined): string | null => {
  switch (errorSchema.parse(value ?? null)) {
    case "invalid":
      return "Check each workflow choice and try again.";
    case "not_found":
      return "That pathway or learner record could not be found in this organization.";
    case "conflict":
      return "This action conflicts with the pathway’s current state.";
    case "not_ready":
      return "Finish the required pathway setup before publishing.";
    case null:
      return null;
  }
};

const pathwaysPath = (tenantId: string): string =>
  `/tenants/${encodeURIComponent(tenantId)}/admin/operations/pathways`;

const pathwayPath = (tenantId: string, pathwayId: string): string =>
  `${pathwaysPath(tenantId)}/${encodeURIComponent(pathwayId)}`;

const redirectWith = (
  c: AppContext,
  path: string,
  key: "notice" | "error",
  value: string,
): Response => {
  const url = new URL(path, c.req.url);
  url.searchParams.set(key, value);
  return c.redirect(`${url.pathname}${url.search}`, 303);
};

const pathwayFailureCode = (cause: unknown): "invalid" | "not_found" | "conflict" | "not_ready" => {
  if (isLearnerPathwayCommandError(cause)) {
    return cause.code;
  }

  if (cause instanceof z.ZodError) {
    return "invalid";
  }

  throw cause;
};

const invalidPathwayForm = (message: string): never => {
  throw new LearnerPathwayCommandError("invalid", message);
};

const readUrlEncodedForm = async (c: AppContext): Promise<URLSearchParams> => {
  const contentType = c.req.header("content-type")?.toLowerCase() ?? "";

  if (!contentType.includes("application/x-www-form-urlencoded")) {
    invalidPathwayForm("Expected a form submission");
  }

  return new URLSearchParams(await c.req.text());
};

const recordTypeLabels = new Map<string, string>([
  ["course", "Verified course completion"],
  ["certificate", "Verified certificate"],
  ["license", "Verified license"],
  ["competency", "Verified competency"],
  ["work_based_learning", "Verified work-based learning"],
  ["experience", "Verified experience"],
  ["membership", "Verified membership"],
  ["custom", "Other institution-verified record"],
]);

const requirementFromSelection = (
  selection: string,
  badgeTemplates: readonly BadgeTemplateRecord[],
): LearnerPathwayRequirementInput => {
  const separatorIndex = selection.indexOf(":");
  const kind = separatorIndex < 0 ? "" : selection.slice(0, separatorIndex);
  const target = separatorIndex < 0 ? undefined : selection.slice(separatorIndex + 1);

  if (target === undefined || target.length === 0) {
    return invalidPathwayForm("Invalid requirement selection");
  }

  if (kind === "badge") {
    const template = badgeTemplates.find((entry) => entry.id === target && !entry.isArchived);

    if (template === undefined) {
      return invalidPathwayForm("Badge template is not available");
    }

    return {
      requirementKind: "badge_template",
      badgeTemplateId: template.id,
      title: template.title,
      ...(template.description === null ? {} : { description: template.description }),
    };
  }

  if (kind === "record") {
    const label = recordTypeLabels.get(target);

    if (label === undefined) {
      return invalidPathwayForm("Learner record type is not available");
    }

    return { requirementKind: "learner_record", learnerRecordType: target, title: label };
  }

  return invalidPathwayForm("Invalid requirement selection");
};

const parsePathwayForm = (
  form: URLSearchParams,
  badgeTemplates: readonly BadgeTemplateRecord[],
): ReturnType<typeof parseCreateLearnerPathwayRequest> => {
  const requirements = form
    .getAll("requirement")
    .map((value) => value.trim())
    .filter((value) => value.length > 0)
    .map((value) => requirementFromSelection(value, badgeTemplates));
  const finalBadgeTemplateId = form.get("finalBadgeTemplateId")?.trim() ?? "";

  return parseCreateLearnerPathwayRequest({
    ownerOrgUnitId: form.get("ownerOrgUnitId") ?? undefined,
    title: form.get("title") ?? undefined,
    learnerDescription: form.get("learnerDescription") ?? undefined,
    completionBehavior: form.get("completionBehavior") ?? undefined,
    ...(finalBadgeTemplateId.length === 0 ? {} : { finalBadgeTemplateId }),
    requirements,
  });
};

export const registerTenantLearnerPathwayAdminRoutes = (
  input: RegisterTenantLearnerPathwayAdminRoutesInput,
): void => {
  const loadAuthorizedShell = async (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ): Promise<
    | Response
    | { shell: PathwayAdminShellData; actorUserId: string; db: ReturnType<ResolveDatabase> }
  > => {
    const role = await input.resolveInstitutionAdminAdminRole(c, tenantId, nextPath);

    if (role instanceof Response) {
      return role;
    }

    const shell = await input.loadInstitutionAdminShellData(
      c,
      tenantId,
      role.principal.userId,
      role.membershipRole,
    );

    if (shell instanceof Response) {
      return shell;
    }

    return { shell, actorUserId: role.principal.userId, db: input.resolveDatabase(c.env) };
  };

  input.app.get("/tenants/:tenantId/admin/operations/pathways", async (c) => {
    const { tenantId } = parseTenantPathParams(c.req.param());
    const basePath = pathwaysPath(tenantId);
    const authorized = await loadAuthorizedShell(c, tenantId, basePath);

    if (authorized instanceof Response) {
      return authorized;
    }

    const pathways = await listLearnerPathways(authorized.db, tenantId);
    c.header("Cache-Control", "no-store");
    return renderAppPage(
      c,
      learnerPathwaysAdminPage({
        ...authorized.shell,
        pathways,
        notice: noticeMessage(c.req.query("notice")),
        error: errorMessage(c.req.query("error")),
      }),
    );
  });

  input.app.get("/tenants/:tenantId/admin/operations/pathways/new", async (c) => {
    const { tenantId } = parseTenantPathParams(c.req.param());
    const nextPath = `${pathwaysPath(tenantId)}/new`;
    const authorized = await loadAuthorizedShell(c, tenantId, nextPath);

    if (authorized instanceof Response) {
      return authorized;
    }

    const [orgUnits, badgeTemplates] = await Promise.all([
      listTenantOrgUnits(authorized.db, { tenantId }),
      listBadgeTemplates(authorized.db, { tenantId, includeArchived: false }),
    ]);
    return renderAppPage(
      c,
      learnerPathwayBuilderPage({
        ...authorized.shell,
        orgUnits,
        badgeTemplates,
        draft: null,
        requirements: [],
        error: errorMessage(c.req.query("error")),
      }),
    );
  });

  input.app.post("/tenants/:tenantId/admin/operations/pathways", async (c) => {
    const { tenantId } = parseTenantPathParams(c.req.param());
    const basePath = pathwaysPath(tenantId);
    const authorized = await loadAuthorizedShell(c, tenantId, basePath);

    if (authorized instanceof Response) {
      return authorized;
    }

    try {
      const badgeTemplates = await listBadgeTemplates(authorized.db, {
        tenantId,
        includeArchived: false,
      });
      const request = parsePathwayForm(await readUrlEncodedForm(c), badgeTemplates);
      const pathway = await createLearnerPathwayDraft(authorized.db, {
        tenantId,
        actorUserId: authorized.actorUserId,
        ...request,
      });
      return redirectWith(c, pathwayPath(tenantId, pathway.id), "notice", "created");
    } catch (cause: unknown) {
      return redirectWith(c, `${basePath}/new`, "error", pathwayFailureCode(cause));
    }
  });

  input.app.get("/tenants/:tenantId/admin/operations/pathways/:pathwayId/edit", async (c) => {
    const { tenantId, pathwayId } = parseLearnerPathwayPathParams(c.req.param());
    const nextPath = `${pathwayPath(tenantId, pathwayId)}/edit`;
    const authorized = await loadAuthorizedShell(c, tenantId, nextPath);

    if (authorized instanceof Response) {
      return authorized;
    }

    const draft = await findLearnerPathwayDraft(authorized.db, tenantId, pathwayId);

    if (draft === null) {
      return redirectWith(c, pathwaysPath(tenantId), "error", "not_found");
    }

    const [orgUnits, badgeTemplates, requirements] = await Promise.all([
      listTenantOrgUnits(authorized.db, { tenantId }),
      listBadgeTemplates(authorized.db, { tenantId, includeArchived: false }),
      listLearnerPathwayRequirements(authorized.db, tenantId, draft.version.id),
    ]);
    return renderAppPage(
      c,
      learnerPathwayBuilderPage({
        ...authorized.shell,
        orgUnits,
        badgeTemplates,
        draft,
        requirements,
        error: errorMessage(c.req.query("error")),
      }),
    );
  });

  input.app.post("/tenants/:tenantId/admin/operations/pathways/:pathwayId/edit", async (c) => {
    const { tenantId, pathwayId } = parseLearnerPathwayPathParams(c.req.param());
    const editPath = `${pathwayPath(tenantId, pathwayId)}/edit`;
    const authorized = await loadAuthorizedShell(c, tenantId, editPath);

    if (authorized instanceof Response) {
      return authorized;
    }

    try {
      const badgeTemplates = await listBadgeTemplates(authorized.db, {
        tenantId,
        includeArchived: false,
      });
      const request = parsePathwayForm(await readUrlEncodedForm(c), badgeTemplates);
      await updateLearnerPathwayDraft(authorized.db, {
        tenantId,
        pathwayId,
        actorUserId: authorized.actorUserId,
        ...request,
      });
      return redirectWith(c, pathwayPath(tenantId, pathwayId), "notice", "updated");
    } catch (cause: unknown) {
      return redirectWith(c, editPath, "error", pathwayFailureCode(cause));
    }
  });

  input.app.get(
    "/tenants/:tenantId/admin/operations/pathways/:pathwayId/versions/:pathwayVersionId",
    async (c) => {
      const { tenantId, pathwayId, pathwayVersionId } = parseLearnerPathwayVersionPathParams(
        c.req.param(),
      );
      const detailPath = pathwayPath(tenantId, pathwayId);
      const versionPath = `${detailPath}/versions/${encodeURIComponent(pathwayVersionId)}`;
      const authorized = await loadAuthorizedShell(c, tenantId, versionPath);

      if (authorized instanceof Response) {
        return authorized;
      }

      const pathway = await findLearnerPathwayVersion(authorized.db, {
        tenantId,
        pathwayId,
        pathwayVersionId,
      });

      if (pathway === null) {
        return redirectWith(c, detailPath, "error", "not_found");
      }

      const [requirements, versions] = await Promise.all([
        listLearnerPathwayRequirements(authorized.db, tenantId, pathway.version.id),
        listLearnerPathwayVersions(authorized.db, { tenantId, pathwayId }),
      ]);
      c.header("Cache-Control", "no-store");
      return renderAppPage(
        c,
        learnerPathwayDetailPage({
          ...authorized.shell,
          pathway,
          requirements,
          versions,
          progress: [],
          notice: null,
          error: null,
          isHistoricalView: true,
        }),
      );
    },
  );

  input.app.get("/tenants/:tenantId/admin/operations/pathways/:pathwayId", async (c) => {
    const { tenantId, pathwayId } = parseLearnerPathwayPathParams(c.req.param());
    const detailPath = pathwayPath(tenantId, pathwayId);
    const authorized = await loadAuthorizedShell(c, tenantId, detailPath);

    if (authorized instanceof Response) {
      return authorized;
    }

    const pathway =
      (await findLearnerPathwayDraft(authorized.db, tenantId, pathwayId)) ??
      (await findLearnerPathwayById(authorized.db, tenantId, pathwayId));

    if (pathway === null) {
      return redirectWith(c, pathwaysPath(tenantId), "error", "not_found");
    }

    const [requirements, versions, progress] = await Promise.all([
      listLearnerPathwayRequirements(authorized.db, tenantId, pathway.version.id),
      listLearnerPathwayVersions(authorized.db, { tenantId, pathwayId }),
      listLearnerPathwayAdminProgress(authorized.db, { tenantId, pathwayId }),
    ]);
    c.header("Cache-Control", "no-store");
    return renderAppPage(
      c,
      learnerPathwayDetailPage({
        ...authorized.shell,
        pathway,
        requirements,
        versions,
        progress,
        notice: noticeMessage(c.req.query("notice")),
        error: errorMessage(c.req.query("error")),
      }),
    );
  });

  input.app.post("/tenants/:tenantId/admin/operations/pathways/:pathwayId/publish", async (c) => {
    const { tenantId, pathwayId } = parseLearnerPathwayPathParams(c.req.param());
    const detailPath = pathwayPath(tenantId, pathwayId);
    const authorized = await loadAuthorizedShell(c, tenantId, detailPath);

    if (authorized instanceof Response) {
      return authorized;
    }

    try {
      await publishLearnerPathway(authorized.db, {
        tenantId,
        pathwayId,
        actorUserId: authorized.actorUserId,
      });
      return redirectWith(c, detailPath, "notice", "published");
    } catch (cause: unknown) {
      return redirectWith(c, detailPath, "error", pathwayFailureCode(cause));
    }
  });

  input.app.post("/tenants/:tenantId/admin/operations/pathways/:pathwayId/versions", async (c) => {
    const { tenantId, pathwayId } = parseLearnerPathwayPathParams(c.req.param());
    const detailPath = pathwayPath(tenantId, pathwayId);
    const authorized = await loadAuthorizedShell(c, tenantId, detailPath);

    if (authorized instanceof Response) {
      return authorized;
    }

    try {
      await createNextLearnerPathwayDraft(authorized.db, {
        tenantId,
        pathwayId,
        actorUserId: authorized.actorUserId,
      });
      return redirectWith(c, `${detailPath}/edit`, "notice", "versioned");
    } catch (cause: unknown) {
      return redirectWith(c, detailPath, "error", pathwayFailureCode(cause));
    }
  });

  input.app.post("/tenants/:tenantId/admin/operations/pathways/:pathwayId/retire", async (c) => {
    const { tenantId, pathwayId } = parseLearnerPathwayPathParams(c.req.param());
    const authorized = await loadAuthorizedShell(c, tenantId, pathwayPath(tenantId, pathwayId));

    if (authorized instanceof Response) {
      return authorized;
    }

    try {
      const form = await readUrlEncodedForm(c);
      parseRetireLearnerPathwayRequest({ confirmation: form.get("confirmation") });
      await retireLearnerPathway(authorized.db, {
        tenantId,
        pathwayId,
        actorUserId: authorized.actorUserId,
      });
      return redirectWith(c, pathwaysPath(tenantId), "notice", "retired");
    } catch (cause: unknown) {
      return redirectWith(c, pathwayPath(tenantId, pathwayId), "error", pathwayFailureCode(cause));
    }
  });

  input.app.post("/tenants/:tenantId/admin/operations/pathways/:pathwayId/enroll", async (c) => {
    const { tenantId, pathwayId } = parseLearnerPathwayPathParams(c.req.param());
    const detailPath = pathwayPath(tenantId, pathwayId);
    const authorized = await loadAuthorizedShell(c, tenantId, detailPath);

    if (authorized instanceof Response) {
      return authorized;
    }

    try {
      const form = await readUrlEncodedForm(c);
      const request = parseEnrollLearnerPathwayRequest({ learnerEmail: form.get("learnerEmail") });
      const learner = await resolveLearnerProfileForIdentity(authorized.db, {
        tenantId,
        identityType: "email",
        identityValue: request.learnerEmail,
      });
      await enrollLearnerInPathway(authorized.db, {
        tenantId,
        pathwayId,
        learnerProfileId: learner.id,
        actorUserId: authorized.actorUserId,
      });
      return redirectWith(c, detailPath, "notice", "enrolled");
    } catch (cause: unknown) {
      return redirectWith(c, detailPath, "error", pathwayFailureCode(cause));
    }
  });

  input.app.post(
    "/tenants/:tenantId/admin/operations/pathways/:pathwayId/enrollments/:enrollmentId/waivers",
    async (c) => {
      const { tenantId, pathwayId } = parseLearnerPathwayPathParams(c.req.param());
      const { enrollmentId } = parseLearnerPathwayEnrollmentPathParams(c.req.param());
      const detailPath = pathwayPath(tenantId, pathwayId);
      const authorized = await loadAuthorizedShell(c, tenantId, detailPath);

      if (authorized instanceof Response) {
        return authorized;
      }

      try {
        const form = await readUrlEncodedForm(c);
        const request = parseWaiveLearnerPathwayRequirementRequest({
          requirementId: form.get("requirementId"),
          reason: form.get("reason"),
        });
        await waiveLearnerPathwayRequirement(authorized.db, {
          tenantId,
          pathwayId,
          enrollmentId,
          actorUserId: authorized.actorUserId,
          ...request,
        });
        return redirectWith(c, detailPath, "notice", "waived");
      } catch (cause: unknown) {
        return redirectWith(c, detailPath, "error", pathwayFailureCode(cause));
      }
    },
  );

  input.app.post(
    "/tenants/:tenantId/admin/operations/pathways/:pathwayId/enrollments/:enrollmentId/waivers/revoke",
    async (c) => {
      const { tenantId, pathwayId } = parseLearnerPathwayPathParams(c.req.param());
      const { enrollmentId } = parseLearnerPathwayEnrollmentPathParams(c.req.param());
      const detailPath = pathwayPath(tenantId, pathwayId);
      const authorized = await loadAuthorizedShell(c, tenantId, detailPath);

      if (authorized instanceof Response) {
        return authorized;
      }

      try {
        const form = await readUrlEncodedForm(c);
        const request = parseRevokeLearnerPathwayRequirementWaiverRequest({
          requirementId: form.get("requirementId"),
          decision: form.get("decision"),
        });
        await revokeLearnerPathwayRequirementWaiver(authorized.db, {
          tenantId,
          pathwayId,
          enrollmentId,
          actorUserId: authorized.actorUserId,
          requirementId: request.requirementId,
        });
        return redirectWith(c, detailPath, "notice", "waiver_revoked");
      } catch (cause: unknown) {
        return redirectWith(c, detailPath, "error", pathwayFailureCode(cause));
      }
    },
  );

  input.app.post(
    "/tenants/:tenantId/admin/operations/pathways/:pathwayId/enrollments/:enrollmentId/completion-review",
    async (c) => {
      const { tenantId, pathwayId } = parseLearnerPathwayPathParams(c.req.param());
      const { enrollmentId } = parseLearnerPathwayEnrollmentPathParams(c.req.param());
      const detailPath = pathwayPath(tenantId, pathwayId);
      const authorized = await loadAuthorizedShell(c, tenantId, detailPath);

      if (authorized instanceof Response) {
        return authorized;
      }

      try {
        const form = await readUrlEncodedForm(c);
        parseLearnerPathwayCompletionReviewRequest({ decision: form.get("decision") });
        await approveLearnerPathwayCompletionReview(authorized.db, {
          tenantId,
          pathwayId,
          enrollmentId,
          actorUserId: authorized.actorUserId,
        });
        return redirectWith(c, detailPath, "notice", "reviewed");
      } catch (cause: unknown) {
        return redirectWith(c, detailPath, "error", pathwayFailureCode(cause));
      }
    },
  );
};
