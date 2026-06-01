import {
  listBadgeTemplates,
  setBadgeTemplateArchivedState,
  type SqlDatabase,
  type TenantMembershipOrgUnitScopeRole,
  type TenantMembershipRole,
} from "@credtrail/db";
import {
  parseBadgeTemplateImageRevisionPathParams,
  parseBadgeTemplatePathParams,
  parseCreateBadgeTemplateRequest,
  parseUpdateBadgeTemplateRequest,
} from "@credtrail/validation";
import type { Hono } from "hono";
import {
  setAdminListMessageFlash,
  type AdminListMessageTone,
} from "../admin/admin-list-message-flash";
import type { AppBindings, AppContext, AppEnv } from "../app";
import {
  badgeTemplateListPageUrl,
  deriveUniqueBadgeTemplateSlug,
  parseBadgeTemplateListPageQuery,
} from "../admin/badge-template-admin-helpers";
import { restoreBadgeTemplateImageRevision } from "../badges/badge-template-image-revision-restore";
import {
  createBadgeTemplateWithAudit,
  isBadgeTemplateSlugConflict,
  updateBadgeTemplateWithAudit,
} from "../badges/badge-template-write-workflows";
import {
  formHasTrustEdMetadataFields,
  trustEdMetadataFromForm,
} from "../badges/trusted-credential-form-mapper";
import { parseTrustEdCredentialMetadataJson } from "../badges/trusted-credential-metadata";
import { withBadgeTemplateIssuerAccess } from "./badge-template-admin-access";

interface RegisterBadgeTemplateListAdminRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  defaultInstitutionOrgUnitId: (tenantId: string) => string;
  requireScopedOrgUnitPermission: (
    c: AppContext,
    input: {
      db: SqlDatabase;
      tenantId: string;
      userId: string;
      membershipRole: TenantMembershipRole;
      orgUnitId: string;
      requiredRole: TenantMembershipOrgUnitScopeRole;
      allowWhenNoScopes?: boolean;
    },
  ) => Promise<Response | null>;
  resolveInstitutionAdminAdminRole: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ) => Promise<
    | Response
    | {
        session: { userId: string };
        membershipRole: TenantMembershipRole;
      }
  >;
}

const buildTemplateListPath = (tenantId: string): string => {
  return `/tenants/${encodeURIComponent(tenantId)}/admin/rules/templates`;
};

const buildTemplateEditorPath = (tenantId: string, badgeTemplateId: string): string => {
  return `${buildTemplateListPath(tenantId)}/${encodeURIComponent(badgeTemplateId)}`;
};

const redirectToTemplateList = (
  c: AppContext,
  tenantId: string,
  listPageQuery: ReturnType<typeof parseBadgeTemplateListPageQuery>,
  extra?: Record<string, string>,
): Response => {
  const location = badgeTemplateListPageUrl(buildTemplateListPath(tenantId), listPageQuery, extra);

  return c.redirect(location, 303);
};

const redirectToTemplateListWithFlash = async (
  c: AppContext,
  input: {
    tenantId: string;
    userId: string;
    listPageQuery: ReturnType<typeof parseBadgeTemplateListPageQuery>;
    tone: AdminListMessageTone;
    message: string;
    extra?: Record<string, string>;
  },
): Promise<Response> => {
  await setAdminListMessageFlash(c, {
    tenantId: input.tenantId,
    userId: input.userId,
    workspace: "badge_templates",
    tone: input.tone,
    message: input.message,
  });

  return redirectToTemplateList(c, input.tenantId, input.listPageQuery, input.extra);
};

const redirectToTemplateEditor = (
  c: AppContext,
  tenantId: string,
  badgeTemplateId: string,
  query: Record<string, string>,
  hash?: string,
): Response => {
  const location = new URL(buildTemplateEditorPath(tenantId, badgeTemplateId), c.req.url);

  for (const [key, value] of Object.entries(query)) {
    if (value.length > 0) {
      location.searchParams.set(key, value);
    }
  }

  if (hash !== undefined && hash.length > 0) {
    location.hash = hash;
  }

  return c.redirect(`${location.pathname}${location.search}${location.hash}`, 303);
};

export const registerBadgeTemplateListAdminRoutes = (
  input: RegisterBadgeTemplateListAdminRoutesInput,
): void => {
  const {
    app,
    resolveDatabase,
    defaultInstitutionOrgUnitId,
    requireScopedOrgUnitPermission,
    resolveInstitutionAdminAdminRole,
  } = input;

  const optionalFormText = (formData: FormData, name: string): string | undefined => {
    const value = formData.get(name);

    if (typeof value !== "string") {
      return undefined;
    }

    const trimmed = value.trim();

    return trimmed.length === 0 ? undefined : trimmed;
  };

  const nullableFormText = (formData: FormData, name: string): string | null => {
    return optionalFormText(formData, name) ?? null;
  };

  app.post("/tenants/:tenantId/admin/rules/templates", async (c) => {
    const tenantId = c.req.param("tenantId").trim();
    const listPageQuery = parseBadgeTemplateListPageQuery(c.req.query());
    const listPath = buildTemplateListPath(tenantId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, tenantId, listPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const db = resolveDatabase(c.env);
    const formData = await c.req.formData();
    const title = optionalFormText(formData, "title") ?? "";
    const existingTemplates = await listBadgeTemplates(db, {
      tenantId,
      includeArchived: true,
    });
    const slug = deriveUniqueBadgeTemplateSlug(title, existingTemplates);

    let request: ReturnType<typeof parseCreateBadgeTemplateRequest>;

    try {
      request = parseCreateBadgeTemplateRequest({
        slug,
        title,
        description: optionalFormText(formData, "description"),
        ownerOrgUnitId: defaultInstitutionOrgUnitId(tenantId),
      });
    } catch {
      return redirectToTemplateListWithFlash(c, {
        tenantId,
        userId: roleCheck.session.userId,
        listPageQuery,
        tone: "error",
        message: "Enter a badge name before creating the template.",
      });
    }

    const { session, membershipRole } = roleCheck;
    const targetOwnerOrgUnitId = request.ownerOrgUnitId ?? defaultInstitutionOrgUnitId(tenantId);
    const scopeCheck = await requireScopedOrgUnitPermission(c, {
      db,
      tenantId,
      userId: session.userId,
      membershipRole,
      orgUnitId: targetOwnerOrgUnitId,
      requiredRole: "issuer",
      allowWhenNoScopes: true,
    });

    if (scopeCheck !== null) {
      return scopeCheck;
    }

    try {
      const template = await createBadgeTemplateWithAudit(db, {
        tenantId,
        request,
        actorUserId: session.userId,
        membershipRole,
      });

      return redirectToTemplateEditor(
        c,
        tenantId,
        template.id,
        { details: "created" },
        "template-editor-artwork",
      );
    } catch (error: unknown) {
      if (isBadgeTemplateSlugConflict(error)) {
        return redirectToTemplateListWithFlash(c, {
          tenantId,
          userId: session.userId,
          listPageQuery,
          tone: "error",
          message: "A badge template with that URL key already exists. Try a more specific name.",
        });
      }

      throw error;
    }
  });

  app.post("/tenants/:tenantId/admin/rules/templates/:badgeTemplateId/details", async (c) => {
    const pathParams = parseBadgeTemplatePathParams(c.req.param());
    const listPageQuery = parseBadgeTemplateListPageQuery(c.req.query());
    const editorPath = buildTemplateEditorPath(pathParams.tenantId, pathParams.badgeTemplateId);

    return withBadgeTemplateIssuerAccess(
      {
        c,
        tenantId: pathParams.tenantId,
        badgeTemplateId: pathParams.badgeTemplateId,
        nextPath: editorPath,
        resolveDatabase,
        resolveInstitutionAdminAdminRole,
        requireScopedOrgUnitPermission,
        notFound: ({ session }) =>
          redirectToTemplateListWithFlash(c, {
            tenantId: pathParams.tenantId,
            userId: session.userId,
            listPageQuery,
            tone: "error",
            message: "Badge template not found",
          }),
      },
      async ({ db, session, membershipRole, template: existingTemplate }) => {
        const formData = await c.req.formData();

        let request: ReturnType<typeof parseUpdateBadgeTemplateRequest>;

        try {
          const trustedCredentialMetadata = formHasTrustEdMetadataFields(formData)
            ? trustEdMetadataFromForm(
                formData,
                parseTrustEdCredentialMetadataJson(existingTemplate.trustedCredentialMetadataJson),
              )
            : undefined;
          request = parseUpdateBadgeTemplateRequest({
            title: optionalFormText(formData, "title"),
            slug: optionalFormText(formData, "slug"),
            description: nullableFormText(formData, "description"),
            criteriaUri: nullableFormText(formData, "criteriaUri"),
            trustedCredentialMetadata,
          });
        } catch {
          return redirectToTemplateEditor(c, pathParams.tenantId, pathParams.badgeTemplateId, {
            detailsError: "Check the template fields and try again.",
          });
        }

        try {
          const template = await updateBadgeTemplateWithAudit(db, {
            tenantId: pathParams.tenantId,
            badgeTemplateId: pathParams.badgeTemplateId,
            existingTemplate,
            request,
            actorUserId: session.userId,
            membershipRole,
          });

          if (template === null) {
            return redirectToTemplateListWithFlash(c, {
              tenantId: pathParams.tenantId,
              userId: session.userId,
              listPageQuery,
              tone: "error",
              message: "Badge template not found",
            });
          }

          return redirectToTemplateEditor(c, pathParams.tenantId, pathParams.badgeTemplateId, {
            details: "saved",
          });
        } catch (error: unknown) {
          if (isBadgeTemplateSlugConflict(error)) {
            return redirectToTemplateEditor(c, pathParams.tenantId, pathParams.badgeTemplateId, {
              detailsError:
                "A template with this URL key already exists. Change the URL key or edit the existing template.",
            });
          }

          throw error;
        }
      },
    );
  });

  const runArchiveAction = async (
    c: AppContext,
    pathParams: ReturnType<typeof parseBadgeTemplatePathParams>,
    archive: boolean,
    listPageQuery: ReturnType<typeof parseBadgeTemplateListPageQuery>,
  ): Promise<Response> => {
    return withBadgeTemplateIssuerAccess(
      {
        c,
        tenantId: pathParams.tenantId,
        badgeTemplateId: pathParams.badgeTemplateId,
        nextPath: buildTemplateListPath(pathParams.tenantId),
        resolveDatabase,
        resolveInstitutionAdminAdminRole,
        requireScopedOrgUnitPermission,
        notFound: ({ session }) =>
          redirectToTemplateListWithFlash(c, {
            tenantId: pathParams.tenantId,
            userId: session.userId,
            listPageQuery,
            tone: "error",
            message: "Badge template not found",
          }),
      },
      async ({ db, session }) => {
        const updatedTemplate = await setBadgeTemplateArchivedState(db, {
          tenantId: pathParams.tenantId,
          id: pathParams.badgeTemplateId,
          isArchived: archive,
        });

        if (updatedTemplate === null) {
          return redirectToTemplateListWithFlash(c, {
            tenantId: pathParams.tenantId,
            userId: session.userId,
            listPageQuery,
            tone: "error",
            message: "Badge template not found",
          });
        }

        return redirectToTemplateListWithFlash(c, {
          tenantId: pathParams.tenantId,
          userId: session.userId,
          listPageQuery,
          tone: "success",
          message: archive ? "Badge template archived." : "Badge template restored.",
        });
      },
    );
  };

  app.post("/tenants/:tenantId/admin/rules/templates/:badgeTemplateId/archive", async (c) => {
    const pathParams = parseBadgeTemplatePathParams(c.req.param());
    const listPageQuery = parseBadgeTemplateListPageQuery(c.req.query());

    return runArchiveAction(c, pathParams, true, listPageQuery);
  });

  app.post("/tenants/:tenantId/admin/rules/templates/:badgeTemplateId/unarchive", async (c) => {
    const pathParams = parseBadgeTemplatePathParams(c.req.param());
    const listPageQuery = parseBadgeTemplateListPageQuery(c.req.query());

    return runArchiveAction(c, pathParams, false, listPageQuery);
  });

  app.post(
    "/tenants/:tenantId/admin/rules/templates/:badgeTemplateId/image-revisions/:revisionId/restore",
    async (c) => {
      const pathParams = parseBadgeTemplateImageRevisionPathParams(c.req.param());
      const listPageQuery = parseBadgeTemplateListPageQuery(c.req.query());

      return withBadgeTemplateIssuerAccess(
        {
          c,
          tenantId: pathParams.tenantId,
          badgeTemplateId: pathParams.badgeTemplateId,
          nextPath: buildTemplateListPath(pathParams.tenantId),
          resolveDatabase,
          resolveInstitutionAdminAdminRole,
          requireScopedOrgUnitPermission,
          notFound: ({ session }) =>
            redirectToTemplateListWithFlash(c, {
              tenantId: pathParams.tenantId,
              userId: session.userId,
              listPageQuery,
              tone: "error",
              message: "Badge template not found",
            }),
        },
        async ({ db, session, membershipRole }) => {
          const result = await restoreBadgeTemplateImageRevision({
            db,
            tenantId: pathParams.tenantId,
            badgeTemplateId: pathParams.badgeTemplateId,
            revisionId: pathParams.revisionId,
            actorUserId: session.userId,
            membershipRole,
          });

          if ("status" in result) {
            return redirectToTemplateListWithFlash(c, {
              tenantId: pathParams.tenantId,
              userId: session.userId,
              listPageQuery,
              tone: "error",
              message: result.message,
              extra: {
                history: "1",
                badgeTemplateId: pathParams.badgeTemplateId,
              },
            });
          }

          return redirectToTemplateListWithFlash(c, {
            tenantId: pathParams.tenantId,
            userId: session.userId,
            listPageQuery,
            tone: "success",
            message: "Badge image restored.",
            extra: {
              badgeTemplateId: pathParams.badgeTemplateId,
              history: "1",
            },
          });
        },
      );
    },
  );
};
