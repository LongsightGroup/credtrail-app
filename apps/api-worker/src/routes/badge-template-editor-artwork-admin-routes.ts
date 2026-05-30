import {
  findBadgeTemplateById,
  type SqlDatabase,
  type TenantMembershipOrgUnitScopeRole,
  type TenantMembershipRole,
} from "@credtrail/db";
import { parseBadgeTemplatePathParams } from "@credtrail/validation";
import type { Hono } from "hono";
import type { AppBindings, AppContext, AppEnv } from "../app";
import {
  applyBadgeTemplateGeneratedImage,
  uploadBadgeTemplateImage,
} from "../badges/badge-template-image-workflows";

interface RegisterBadgeTemplateEditorArtworkAdminRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
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

const buildTemplateEditorPath = (tenantId: string, badgeTemplateId: string): string => {
  return `/tenants/${encodeURIComponent(tenantId)}/admin/rules/templates/${encodeURIComponent(
    badgeTemplateId,
  )}`;
};

const redirectToTemplateEditor = (
  c: AppContext,
  tenantId: string,
  badgeTemplateId: string,
  query: Record<string, string>,
): Response => {
  const location = new URL(buildTemplateEditorPath(tenantId, badgeTemplateId), c.req.url);

  for (const [key, value] of Object.entries(query)) {
    if (value.length > 0) {
      location.searchParams.set(key, value);
    }
  }

  return c.redirect(`${location.pathname}${location.search}`, 303);
};

export const registerBadgeTemplateEditorArtworkAdminRoutes = (
  input: RegisterBadgeTemplateEditorArtworkAdminRoutesInput,
): void => {
  const { app, resolveDatabase, requireScopedOrgUnitPermission, resolveInstitutionAdminAdminRole } =
    input;

  app.post("/tenants/:tenantId/admin/rules/templates/:badgeTemplateId/image-upload", async (c) => {
    const pathParams = parseBadgeTemplatePathParams(c.req.param());
    const editorPath = buildTemplateEditorPath(pathParams.tenantId, pathParams.badgeTemplateId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, editorPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const template = await findBadgeTemplateById(
      db,
      pathParams.tenantId,
      pathParams.badgeTemplateId,
    );

    if (template === null) {
      return redirectToTemplateEditor(c, pathParams.tenantId, pathParams.badgeTemplateId, {
        artworkError: "Badge template not found",
      });
    }

    const scopeCheck = await requireScopedOrgUnitPermission(c, {
      db,
      tenantId: pathParams.tenantId,
      userId: session.userId,
      membershipRole,
      orgUnitId: template.ownerOrgUnitId,
      requiredRole: "issuer",
      allowWhenNoScopes: true,
    });

    if (scopeCheck !== null) {
      return scopeCheck;
    }

    const contentType = c.req.header("content-type") ?? "";

    if (!contentType.includes("multipart/form-data")) {
      return redirectToTemplateEditor(c, pathParams.tenantId, pathParams.badgeTemplateId, {
        artworkError: "Choose an image file to upload.",
      });
    }

    const formData = await c.req.formData();
    const upload = formData.get("file");

    if (!(upload instanceof File)) {
      return redirectToTemplateEditor(c, pathParams.tenantId, pathParams.badgeTemplateId, {
        artworkError: "Choose an image file to upload.",
      });
    }

    const result = await uploadBadgeTemplateImage({
      c,
      db,
      bindings: c.env,
      tenantId: pathParams.tenantId,
      badgeTemplateId: pathParams.badgeTemplateId,
      actorUserId: session.userId,
      membershipRole,
      file: upload,
    });

    if ("status" in result) {
      return redirectToTemplateEditor(c, pathParams.tenantId, pathParams.badgeTemplateId, {
        artworkError: result.message,
      });
    }

    return redirectToTemplateEditor(c, pathParams.tenantId, pathParams.badgeTemplateId, {
      artwork: "uploaded",
    });
  });

  app.post(
    "/tenants/:tenantId/admin/rules/templates/:badgeTemplateId/image-generations/apply",
    async (c) => {
      const pathParams = parseBadgeTemplatePathParams(c.req.param());
      const editorPath = buildTemplateEditorPath(pathParams.tenantId, pathParams.badgeTemplateId);
      const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, editorPath);

      if (roleCheck instanceof Response) {
        return roleCheck;
      }

      const { session, membershipRole } = roleCheck;
      const db = resolveDatabase(c.env);
      const template = await findBadgeTemplateById(
        db,
        pathParams.tenantId,
        pathParams.badgeTemplateId,
      );

      if (template === null) {
        return redirectToTemplateEditor(c, pathParams.tenantId, pathParams.badgeTemplateId, {
          artworkError: "Badge template not found",
        });
      }

      const scopeCheck = await requireScopedOrgUnitPermission(c, {
        db,
        tenantId: pathParams.tenantId,
        userId: session.userId,
        membershipRole,
        orgUnitId: template.ownerOrgUnitId,
        requiredRole: "issuer",
        allowWhenNoScopes: true,
      });

      if (scopeCheck !== null) {
        return scopeCheck;
      }

      const formData = await c.req.formData();
      const generationIdRaw = formData.get("generationId");
      const generationId = typeof generationIdRaw === "string" ? generationIdRaw.trim() : "";

      if (generationId.length === 0) {
        return redirectToTemplateEditor(c, pathParams.tenantId, pathParams.badgeTemplateId, {
          artworkError: "No generated draft is selected.",
        });
      }

      const result = await applyBadgeTemplateGeneratedImage({
        db,
        tenantId: pathParams.tenantId,
        badgeTemplateId: pathParams.badgeTemplateId,
        generationId,
        actorUserId: session.userId,
        membershipRole,
      });

      if ("status" in result) {
        return redirectToTemplateEditor(c, pathParams.tenantId, pathParams.badgeTemplateId, {
          artworkError: result.message,
        });
      }

      return redirectToTemplateEditor(c, pathParams.tenantId, pathParams.badgeTemplateId, {
        artwork: "applied",
      });
    },
  );
};
