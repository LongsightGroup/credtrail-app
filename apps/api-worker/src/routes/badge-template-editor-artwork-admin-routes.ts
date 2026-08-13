import type { TenantMembershipRole } from "@credtrail/db";
import { parseBadgeTemplatePathParams } from "@credtrail/validation";
import type { Hono } from "hono";
import { badgeTemplateAdminEditorHref } from "../admin/badge-template-admin-helpers";
import type { AppContext, AppEnv } from "../app";
import type { RequireScopedOrgUnitPermission, ResolveDatabase } from "../app/route-deps";
import {
  applyBadgeTemplateGeneratedImage,
  uploadBadgeTemplateImage,
} from "../badges/badge-template-image-workflows";
import { withBadgeTemplateIssuerAccess } from "./badge-template-admin-access";

interface RegisterBadgeTemplateEditorArtworkAdminRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: ResolveDatabase;
  requireScopedOrgUnitPermission: RequireScopedOrgUnitPermission;
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
}

const redirectToTemplateEditor = (
  c: AppContext,
  tenantId: string,
  badgeTemplateId: string,
  query: Record<string, string>,
): Response => {
  const location = new URL(badgeTemplateAdminEditorHref(tenantId, badgeTemplateId), c.req.url);

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
    const editorPath = badgeTemplateAdminEditorHref(
      pathParams.tenantId,
      pathParams.badgeTemplateId,
    );

    return withBadgeTemplateIssuerAccess(
      {
        c,
        tenantId: pathParams.tenantId,
        badgeTemplateId: pathParams.badgeTemplateId,
        nextPath: editorPath,
        resolveDatabase,
        resolveInstitutionAdminAdminRole,
        requireScopedOrgUnitPermission,
        notFound: () =>
          redirectToTemplateEditor(c, pathParams.tenantId, pathParams.badgeTemplateId, {
            artworkError: "Badge template not found",
          }),
      },
      async ({ db, principal, membershipRole }) => {
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
          actorUserId: principal.userId,
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
      },
    );
  });

  app.post(
    "/tenants/:tenantId/admin/rules/templates/:badgeTemplateId/image-generations/apply",
    async (c) => {
      const pathParams = parseBadgeTemplatePathParams(c.req.param());
      const editorPath = badgeTemplateAdminEditorHref(
        pathParams.tenantId,
        pathParams.badgeTemplateId,
      );

      return withBadgeTemplateIssuerAccess(
        {
          c,
          tenantId: pathParams.tenantId,
          badgeTemplateId: pathParams.badgeTemplateId,
          nextPath: editorPath,
          resolveDatabase,
          resolveInstitutionAdminAdminRole,
          requireScopedOrgUnitPermission,
          notFound: () =>
            redirectToTemplateEditor(c, pathParams.tenantId, pathParams.badgeTemplateId, {
              artworkError: "Badge template not found",
            }),
        },
        async ({ db, principal, membershipRole }) => {
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
            actorUserId: principal.userId,
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
    },
  );
};
