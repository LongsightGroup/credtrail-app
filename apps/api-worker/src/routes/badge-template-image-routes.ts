import {
  createBadgeTemplateImageGeneration,
  findBadgeTemplateById,
  findBadgeTemplateImageGenerationById,
  listBadgeTemplateImageRevisions,
  type SqlDatabase,
  type TenantMembershipOrgUnitScopeRole,
  type TenantMembershipRole,
} from "@credtrail/db";
import type { Hono } from "hono";
import {
  parseBadgeTemplateImageGenerationPathParams,
  parseBadgeTemplateImageRevisionPathParams,
  parseBadgeTemplatePathParams,
  parseGenerateBadgeTemplateImageRequest,
} from "@credtrail/validation";
import type { AppBindings, AppContext, AppEnv } from "../app";
import type { AuthenticatedPrincipal } from "../auth/auth-context";
import {
  badgeTemplateImageMimeTypeFromValue,
  loadBadgeTemplateImage,
} from "../badges/template-image-storage";
import {
  applyBadgeTemplateGeneratedImage,
  uploadBadgeTemplateImage,
} from "../badges/badge-template-image-workflows";
import { restoreBadgeTemplateImageRevision } from "../badges/badge-template-image-revision-restore";
import {
  buildBadgeTemplateImagePrompt,
  completeBadgeTemplateImageGeneration,
  isBadgeTemplateImageGenerationConfigured,
} from "../badges/badge-template-image-generation";

interface RegisterBadgeTemplateImageRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  requireTenantRole: (
    c: AppContext,
    tenantId: string,
    allowedRoles: readonly TenantMembershipRole[],
  ) => Promise<
    | {
        principal: AuthenticatedPrincipal;
        membershipRole: TenantMembershipRole;
      }
    | Response
  >;
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
  ADMIN_ROLES: readonly TenantMembershipRole[];
}

export const registerBadgeTemplateImageRoutes = (
  input: RegisterBadgeTemplateImageRoutesInput,
): void => {
  const { app, resolveDatabase, requireTenantRole, requireScopedOrgUnitPermission, ADMIN_ROLES } =
    input;

  app.get("/badges/assets/:tenantId/:badgeTemplateId/:assetId", async (c) => {
    const tenantId = c.req.param("tenantId").trim();
    const badgeTemplateId = c.req.param("badgeTemplateId").trim();
    const assetId = c.req.param("assetId").trim();

    if (tenantId.length === 0 || badgeTemplateId.length === 0 || assetId.length === 0) {
      return c.notFound();
    }

    const image = await loadBadgeTemplateImage(c.env.BADGE_OBJECTS, {
      tenantId,
      badgeTemplateId,
      assetId,
    });

    if (image === null) {
      return c.notFound();
    }

    c.header("Cache-Control", "public, max-age=31536000, immutable");
    c.header("Content-Type", image.mimeType);
    c.header("X-Content-Type-Options", "nosniff");

    const imageBuffer = new ArrayBuffer(image.bytes.byteLength);
    new Uint8Array(imageBuffer).set(image.bytes);

    return c.body(imageBuffer);
  });

  app.post("/v1/tenants/:tenantId/badge-templates/:badgeTemplateId/image-upload", async (c) => {
    const pathParams = parseBadgeTemplatePathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { principal, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const template = await findBadgeTemplateById(
      db,
      pathParams.tenantId,
      pathParams.badgeTemplateId,
    );

    if (template === null) {
      return c.json(
        {
          error: "Badge template not found",
        },
        404,
      );
    }

    const scopeCheck = await requireScopedOrgUnitPermission(c, {
      db,
      tenantId: pathParams.tenantId,
      userId: principal.userId,
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
      return c.json(
        {
          error:
            'Badge template image upload requires multipart/form-data with a file field named "file"',
        },
        400,
      );
    }

    const formData = await c.req.formData();
    const upload = formData.get("file");

    if (!(upload instanceof File)) {
      return c.json(
        {
          error: 'Badge template image file is required in form field "file"',
        },
        400,
      );
    }

    const uploadResult = await uploadBadgeTemplateImage({
      c,
      db,
      bindings: c.env,
      tenantId: pathParams.tenantId,
      badgeTemplateId: pathParams.badgeTemplateId,
      actorUserId: principal.userId,
      membershipRole,
      file: upload,
    });

    if ("status" in uploadResult) {
      return c.json(
        {
          error: uploadResult.message,
        },
        uploadResult.status,
      );
    }

    const updatedTemplate = uploadResult.updatedTemplate;
    const imageUrl = updatedTemplate.imageUri;

    if (imageUrl === null) {
      return c.json(
        {
          error: "Badge template image upload did not produce an image URI",
        },
        500,
      );
    }

    const imageUrlObject = new URL(imageUrl);
    const imagePath = imageUrlObject.pathname;
    const assetId = decodeURIComponent(imageUrlObject.pathname.split("/").pop() ?? "");
    const declaredMimeType = badgeTemplateImageMimeTypeFromValue(upload.type);

    return c.json(
      {
        tenantId: pathParams.tenantId,
        template: updatedTemplate,
        image: {
          assetId,
          path: imagePath,
          url: imageUrl,
          mimeType: declaredMimeType ?? "image/png",
          byteSize: upload.size,
        },
      },
      201,
    );
  });

  app.get("/v1/tenants/:tenantId/badge-templates/:badgeTemplateId/image-revisions", async (c) => {
    const pathParams = parseBadgeTemplatePathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { principal, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const template = await findBadgeTemplateById(
      db,
      pathParams.tenantId,
      pathParams.badgeTemplateId,
    );

    if (template === null) {
      return c.json(
        {
          error: "Badge template not found",
        },
        404,
      );
    }

    const scopeCheck = await requireScopedOrgUnitPermission(c, {
      db,
      tenantId: pathParams.tenantId,
      userId: principal.userId,
      membershipRole,
      orgUnitId: template.ownerOrgUnitId,
      requiredRole: "viewer",
      allowWhenNoScopes: true,
    });

    if (scopeCheck !== null) {
      return scopeCheck;
    }

    const revisions = await listBadgeTemplateImageRevisions(db, {
      tenantId: pathParams.tenantId,
      badgeTemplateId: pathParams.badgeTemplateId,
      limit: 25,
    });

    return c.json({
      tenantId: pathParams.tenantId,
      template,
      revisions,
    });
  });

  app.post(
    "/v1/tenants/:tenantId/badge-templates/:badgeTemplateId/image-revisions/:revisionId/restore",
    async (c) => {
      const pathParams = parseBadgeTemplateImageRevisionPathParams(c.req.param());
      const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

      if (roleCheck instanceof Response) {
        return roleCheck;
      }

      const { principal, membershipRole } = roleCheck;
      const db = resolveDatabase(c.env);
      const template = await findBadgeTemplateById(
        db,
        pathParams.tenantId,
        pathParams.badgeTemplateId,
      );

      if (template === null) {
        return c.json(
          {
            error: "Badge template not found",
          },
          404,
        );
      }

      const scopeCheck = await requireScopedOrgUnitPermission(c, {
        db,
        tenantId: pathParams.tenantId,
        userId: principal.userId,
        membershipRole,
        orgUnitId: template.ownerOrgUnitId,
        requiredRole: "issuer",
        allowWhenNoScopes: true,
      });

      if (scopeCheck !== null) {
        return scopeCheck;
      }

      const result = await restoreBadgeTemplateImageRevision({
        db,
        tenantId: pathParams.tenantId,
        badgeTemplateId: pathParams.badgeTemplateId,
        revisionId: pathParams.revisionId,
        actorUserId: principal.userId,
        membershipRole,
      });

      if ("status" in result) {
        return c.json(
          {
            error: result.message,
          },
          result.status,
        );
      }

      return c.json({
        tenantId: pathParams.tenantId,
        template: result.updatedTemplate,
        restoredRevision: result.restoredRevision,
      });
    },
  );

  app.post(
    "/v1/tenants/:tenantId/badge-templates/:badgeTemplateId/image-generations",
    async (c) => {
      const pathParams = parseBadgeTemplatePathParams(c.req.param());
      const payload = await c.req.json<unknown>();
      const request = parseGenerateBadgeTemplateImageRequest(payload);
      const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

      if (roleCheck instanceof Response) {
        return roleCheck;
      }

      if (!isBadgeTemplateImageGenerationConfigured(c.env)) {
        return c.json(
          {
            error: "Badge image generation is not configured",
          },
          501,
        );
      }

      const { principal, membershipRole } = roleCheck;
      const db = resolveDatabase(c.env);
      const template = await findBadgeTemplateById(
        db,
        pathParams.tenantId,
        pathParams.badgeTemplateId,
      );

      if (template === null) {
        return c.json(
          {
            error: "Badge template not found",
          },
          404,
        );
      }

      const scopeCheck = await requireScopedOrgUnitPermission(c, {
        db,
        tenantId: pathParams.tenantId,
        userId: principal.userId,
        membershipRole,
        orgUnitId: template.ownerOrgUnitId,
        requiredRole: "issuer",
        allowWhenNoScopes: true,
      });

      if (scopeCheck !== null) {
        return scopeCheck;
      }

      const promptText = buildBadgeTemplateImagePrompt({
        template,
        stylePreset: request.stylePreset,
        promptNotes: request.promptNotes,
        accentColor: request.accentColor,
      });
      const generation = await createBadgeTemplateImageGeneration(db, {
        tenantId: pathParams.tenantId,
        badgeTemplateId: pathParams.badgeTemplateId,
        promptText,
        stylePreset: request.stylePreset,
        promptNotes: request.promptNotes,
        accentColor: request.accentColor,
        requestedByUserId: principal.userId,
      });

      try {
        const completedGeneration = await completeBadgeTemplateImageGeneration({
          db,
          store: c.env.BADGE_OBJECTS,
          env: c.env,
          tenantId: pathParams.tenantId,
          badgeTemplateId: pathParams.badgeTemplateId,
          generationId: generation.id,
          promptText,
          requestedByUserId: principal.userId,
        });

        return c.json({
          tenantId: pathParams.tenantId,
          template,
          generation: completedGeneration,
        });
      } catch (error: unknown) {
        const detail =
          error instanceof Error ? error.message : "Unknown badge image generation error";
        const failedGeneration =
          (await findBadgeTemplateImageGenerationById(db, pathParams.tenantId, generation.id)) ??
          generation;
        const status = detail.includes("timed out") ? 504 : 502;

        return c.json(
          {
            error: detail,
            tenantId: pathParams.tenantId,
            template,
            generation: failedGeneration,
          },
          status,
        );
      }
    },
  );

  app.get(
    "/v1/tenants/:tenantId/badge-templates/:badgeTemplateId/image-generations/:generationId",
    async (c) => {
      const pathParams = parseBadgeTemplateImageGenerationPathParams(c.req.param());
      const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

      if (roleCheck instanceof Response) {
        return roleCheck;
      }

      const { principal, membershipRole } = roleCheck;
      const db = resolveDatabase(c.env);
      const template = await findBadgeTemplateById(
        db,
        pathParams.tenantId,
        pathParams.badgeTemplateId,
      );

      if (template === null) {
        return c.json(
          {
            error: "Badge template not found",
          },
          404,
        );
      }

      const scopeCheck = await requireScopedOrgUnitPermission(c, {
        db,
        tenantId: pathParams.tenantId,
        userId: principal.userId,
        membershipRole,
        orgUnitId: template.ownerOrgUnitId,
        requiredRole: "viewer",
        allowWhenNoScopes: true,
      });

      if (scopeCheck !== null) {
        return scopeCheck;
      }

      const generation = await findBadgeTemplateImageGenerationById(
        db,
        pathParams.tenantId,
        pathParams.generationId,
      );

      if (generation === null || generation.badgeTemplateId !== pathParams.badgeTemplateId) {
        return c.json(
          {
            error: "Badge template image generation not found",
          },
          404,
        );
      }

      return c.json({
        tenantId: pathParams.tenantId,
        template,
        generation,
      });
    },
  );

  app.post(
    "/v1/tenants/:tenantId/badge-templates/:badgeTemplateId/image-generations/:generationId/apply",
    async (c) => {
      const pathParams = parseBadgeTemplateImageGenerationPathParams(c.req.param());
      const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

      if (roleCheck instanceof Response) {
        return roleCheck;
      }

      const { principal, membershipRole } = roleCheck;
      const db = resolveDatabase(c.env);
      const template = await findBadgeTemplateById(
        db,
        pathParams.tenantId,
        pathParams.badgeTemplateId,
      );

      if (template === null) {
        return c.json(
          {
            error: "Badge template not found",
          },
          404,
        );
      }

      const scopeCheck = await requireScopedOrgUnitPermission(c, {
        db,
        tenantId: pathParams.tenantId,
        userId: principal.userId,
        membershipRole,
        orgUnitId: template.ownerOrgUnitId,
        requiredRole: "issuer",
        allowWhenNoScopes: true,
      });

      if (scopeCheck !== null) {
        return scopeCheck;
      }

      const applyResult = await applyBadgeTemplateGeneratedImage({
        db,
        tenantId: pathParams.tenantId,
        badgeTemplateId: pathParams.badgeTemplateId,
        generationId: pathParams.generationId,
        actorUserId: principal.userId,
        membershipRole,
      });

      if ("status" in applyResult) {
        return c.json(
          {
            error: applyResult.message,
          },
          applyResult.status,
        );
      }

      const generation = await findBadgeTemplateImageGenerationById(
        db,
        pathParams.tenantId,
        pathParams.generationId,
      );

      return c.json({
        tenantId: pathParams.tenantId,
        template: applyResult.updatedTemplate,
        generation,
      });
    },
  );
};
