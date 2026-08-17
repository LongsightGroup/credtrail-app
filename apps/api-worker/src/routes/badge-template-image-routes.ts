import {
  createBadgeTemplateImageGeneration,
  findBadgeTemplateById,
  findBadgeTemplateImageGenerationById,
  type TenantMembershipRole,
} from "@credtrail/db";
import {
  parseBadgeTemplateImageGenerationPathParams,
  parseBadgeTemplatePathParams,
  parseGenerateBadgeTemplateImageRequest,
} from "@credtrail/validation";
import type { Hono } from "hono";
import type { AppEnv } from "../app/types";
import type {
  RequireScopedOrgUnitPermission,
  RequireTenantRole,
  ResolveDatabase,
} from "../app/route-deps";
import {
  buildBadgeTemplateImagePrompt,
  completeBadgeTemplateImageGeneration,
  isBadgeTemplateImageGenerationConfigured,
} from "../badges/badge-template-image-generation";
import { loadBadgeTemplateImage } from "../badges/template-image-storage";

interface RegisterBadgeTemplateImageRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: ResolveDatabase;
  requireTenantRole: RequireTenantRole;
  requireScopedOrgUnitPermission: RequireScopedOrgUnitPermission;
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
};
