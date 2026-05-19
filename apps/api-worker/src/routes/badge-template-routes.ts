import {
  createAuditLog,
  createBadgeTemplateImageGeneration,
  createBadgeTemplateImageRevision,
  createBadgeTemplate,
  findBadgeTemplateById,
  findBadgeTemplateImageGenerationById,
  findBadgeTemplateImageRevisionById,
  hasTenantMembershipOrgUnitAccess,
  hasTenantMembershipOrgUnitScopeAssignments,
  listBadgeTemplateImageRevisions,
  listBadgeTemplateOwnershipEvents,
  listBadgeTemplates,
  setBadgeTemplateArchivedState,
  transferBadgeTemplateOwnership,
  updateBadgeTemplate,
  type SqlDatabase,
  type TenantMembershipOrgUnitScopeRole,
  type TenantMembershipRole,
} from "@credtrail/db";
import type { Hono } from "hono";
import {
  parseBadgeTemplateImageGenerationPathParams,
  parseBadgeTemplateImageRevisionPathParams,
  parseBadgeTemplateListQuery,
  parseBadgeTemplatePathParams,
  parseCreateBadgeTemplateRequest,
  parseGenerateBadgeTemplateImageRequest,
  parseTenantPathParams,
  parseTransferBadgeTemplateOwnershipRequest,
  parseUpdateBadgeTemplateRequest,
} from "@credtrail/validation";
import type { AppBindings, AppContext, AppEnv } from "../app";
import type { AuthenticatedPrincipal } from "../auth/auth-context";
import {
  BADGE_TEMPLATE_IMAGE_MAX_BYTES,
  badgeTemplateImageMimeTypeFromBytes,
  badgeTemplateImageMimeTypeFromValue,
  loadBadgeTemplateImage,
  storeBadgeTemplateImage,
} from "../badges/template-image-storage";
import {
  buildBadgeTemplateImagePrompt,
  completeBadgeTemplateImageGeneration,
  isBadgeTemplateImageGenerationConfigured,
} from "../badges/badge-template-image-generation";

interface RegisterBadgeTemplateRoutesInput {
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
  defaultInstitutionOrgUnitId: (tenantId: string) => string;
  ADMIN_ROLES: readonly TenantMembershipRole[];
  ISSUER_ROLES: readonly TenantMembershipRole[];
  TENANT_MEMBER_ROLES: readonly TenantMembershipRole[];
}

export const registerBadgeTemplateRoutes = (input: RegisterBadgeTemplateRoutesInput): void => {
  const {
    app,
    resolveDatabase,
    requireTenantRole,
    requireScopedOrgUnitPermission,
    defaultInstitutionOrgUnitId,
    ADMIN_ROLES,
    ISSUER_ROLES,
    TENANT_MEMBER_ROLES,
  } = input;

  const recordImageRevisionIfChanged = async (
    db: SqlDatabase,
    input: {
      tenantId: string;
      badgeTemplateId: string;
      previousImageUri: string | null;
      newImageUri: string | null;
      sourceType: "manual_update" | "upload" | "ai_generated" | "restore";
      createdByUserId: string;
      promptText?: string | undefined;
      provider?: string | undefined;
      model?: string | undefined;
      metadata?: Record<string, string | number | boolean | null> | undefined;
    },
  ): Promise<void> => {
    if (input.previousImageUri === input.newImageUri) {
      return;
    }

    await createBadgeTemplateImageRevision(db, {
      tenantId: input.tenantId,
      badgeTemplateId: input.badgeTemplateId,
      previousImageUri: input.previousImageUri,
      newImageUri: input.newImageUri,
      sourceType: input.sourceType,
      promptText: input.promptText,
      provider: input.provider,
      model: input.model,
      metadataJson: input.metadata === undefined ? null : JSON.stringify(input.metadata),
      createdByUserId: input.createdByUserId,
    });
  };

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

  app.get("/v1/tenants/:tenantId/badge-templates", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const query = parseBadgeTemplateListQuery({
      includeArchived: c.req.query("includeArchived"),
    });
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, TENANT_MEMBER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { principal, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    let templates = await listBadgeTemplates(db, {
      tenantId: pathParams.tenantId,
      includeArchived: query.includeArchived,
    });

    if (membershipRole === "issuer") {
      const hasScopedAssignments = await hasTenantMembershipOrgUnitScopeAssignments(
        db,
        pathParams.tenantId,
        principal.userId,
      );

      if (hasScopedAssignments) {
        const scopedTemplates: typeof templates = [];

        for (const template of templates) {
          const canViewTemplate = await hasTenantMembershipOrgUnitAccess(db, {
            tenantId: pathParams.tenantId,
            userId: principal.userId,
            orgUnitId: template.ownerOrgUnitId,
            requiredRole: "viewer",
          });

          if (canViewTemplate) {
            scopedTemplates.push(template);
          }
        }

        templates = scopedTemplates;
      }
    }

    return c.json({
      tenantId: pathParams.tenantId,
      templates,
    });
  });

  app.post("/v1/tenants/:tenantId/badge-templates", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const payload = await c.req.json<unknown>();
    const request = parseCreateBadgeTemplateRequest(payload);
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { principal, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const targetOwnerOrgUnitId =
      request.ownerOrgUnitId ?? defaultInstitutionOrgUnitId(pathParams.tenantId);

    const scopeCheck = await requireScopedOrgUnitPermission(c, {
      db,
      tenantId: pathParams.tenantId,
      userId: principal.userId,
      membershipRole,
      orgUnitId: targetOwnerOrgUnitId,
      requiredRole: "issuer",
      allowWhenNoScopes: true,
    });

    if (scopeCheck !== null) {
      return scopeCheck;
    }

    try {
      const template = await createBadgeTemplate(db, {
        tenantId: pathParams.tenantId,
        slug: request.slug,
        title: request.title,
        description: request.description,
        criteriaUri: request.criteriaUri,
        imageUri: request.imageUri,
        ownerOrgUnitId: request.ownerOrgUnitId,
        createdByUserId: principal.userId,
      });

      await createAuditLog(db, {
        tenantId: pathParams.tenantId,
        actorUserId: principal.userId,
        action: "badge_template.created",
        targetType: "badge_template",
        targetId: template.id,
        metadata: {
          role: membershipRole,
          slug: template.slug,
          title: template.title,
          ownerOrgUnitId: template.ownerOrgUnitId,
        },
      });

      return c.json(
        {
          tenantId: pathParams.tenantId,
          template,
        },
        201,
      );
    } catch (error: unknown) {
      if (error instanceof Error && error.message.includes("UNIQUE constraint failed")) {
        return c.json(
          {
            error: "Badge template slug already exists for tenant",
          },
          409,
        );
      }

      if (
        error instanceof Error &&
        error.message.includes("Org unit") &&
        error.message.includes("not found for tenant")
      ) {
        return c.json(
          {
            error: error.message,
          },
          422,
        );
      }

      throw error;
    }
  });

  app.get("/v1/tenants/:tenantId/badge-templates/:badgeTemplateId", async (c) => {
    const pathParams = parseBadgeTemplatePathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, TENANT_MEMBER_ROLES);

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

    if (membershipRole === "issuer") {
      const hasScopedAssignments = await hasTenantMembershipOrgUnitScopeAssignments(
        db,
        pathParams.tenantId,
        principal.userId,
      );

      if (hasScopedAssignments) {
        const canViewTemplate = await hasTenantMembershipOrgUnitAccess(db, {
          tenantId: pathParams.tenantId,
          userId: principal.userId,
          orgUnitId: template.ownerOrgUnitId,
          requiredRole: "viewer",
        });

        if (!canViewTemplate) {
          return c.json(
            {
              error: "Insufficient org-unit scope for requested action",
            },
            403,
          );
        }
      }
    }

    return c.json({
      tenantId: pathParams.tenantId,
      template,
    });
  });

  app.get("/v1/tenants/:tenantId/badge-templates/:badgeTemplateId/ownership-history", async (c) => {
    const pathParams = parseBadgeTemplatePathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

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

    const events = await listBadgeTemplateOwnershipEvents(db, {
      tenantId: pathParams.tenantId,
      badgeTemplateId: pathParams.badgeTemplateId,
    });

    return c.json({
      tenantId: pathParams.tenantId,
      template,
      events,
    });
  });

  app.post(
    "/v1/tenants/:tenantId/badge-templates/:badgeTemplateId/ownership-transfer",
    async (c) => {
      const pathParams = parseBadgeTemplatePathParams(c.req.param());
      let request: ReturnType<typeof parseTransferBadgeTemplateOwnershipRequest>;

      try {
        request = parseTransferBadgeTemplateOwnershipRequest(await c.req.json<unknown>());
      } catch {
        return c.json(
          {
            error: "Invalid ownership transfer request payload",
          },
          400,
        );
      }

      const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

      if (roleCheck instanceof Response) {
        return roleCheck;
      }

      const { principal, membershipRole } = roleCheck;

      try {
        const transition = await transferBadgeTemplateOwnership(resolveDatabase(c.env), {
          tenantId: pathParams.tenantId,
          badgeTemplateId: pathParams.badgeTemplateId,
          toOrgUnitId: request.toOrgUnitId,
          reasonCode: request.reasonCode,
          reason: request.reason,
          governanceMetadataJson:
            request.governanceMetadata === undefined
              ? undefined
              : JSON.stringify(request.governanceMetadata),
          transferredByUserId: principal.userId,
          transferredAt: request.transferredAt ?? new Date().toISOString(),
        });

        await createAuditLog(resolveDatabase(c.env), {
          tenantId: pathParams.tenantId,
          actorUserId: principal.userId,
          action: "badge_template.ownership_transferred",
          targetType: "badge_template",
          targetId: pathParams.badgeTemplateId,
          metadata: {
            role: membershipRole,
            status: transition.status,
            fromOrgUnitId: transition.event?.fromOrgUnitId ?? transition.template.ownerOrgUnitId,
            toOrgUnitId: transition.template.ownerOrgUnitId,
            reasonCode: request.reasonCode,
            reason: request.reason,
            eventId: transition.event?.id ?? null,
          },
        });

        return c.json({
          tenantId: pathParams.tenantId,
          status: transition.status,
          template: transition.template,
          event: transition.event,
        });
      } catch (error: unknown) {
        if (error instanceof Error) {
          if (
            error.message.includes("not found for tenant") &&
            error.message.includes("Badge template")
          ) {
            return c.json(
              {
                error: "Badge template not found",
              },
              404,
            );
          }

          if (
            error.message.includes("transferredAt must be a valid ISO timestamp") ||
            error.message.includes("Unsupported badge template ownership reason code") ||
            error.message.includes("initial_assignment is reserved") ||
            (error.message.includes("Org unit") && error.message.includes("not found for tenant"))
          ) {
            return c.json(
              {
                error: error.message,
              },
              422,
            );
          }
        }

        throw error;
      }
    },
  );

  app.patch("/v1/tenants/:tenantId/badge-templates/:badgeTemplateId", async (c) => {
    const pathParams = parseBadgeTemplatePathParams(c.req.param());
    const payload = await c.req.json<unknown>();
    const request = parseUpdateBadgeTemplateRequest(payload);
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { principal, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const existingTemplate = await findBadgeTemplateById(
      db,
      pathParams.tenantId,
      pathParams.badgeTemplateId,
    );

    if (existingTemplate === null) {
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
      orgUnitId: existingTemplate.ownerOrgUnitId,
      requiredRole: "issuer",
      allowWhenNoScopes: true,
    });

    if (scopeCheck !== null) {
      return scopeCheck;
    }

    try {
      const template = await updateBadgeTemplate(db, {
        tenantId: pathParams.tenantId,
        id: pathParams.badgeTemplateId,
        slug: request.slug,
        title: request.title,
        description: request.description,
        criteriaUri: request.criteriaUri,
        imageUri: request.imageUri,
      });

      if (template === null) {
        return c.json(
          {
            error: "Badge template not found",
          },
          404,
        );
      }

      if (request.imageUri !== undefined) {
        await recordImageRevisionIfChanged(db, {
          tenantId: pathParams.tenantId,
          badgeTemplateId: pathParams.badgeTemplateId,
          previousImageUri: existingTemplate.imageUri,
          newImageUri: template.imageUri,
          sourceType: "manual_update",
          createdByUserId: principal.userId,
        });
      }

      await createAuditLog(db, {
        tenantId: pathParams.tenantId,
        actorUserId: principal.userId,
        action: "badge_template.updated",
        targetType: "badge_template",
        targetId: template.id,
        metadata: {
          role: membershipRole,
          slug: template.slug,
          title: template.title,
        },
      });

      return c.json({
        tenantId: pathParams.tenantId,
        template,
      });
    } catch (error: unknown) {
      if (error instanceof Error && error.message.includes("UNIQUE constraint failed")) {
        return c.json(
          {
            error: "Badge template slug already exists for tenant",
          },
          409,
        );
      }

      throw error;
    }
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

    if (upload.size < 1) {
      return c.json(
        {
          error: "Badge template image file must not be empty",
        },
        422,
      );
    }

    if (upload.size > BADGE_TEMPLATE_IMAGE_MAX_BYTES) {
      return c.json(
        {
          error: `Badge template image exceeds ${String(BADGE_TEMPLATE_IMAGE_MAX_BYTES)} byte limit`,
        },
        413,
      );
    }

    const declaredMimeType = badgeTemplateImageMimeTypeFromValue(upload.type);

    if (declaredMimeType === null) {
      return c.json(
        {
          error: "Unsupported image type. Allowed types: image/png, image/jpeg, image/webp",
        },
        422,
      );
    }

    const bytes = new Uint8Array(await upload.arrayBuffer());
    const detectedMimeType = badgeTemplateImageMimeTypeFromBytes(bytes);

    if (detectedMimeType === null || detectedMimeType !== declaredMimeType) {
      return c.json(
        {
          error: "Uploaded file content does not match declared image type",
        },
        422,
      );
    }

    const assetId = crypto.randomUUID();
    const fileName = upload.name.trim();
    await storeBadgeTemplateImage(c.env.BADGE_OBJECTS, {
      tenantId: pathParams.tenantId,
      badgeTemplateId: pathParams.badgeTemplateId,
      assetId,
      mimeType: declaredMimeType,
      bytes,
      originalFilename: fileName.length === 0 ? null : fileName,
    });

    const imagePath = `/badges/assets/${encodeURIComponent(pathParams.tenantId)}/${encodeURIComponent(
      pathParams.badgeTemplateId,
    )}/${encodeURIComponent(assetId)}`;
    const imageUrl = new URL(imagePath, c.req.url).toString();
    const updatedTemplate = await updateBadgeTemplate(db, {
      tenantId: pathParams.tenantId,
      id: pathParams.badgeTemplateId,
      imageUri: imageUrl,
    });

    if (updatedTemplate === null) {
      return c.json(
        {
          error: "Badge template not found",
        },
        404,
      );
    }

    await recordImageRevisionIfChanged(db, {
      tenantId: pathParams.tenantId,
      badgeTemplateId: pathParams.badgeTemplateId,
      previousImageUri: template.imageUri,
      newImageUri: updatedTemplate.imageUri,
      sourceType: "upload",
      createdByUserId: principal.userId,
      metadata: {
        imagePath,
        imageMimeType: declaredMimeType,
        imageSizeBytes: bytes.byteLength,
        fileName: fileName.length === 0 ? null : fileName,
      },
    });

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: principal.userId,
      action: "badge_template.image_uploaded",
      targetType: "badge_template",
      targetId: updatedTemplate.id,
      metadata: {
        role: membershipRole,
        imagePath,
        imageMimeType: declaredMimeType,
        imageSizeBytes: bytes.byteLength,
        ...(fileName.length === 0 ? {} : { fileName }),
      },
    });

    return c.json(
      {
        tenantId: pathParams.tenantId,
        template: updatedTemplate,
        image: {
          assetId,
          path: imagePath,
          url: imageUrl,
          mimeType: declaredMimeType,
          byteSize: bytes.byteLength,
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

      const revision = await findBadgeTemplateImageRevisionById(
        db,
        pathParams.tenantId,
        pathParams.badgeTemplateId,
        pathParams.revisionId,
      );

      if (revision === null) {
        return c.json(
          {
            error: "Badge template image revision not found",
          },
          404,
        );
      }

      const updatedTemplate = await updateBadgeTemplate(db, {
        tenantId: pathParams.tenantId,
        id: pathParams.badgeTemplateId,
        imageUri: revision.previousImageUri,
      });

      if (updatedTemplate === null) {
        return c.json(
          {
            error: "Badge template not found",
          },
          404,
        );
      }

      await recordImageRevisionIfChanged(db, {
        tenantId: pathParams.tenantId,
        badgeTemplateId: pathParams.badgeTemplateId,
        previousImageUri: template.imageUri,
        newImageUri: updatedTemplate.imageUri,
        sourceType: "restore",
        createdByUserId: principal.userId,
        metadata: {
          restoredRevisionId: revision.id,
        },
      });

      await createAuditLog(db, {
        tenantId: pathParams.tenantId,
        actorUserId: principal.userId,
        action: "badge_template.image_restored",
        targetType: "badge_template",
        targetId: updatedTemplate.id,
        metadata: {
          role: membershipRole,
          restoredRevisionId: revision.id,
        },
      });

      return c.json({
        tenantId: pathParams.tenantId,
        template: updatedTemplate,
        restoredRevision: revision,
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

      if (generation.status !== "succeeded" || generation.resultImageUri === null) {
        return c.json(
          {
            error: "Badge template image generation is not ready to apply",
          },
          409,
        );
      }

      const updatedTemplate = await updateBadgeTemplate(db, {
        tenantId: pathParams.tenantId,
        id: pathParams.badgeTemplateId,
        imageUri: generation.resultImageUri,
      });

      if (updatedTemplate === null) {
        return c.json(
          {
            error: "Badge template not found",
          },
          404,
        );
      }

      await recordImageRevisionIfChanged(db, {
        tenantId: pathParams.tenantId,
        badgeTemplateId: pathParams.badgeTemplateId,
        previousImageUri: template.imageUri,
        newImageUri: updatedTemplate.imageUri,
        sourceType: "ai_generated",
        createdByUserId: principal.userId,
        promptText: generation.promptText,
        metadata: {
          generationId: generation.id,
          stylePreset: generation.stylePreset,
        },
      });

      await createAuditLog(db, {
        tenantId: pathParams.tenantId,
        actorUserId: principal.userId,
        action: "badge_template.image_generation_applied",
        targetType: "badge_template",
        targetId: updatedTemplate.id,
        metadata: {
          role: membershipRole,
          generationId: generation.id,
        },
      });

      return c.json({
        tenantId: pathParams.tenantId,
        template: updatedTemplate,
        generation,
      });
    },
  );

  app.post("/v1/tenants/:tenantId/badge-templates/:badgeTemplateId/archive", async (c) => {
    const pathParams = parseBadgeTemplatePathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { principal, membershipRole } = roleCheck;

    const template = await setBadgeTemplateArchivedState(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      id: pathParams.badgeTemplateId,
      isArchived: true,
    });

    if (template === null) {
      return c.json(
        {
          error: "Badge template not found",
        },
        404,
      );
    }

    await createAuditLog(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      actorUserId: principal.userId,
      action: "badge_template.archived_state_changed",
      targetType: "badge_template",
      targetId: template.id,
      metadata: {
        role: membershipRole,
        isArchived: template.isArchived,
      },
    });

    return c.json({
      tenantId: pathParams.tenantId,
      template,
    });
  });

  app.post("/v1/tenants/:tenantId/badge-templates/:badgeTemplateId/unarchive", async (c) => {
    const pathParams = parseBadgeTemplatePathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { principal, membershipRole } = roleCheck;

    const template = await setBadgeTemplateArchivedState(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      id: pathParams.badgeTemplateId,
      isArchived: false,
    });

    if (template === null) {
      return c.json(
        {
          error: "Badge template not found",
        },
        404,
      );
    }

    await createAuditLog(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      actorUserId: principal.userId,
      action: "badge_template.archived_state_changed",
      targetType: "badge_template",
      targetId: template.id,
      metadata: {
        role: membershipRole,
        isArchived: template.isArchived,
      },
    });

    return c.json({
      tenantId: pathParams.tenantId,
      template,
    });
  });
};
