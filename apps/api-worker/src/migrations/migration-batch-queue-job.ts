import {
  badgeAchievementSnapshotFromTemplate,
  findAssertionByIdempotencyKey,
  updateBadgeTemplate,
  upsertBadgeTemplateBySlug,
  type SqlDatabase,
} from "@credtrail/db";
import type { ImmutableCredentialStore } from "@credtrail/core-domain";
import type { ImportMigrationBatchQueueJob } from "@credtrail/validation";
import type { DirectIssueBadgeOptions, DirectIssueBadgeResult } from "../badges/direct-issue";
import type { DirectIssueBadgeRequest } from "../badges/recipient-identifiers";
import {
  BADGE_TEMPLATE_IMAGE_MAX_BYTES,
  badgeTemplateImageMimeTypeFromBytes,
  badgeTemplateImagePublicPath,
  storeBadgeTemplateImage,
} from "../badges/template-image-storage";
import { canonicalAppUrl } from "../http/canonical-app-url";
import { loadPublicBytesFromUrl, type PublicJsonNetwork } from "../http/public-json-network";

const importedImageBytes = async (
  network: PublicJsonNetwork,
  payload: ImportMigrationBatchQueueJob["payload"],
): Promise<Uint8Array> => {
  if (payload.bakedBadgeImage !== undefined) {
    const encoded = payload.bakedBadgeImage.includes(",")
      ? (payload.bakedBadgeImage.split(",", 2)[1] ?? "")
      : payload.bakedBadgeImage;

    try {
      return Uint8Array.from(atob(encoded), (character) => character.charCodeAt(0));
    } catch {
      throw new Error("Migration badge artwork is not valid base64 image data");
    }
  }

  const imageUri = payload.conversion.createBadgeTemplateRequest.imageUri;

  if (imageUri === undefined) {
    throw new Error("Migration row does not provide badge artwork");
  }

  const loaded = await loadPublicBytesFromUrl(network, {
    resourceUrl: imageUri,
    headers: new Headers({ accept: "image/png, image/jpeg, image/webp" }),
    maxResponseBytes: BADGE_TEMPLATE_IMAGE_MAX_BYTES,
  });

  if (loaded.status === "error") {
    throw new Error(`Migration badge artwork could not be downloaded (${loaded.error.kind})`);
  }

  return loaded.bodyBytes;
};

/** Applies one validated OB2 migration queue row and issues its idempotent OB3 credential. */
export const processMigrationBatchQueueJob = async <ContextType>(input: {
  context: ContextType;
  db: SqlDatabase;
  tenantId: string;
  payload: ImportMigrationBatchQueueJob["payload"];
  idempotencyKey: string;
  store: ImmutableCredentialStore;
  publicAppOrigin: string;
  publicJsonNetwork: PublicJsonNetwork;
  issueBadgeForTenant: (
    context: ContextType,
    tenantId: string,
    request: DirectIssueBadgeRequest,
    issuedByUserId?: string,
    options?: DirectIssueBadgeOptions,
  ) => Promise<DirectIssueBadgeResult>;
}): Promise<DirectIssueBadgeResult> => {
  const requestedTemplate = input.payload.conversion.createBadgeTemplateRequest;
  const manualIssue = input.payload.conversion.manualIssueRequest;
  const issueOptions = input.payload.conversion.issueOptions;
  const options: DirectIssueBadgeOptions = {
    ...(issueOptions.recipientDisplayName === undefined
      ? {}
      : { recipientDisplayName: issueOptions.recipientDisplayName }),
    ...(issueOptions.issuerName === undefined ? {} : { issuerName: issueOptions.issuerName }),
    ...(issueOptions.issuerUrl === undefined ? {} : { issuerUrl: issueOptions.issuerUrl }),
    issuedAt: input.payload.conversion.sourceMetadata.issuedOn,
    sendEmailNotification: false,
  };
  const existingAssertion = await findAssertionByIdempotencyKey(
    input.db,
    input.tenantId,
    input.idempotencyKey,
  );

  if (existingAssertion !== null) {
    if (existingAssertion.achievementSnapshotStatus !== "captured") {
      throw new Error(`Migration assertion "${existingAssertion.id}" has no achievement snapshot`);
    }

    return input.issueBadgeForTenant(
      input.context,
      input.tenantId,
      {
        recipientIdentity: manualIssue.recipientIdentity,
        recipientIdentityType: manualIssue.recipientIdentityType,
        idempotencyKey: input.idempotencyKey,
        achievementSource: {
          kind: "template_snapshot",
          snapshot: existingAssertion.achievementSnapshot,
          provenance: { source: "programmatic" },
        },
      },
      input.payload.requestedByUserId,
      options,
    );
  }

  const upserted = await upsertBadgeTemplateBySlug(input.db, {
    tenantId: input.tenantId,
    slug: requestedTemplate.slug,
    title: requestedTemplate.title,
    description: requestedTemplate.description,
    criteriaUri: requestedTemplate.criteriaUri,
    createdByUserId: input.payload.requestedByUserId,
  });
  const bytes = await importedImageBytes(input.publicJsonNetwork, input.payload);
  const mimeType = badgeTemplateImageMimeTypeFromBytes(bytes);

  if (mimeType === null) {
    throw new Error("Migration badge artwork is not a supported PNG, JPEG, or WebP image");
  }

  const assetId = `migration-${input.payload.batchId}-${String(input.payload.rowNumber)}`;
  await storeBadgeTemplateImage(input.store, {
    tenantId: input.tenantId,
    badgeTemplateId: upserted.template.id,
    assetId,
    mimeType,
    bytes,
    originalFilename: null,
  });
  const imageUri = canonicalAppUrl(
    input.publicAppOrigin,
    badgeTemplateImagePublicPath({
      tenantId: input.tenantId,
      badgeTemplateId: upserted.template.id,
      assetId,
    }),
  );
  const updatedTemplate =
    upserted.template.imageUri === imageUri
      ? upserted.template
      : await updateBadgeTemplate(input.db, {
          tenantId: input.tenantId,
          id: upserted.template.id,
          imageUri,
        });

  if (updatedTemplate === null) {
    throw new Error(`Migration badge template "${upserted.template.id}" could not be updated`);
  }

  const templateSnapshot = {
    ...upserted.template,
    imageUri,
  };

  const request: DirectIssueBadgeRequest = {
    recipientIdentity: manualIssue.recipientIdentity,
    recipientIdentityType: manualIssue.recipientIdentityType,
    idempotencyKey: input.idempotencyKey,
    achievementSource: {
      kind: "template_snapshot",
      snapshot: badgeAchievementSnapshotFromTemplate(templateSnapshot),
      provenance: { source: "programmatic" },
    },
  };
  return input.issueBadgeForTenant(
    input.context,
    input.tenantId,
    request,
    input.payload.requestedByUserId,
    options,
  );
};
