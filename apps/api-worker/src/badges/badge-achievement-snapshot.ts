import type { ImmutableCredentialStore } from "@credtrail/core-domain";
import {
  badgeAchievementSnapshotFromTemplate,
  type ExpectedBadgeTemplateRevision,
  type BadgeTemplateRecord,
} from "@credtrail/db";
import {
  resolveManagedBadgeTemplateImageReference,
  type BadgeAchievementSnapshot,
} from "@credtrail/validation";
import { canonicalAppUrl } from "../http/canonical-app-url";
import { readBadgeTemplateImage } from "./template-image-storage";

export { badgeAchievementSnapshotFromTemplate };

export type ResolveIssuableBadgeAchievementSnapshotResult =
  | {
      readonly status: "resolved";
      readonly snapshot: BadgeAchievementSnapshot;
    }
  | {
      readonly status: "unmanaged_artwork" | "missing_artwork" | "invalid_artwork";
    }
  | {
      readonly status: "storage_unavailable";
      readonly cause: unknown;
    };

/** Typed artwork-resolution failure returned before a badge can be issued. */
export type IssuableBadgeArtworkFailure = Exclude<
  ResolveIssuableBadgeAchievementSnapshotResult,
  { readonly status: "resolved" }
>;

export type BadgeTemplateArtworkReadiness =
  | "ready"
  | "missing_artwork"
  | "unmanaged_artwork"
  | "invalid_artwork"
  | "storage_unavailable";

export type ResolveExpectedBadgeTemplateRevisionResult =
  | {
      readonly status: "ready";
      readonly revision: ExpectedBadgeTemplateRevision;
    }
  | {
      readonly status: Exclude<BadgeTemplateArtworkReadiness, "ready" | "storage_unavailable">;
    }
  | {
      readonly status: "storage_unavailable";
      readonly cause: unknown;
    };

/** Verifies managed artwork exists and canonicalizes its public URL before issuance. */
export const resolveIssuableBadgeAchievementSnapshot = async (input: {
  readonly store: ImmutableCredentialStore;
  readonly publicAppOrigin: string;
  readonly tenantId: string;
  readonly snapshot: BadgeAchievementSnapshot;
}): Promise<ResolveIssuableBadgeAchievementSnapshotResult> => {
  if (input.snapshot.imageUri === null) {
    return { status: "missing_artwork" };
  }

  const imageReference = resolveManagedBadgeTemplateImageReference({
    imageUri: input.snapshot.imageUri,
    tenantId: input.tenantId,
    badgeTemplateId: input.snapshot.badgeTemplateId,
  });

  if (imageReference === null) {
    return { status: "unmanaged_artwork" };
  }

  let storedImageResult: Awaited<ReturnType<typeof readBadgeTemplateImage>>;

  try {
    storedImageResult = await readBadgeTemplateImage(input.store, imageReference);
  } catch (cause: unknown) {
    return { status: "storage_unavailable", cause };
  }

  if (storedImageResult.status === "missing") {
    return { status: "missing_artwork" };
  }

  if (storedImageResult.status === "invalid") {
    return { status: "invalid_artwork" };
  }

  return {
    status: "resolved",
    snapshot: {
      ...input.snapshot,
      imageUri: canonicalAppUrl(input.publicAppOrigin, imageReference.path),
    },
  };
};

/** Resolves the one template revision that may be captured by rule authoring. */
export const resolveExpectedBadgeTemplateRevision = async (input: {
  readonly store: ImmutableCredentialStore;
  readonly publicAppOrigin: string;
  readonly template: BadgeTemplateRecord;
}): Promise<ResolveExpectedBadgeTemplateRevisionResult> => {
  if (input.template.imageUri === null) {
    return { status: "missing_artwork" };
  }

  const artwork = await resolveIssuableBadgeAchievementSnapshot({
    store: input.store,
    publicAppOrigin: input.publicAppOrigin,
    tenantId: input.template.tenantId,
    snapshot: badgeAchievementSnapshotFromTemplate(input.template),
  });

  if (artwork.status !== "resolved") {
    return artwork;
  }

  if (artwork.snapshot.imageUri !== input.template.imageUri) {
    return { status: "unmanaged_artwork" };
  }

  return {
    status: "ready",
    revision: {
      updatedAt: input.template.updatedAt,
      achievementSnapshot: artwork.snapshot,
    },
  };
};
