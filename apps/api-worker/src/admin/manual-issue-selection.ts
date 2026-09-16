import type { BadgeTemplateRecord } from "@credtrail/db";
import type { ImmutableCredentialStore } from "@credtrail/core-domain";
import { manualIssuePageQuerySchema } from "@credtrail/validation";
import { resolveExpectedBadgeTemplateRevision } from "../badges/badge-achievement-snapshot";

export type ManualIssueSelection =
  | { readonly kind: "choose" }
  | { readonly kind: "ready"; readonly template: BadgeTemplateRecord }
  | {
      readonly kind: "blocked";
      readonly template: BadgeTemplateRecord | null;
      readonly message: string;
    };

export const resolveManualIssueSelection = async (input: {
  readonly query: unknown;
  readonly templates: readonly BadgeTemplateRecord[];
  readonly store: ImmutableCredentialStore;
  readonly publicAppOrigin: string;
}): Promise<{
  readonly selection: ManualIssueSelection;
  readonly pathwayHandoffId: string | null;
}> => {
  const query = manualIssuePageQuerySchema.safeParse(input.query);
  if (!query.success)
    return {
      selection: {
        kind: "blocked",
        template: null,
        message: "This badge selection is invalid. Choose a badge to continue.",
      },
      pathwayHandoffId: null,
    };
  const pathwayHandoffId = query.data.pathwayHandoffId ?? null;
  if (query.data.badgeTemplateId === undefined)
    return { selection: { kind: "choose" }, pathwayHandoffId };
  const template = input.templates.find(
    (entry) => entry.id === query.data.badgeTemplateId && !entry.isArchived,
  );
  if (template === undefined)
    return {
      selection: {
        kind: "blocked",
        template: null,
        message:
          "This badge is unavailable for issuance. Choose an active badge from this institution.",
      },
      pathwayHandoffId,
    };
  const artwork = await resolveExpectedBadgeTemplateRevision({
    store: input.store,
    publicAppOrigin: input.publicAppOrigin,
    template,
  });
  if (artwork.status === "ready")
    return { selection: { kind: "ready", template }, pathwayHandoffId };
  const message =
    artwork.status === "storage_unavailable"
      ? "Artwork could not be checked. Reload this page to try again."
      : artwork.status === "missing_artwork"
        ? "Add artwork before issuing this badge."
        : "Replace the artwork before issuing this badge.";
  return { selection: { kind: "blocked", template, message }, pathwayHandoffId };
};
