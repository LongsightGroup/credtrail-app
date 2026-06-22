import { createTenantBadgeCriteriaRegistryPage } from "./public-badge-criteria-registry-page";
import { createPublicBadgePage } from "./public-badge-detail-page";
import { createPublicBadgeNotFoundPage } from "./public-badge-not-found-page";
import type {
  CreatePublicBadgePageRenderersInput,
  PublicBadgePageRenderers,
} from "./public-badge-renderer-types";
import { createTenantBadgeWallPage } from "./public-badge-wall-page";

export type {
  CreatePublicBadgePageRenderersInput,
  PublicBadgeCriteriaRegistryViewModel,
  PublicBadgeCriteriaRuleViewRecord,
  PublicBadgeCriteriaTemplateViewRecord,
  PublicBadgePageRenderers,
  PublicBadgeWallEntryViewRecord,
} from "./public-badge-renderer-types";

export const createPublicBadgePageRenderers = (
  input: CreatePublicBadgePageRenderersInput,
): PublicBadgePageRenderers => {
  return {
    publicBadgeNotFoundPage: createPublicBadgeNotFoundPage(),
    publicBadgePage: createPublicBadgePage(input),
    tenantBadgeWallPage: createTenantBadgeWallPage(input),
    tenantBadgeCriteriaRegistryPage: createTenantBadgeCriteriaRegistryPage(input),
  };
};
