import type { AccessibleTenantContextRecord, TenantMembershipRole } from "@credtrail/db";
import type { RequestedTenantContext } from "./auth-context";
import { tenantIdFromNextPath } from "./better-auth-runtime";
import { isSafeRedirectPath } from "./redirect-paths";

export interface AccessibleTenantContextView extends AccessibleTenantContextRecord {
  preferredPath: string;
}

export type TenantContextSelectionResult =
  | {
      kind: "redirect";
      tenantId: string;
      location: string;
    }
  | {
      kind: "chooser";
      location: string;
    }
  | {
      kind: "unavailable";
      reason: "no_access" | "requested_tenant_forbidden";
    };

const isAdminLandingRole = (role: TenantMembershipRole): boolean => {
  return role === "owner" || role === "admin";
};

export const preferredTenantLandingPath = (
  tenantId: string,
  membershipRole: TenantMembershipRole,
): string => {
  if (isAdminLandingRole(membershipRole)) {
    return `/tenants/${encodeURIComponent(tenantId)}/admin`;
  }

  return `/tenants/${encodeURIComponent(tenantId)}/learner/dashboard`;
};

export const toAccessibleTenantContextViews = (
  contexts: readonly AccessibleTenantContextRecord[],
): AccessibleTenantContextView[] => {
  return contexts.map((context) => ({
    ...context,
    preferredPath: preferredTenantLandingPath(context.tenantId, context.membershipRole),
  }));
};

export const buildOrganizationsPath = (nextPath?: string | null): string => {
  const normalizedNextPath = nextPath?.trim() ?? "";

  if (!isSafeRedirectPath(normalizedNextPath)) {
    return "/account/organizations";
  }

  const url = new URL("/account/organizations", "https://credtrail.local");
  url.searchParams.set("next", normalizedNextPath);
  return `${url.pathname}${url.search}`;
};

export const resolveChosenTenantLocation = (input: {
  contexts: readonly AccessibleTenantContextView[];
  tenantId: string;
  nextPath?: string | null;
}): string | null => {
  const context = input.contexts.find((candidate) => candidate.tenantId === input.tenantId);

  if (context === undefined) {
    return null;
  }

  const normalizedNextPath = input.nextPath?.trim() ?? "";
  const nextTenantId = tenantIdFromNextPath(normalizedNextPath);

  if (isSafeRedirectPath(normalizedNextPath) && nextTenantId === context.tenantId) {
    return normalizedNextPath;
  }

  return context.preferredPath;
};

export const resolveTenantContextSelection = (input: {
  contexts: readonly AccessibleTenantContextView[];
  requestedTenant: RequestedTenantContext | null;
  nextPath?: string | null;
}): TenantContextSelectionResult => {
  if (input.contexts.length === 0) {
    return {
      kind: "unavailable",
      reason: "no_access",
    };
  }

  const normalizedNextPath = input.nextPath?.trim() ?? "";
  const nextTenantId = tenantIdFromNextPath(normalizedNextPath);

  if (nextTenantId !== null) {
    const nextTenantLocation = resolveChosenTenantLocation({
      contexts: input.contexts,
      tenantId: nextTenantId,
      nextPath: normalizedNextPath,
    });

    if (nextTenantLocation === null) {
      return {
        kind: "unavailable",
        reason: "requested_tenant_forbidden",
      };
    }

    return {
      kind: "redirect",
      tenantId: nextTenantId,
      location: nextTenantLocation,
    };
  }

  const rememberedTenantId = input.requestedTenant?.tenantId?.trim() ?? "";

  if (rememberedTenantId.length > 0) {
    const rememberedLocation = resolveChosenTenantLocation({
      contexts: input.contexts,
      tenantId: rememberedTenantId,
    });

    if (rememberedLocation !== null) {
      return {
        kind: "redirect",
        tenantId: rememberedTenantId,
        location: rememberedLocation,
      };
    }
  }

  if (input.contexts.length === 1) {
    const [context] = input.contexts;

    if (context === undefined) {
      return {
        kind: "unavailable",
        reason: "no_access",
      };
    }

    return {
      kind: "redirect",
      tenantId: context.tenantId,
      location: context.preferredPath,
    };
  }

  return {
    kind: "chooser",
    location: buildOrganizationsPath(normalizedNextPath),
  };
};
