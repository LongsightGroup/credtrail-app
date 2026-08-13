import type { ListBadgeIssuanceRuleRegistryPageInput, TenantMembershipRole } from "@credtrail/db";
import type { AppPage, renderAppPage } from "../ui/render-page";
import type { AppContext } from "../app";

export type InstitutionAdminWorkspaceRoleCheck =
  | Response
  | {
      session: { userId: string };
      membershipRole: TenantMembershipRole;
    };

export interface LoadInstitutionAdminWorkspaceInput<TPageData> {
  c: AppContext;
  tenantId: string;
  nextPath: string;
  view?: import("./institution-admin/page-types").InstitutionAdminView;
  resolveInstitutionAdminAdminRole: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ) => Promise<InstitutionAdminWorkspaceRoleCheck>;
  loadInstitutionAdminPageData: (
    c: AppContext,
    tenantId: string,
    sessionUserId: string,
    membershipRole: TenantMembershipRole,
    options?: {
      view?: import("./institution-admin/page-types").InstitutionAdminView;
      badgeTemplatesIncludeArchived?: boolean;
      badgeRuleRegistryQuery?: Omit<ListBadgeIssuanceRuleRegistryPageInput, "tenantId" | "scope">;
    },
  ) => Promise<TPageData | Response>;
}

export const loadInstitutionAdminWorkspacePageData = async <TPageData>(
  input: LoadInstitutionAdminWorkspaceInput<TPageData>,
): Promise<
  | Response
  | {
      pageData: TPageData;
      session: { userId: string };
      membershipRole: TenantMembershipRole;
    }
> => {
  const roleCheck = await input.resolveInstitutionAdminAdminRole(
    input.c,
    input.tenantId,
    input.nextPath,
  );

  if (roleCheck instanceof Response) {
    return roleCheck;
  }

  const { session, membershipRole } = roleCheck;
  const pageData = await input.loadInstitutionAdminPageData(
    input.c,
    input.tenantId,
    session.userId,
    membershipRole,
    input.view === undefined ? {} : { view: input.view },
  );

  if (pageData instanceof Response) {
    return pageData;
  }

  return {
    pageData,
    session: { userId: session.userId },
    membershipRole,
  };
};

export const renderInstitutionAdminWorkspacePage = async (
  c: AppContext,
  renderAppPageFn: typeof renderAppPage,
  page: AppPage,
): Promise<Response> => {
  c.header("Cache-Control", "no-store");

  return await renderAppPageFn(c, page);
};
