import type {
  ListBadgeIssuanceRuleRegistryPageInput,
  TenantMembershipRole,
  TenantReportingLifecycleFilter,
} from "@credtrail/db";
import type { AppContext } from "../../app/types";
import type { InstitutionAdminReportingView } from "../../admin/institution-admin/page-types";
import { loadInstitutionAdminReportingPageData } from "../tenant-admin-reporting-data-loader";
import {
  loadInstitutionAdminPageData as loadInstitutionAdminPageDataFromLoader,
  loadInstitutionAdminShellData as loadInstitutionAdminShellDataFromLoader,
  type InstitutionAdminPageData,
} from "../institution-admin-page-data-loader";
import { reportingAccessRequiredPage } from "../tenant-governance-shared-pages";
import type { RegisterTenantGovernanceRoutesInput } from "../tenant-governance-routes.types";

export type TenantGovernanceAdminPageDataLoaders = ReturnType<
  typeof createTenantGovernanceAdminPageDataLoaders
>;

export const createTenantGovernanceAdminPageDataLoaders = (
  input: Pick<RegisterTenantGovernanceRoutesInput, "resolveDatabase">,
) => {
  const { resolveDatabase } = input;

  const loadInstitutionAdminPageData = async (
    c: AppContext,
    tenantId: string,
    sessionUserId: string,
    membershipRole: TenantMembershipRole,
    options?: {
      view?: import("../../admin/institution-admin/page-types").InstitutionAdminView;
      badgeTemplatesIncludeArchived?: boolean;
      badgeRuleRegistryQuery?: Omit<ListBadgeIssuanceRuleRegistryPageInput, "tenantId" | "scope">;
    },
  ): Promise<InstitutionAdminPageData | Response> => {
    return loadInstitutionAdminPageDataFromLoader({
      c,
      tenantId,
      sessionUserId,
      membershipRole,
      resolveDatabase,
      ...(options?.view === undefined ? {} : { view: options.view }),
      ...(options?.badgeTemplatesIncludeArchived === undefined
        ? {}
        : { badgeTemplatesIncludeArchived: options.badgeTemplatesIncludeArchived }),
      ...(options?.badgeRuleRegistryQuery === undefined
        ? {}
        : { badgeRuleRegistryQuery: options.badgeRuleRegistryQuery }),
    });
  };

  const loadInstitutionAdminShellData = async (
    c: AppContext,
    tenantId: string,
    sessionUserId: string,
    membershipRole: TenantMembershipRole,
  ): Promise<
    | Pick<
        InstitutionAdminPageData,
        "membershipRole" | "switchOrganizationPath" | "tenant" | "userEmail" | "userId"
      >
    | Response
  > => {
    return loadInstitutionAdminShellDataFromLoader({
      c,
      tenantId,
      sessionUserId,
      membershipRole,
      resolveDatabase,
    });
  };

  const loadReportingPageData = async (input: {
    c: AppContext;
    tenantId: string;
    sessionUserId: string;
    membershipRole: TenantMembershipRole;
    view: InstitutionAdminReportingView;
    issuedFrom?: string | undefined;
    issuedTo?: string | undefined;
    badgeTemplateId?: string | undefined;
    orgUnitId?: string | undefined;
    state?: TenantReportingLifecycleFilter | undefined;
  }): Promise<InstitutionAdminPageData | Response> => {
    return loadInstitutionAdminReportingPageData({
      ...input,
      resolveDatabase,
      loadInstitutionAdminPageData,
      reportingAccessRequiredPage,
    });
  };

  return {
    loadInstitutionAdminPageData,
    loadInstitutionAdminShellData,
    loadReportingPageData,
  };
};
