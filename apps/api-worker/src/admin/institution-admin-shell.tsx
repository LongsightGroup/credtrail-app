import type { TenantMembershipRole, TenantRecord } from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import { appPage, type AppPage } from "../ui/render-page";
import type { PageAssetKey } from "../ui/page-assets";
import {
  AdminPageHeader,
  AdminShell,
  AdminSidebar,
  AdminTopbar,
  type AdminSidebarFooterLink,
} from "./components";
import {
  buildInstitutionAdminSidebarPaths,
  buildInstitutionAdminSidebarSectionsForTenant,
  type InstitutionAdminSidebarView,
} from "./institution-admin-sidebar";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

export type InstitutionAdminShellView = InstitutionAdminSidebarView;

export interface InstitutionAdminShellPaths {
  tenantAdminPath: string;
  operationsPath: string;
  operationsLearnerRecordsPath: string;
  operationsLearnerRecordImportsPath: string;
  operationsReviewQueuePath: string;
  operationsIssuedBadgesPath: string;
  operationsBadgeStatusPath: string;
  reportingPath: string;
  reportingExplorePath: string;
  reportingTrendsPath: string;
  reportingReportsPath: string;
  rulesWorkspacePath: string;
  rulesApprovalsPath: string;
  rulesTemplatesPath: string;
  ruleBuilderPath: string;
  accessPath: string;
  accessMembersPath: string;
  accessOrgUnitAccessPath: string;
  accessGovernancePath: string;
  accessDelegationsPath: string;
  accessAuthenticationPath: string;
  accessApiKeysPath: string;
  accessLmsConnectionsPath: string;
  accessOrgUnitsPath: string;
  operationsManualIssuePath: string;
  showcasePath: string;
}

export const serializeJsonScriptContent = (value: unknown): string => {
  return JSON.stringify(value)
    .replaceAll("<", "\\u003c")
    .replaceAll(">", "\\u003e")
    .replaceAll("&", "\\u0026")
    .replaceAll("\u2028", "\\u2028")
    .replaceAll("\u2029", "\\u2029");
};

export const buildInstitutionAdminShellPaths = (tenantId: string): InstitutionAdminShellPaths => {
  const sidebarPaths = buildInstitutionAdminSidebarPaths(tenantId);

  return {
    ...sidebarPaths,
    showcasePath: `/showcase/${encodeURIComponent(tenantId)}`,
  };
};

const buildSidebarFooterLinks = (input: {
  paths: InstitutionAdminShellPaths;
  switchOrganizationPath?: string | null;
}): readonly AdminSidebarFooterLink[] => {
  const switchOrganizationPath = input.switchOrganizationPath?.trim() ?? "";

  return [
    {
      href: input.paths.showcasePath,
      label: "Public showcase",
      isExternal: true,
      target: "_blank",
      rel: "noopener noreferrer",
    },
    ...(switchOrganizationPath.length > 0
      ? [{ href: switchOrganizationPath, label: "Switch organization" }]
      : []),
  ];
};

export const renderInstitutionAdminPageHeader = (
  title: string,
  description: string,
  noteMarkup: HonoElement | null = null,
): HonoElement => {
  return <AdminPageHeader title={title} description={description} note={noteMarkup} />;
};

export const renderInstitutionAdminShellPage = (input: {
  tenant: TenantRecord;
  userId: string;
  userEmail?: string | undefined;
  membershipRole: TenantMembershipRole;
  view: InstitutionAdminShellView;
  title: string;
  assets: PageAssetKey[];
  contextJson: unknown;
  switchOrganizationPath?: string | null;
  children: HonoElement;
}): AppPage => {
  const paths = buildInstitutionAdminShellPaths(input.tenant.id);
  const userLabel = input.userEmail ?? input.userId;

  return appPage({
    title: input.title,
    assets: input.assets,
    variant: "admin",
    body: (
      <AdminShell
        sidebar={
          <AdminSidebar
            brandHref={paths.tenantAdminPath}
            sections={buildInstitutionAdminSidebarSectionsForTenant(
              input.tenant.id,
              input.view,
              input.tenant.planTier,
            )}
            footerLinks={buildSidebarFooterLinks({
              paths,
              ...(input.switchOrganizationPath === undefined
                ? {}
                : { switchOrganizationPath: input.switchOrganizationPath }),
            })}
          />
        }
        topbar={
          <AdminTopbar
            title={input.tenant.displayName}
            chips={[{ label: input.membershipRole }, { label: input.tenant.planTier }]}
            userLabel={userLabel}
            userTitle={`User ID: ${input.userId}`}
          />
        }
      >
        {input.children}
        <div
          id="ct-admin-context"
          hidden
          data-context-json={serializeJsonScriptContent(input.contextJson)}
        ></div>
      </AdminShell>
    ),
  });
};
