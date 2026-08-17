import { AdminStatusPill, AdminWorkspaceCard } from "../components";
import type { InstitutionAdminPageInput } from "./page-types";
import type { InstitutionAdminViewContentInput } from "./view-content";
import type { buildInstitutionAdminViewPaths } from "./view-paths";

export const buildInstitutionAdminHomeViewResources = (input: {
  page: InstitutionAdminPageInput;
  paths: ReturnType<typeof buildInstitutionAdminViewPaths>;
  enabled: boolean;
}): InstitutionAdminViewContentInput["home"] => {
  if (!input.enabled) {
    return { workspaceCardsMarkup: <></> };
  }

  const { page, paths } = input;
  const badgeTemplateCount = String(page.badgeTemplates.length);
  const ruleCount = String(page.badgeRules.length);

  return {
    workspaceCardsMarkup: (
      <section class="ct-admin__workspace-grid ct-grid" aria-label="Institution admin workspaces">
        <AdminWorkspaceCard
          href={paths.operationsManualIssuePath}
          ariaLabel="Open Issuance workspace"
        >
          <h2>Issuance</h2>
          <p>
            Issue badges, route manual review, inspect issued badges, and update badge status across
            focused pages.
          </p>
          <div class="ct-admin__workspace-stats ct-cluster">
            <AdminStatusPill>{badgeTemplateCount} templates</AdminStatusPill>
            <AdminStatusPill>{ruleCount} rules</AdminStatusPill>
          </div>
        </AdminWorkspaceCard>
        <AdminWorkspaceCard
          href={paths.operationsLearnerRecordsPath}
          ariaLabel="Open Learner Records workspace"
        >
          <h2>Learner Records</h2>
          <p>View, import, and export learner records.</p>
        </AdminWorkspaceCard>
        <AdminWorkspaceCard
          href={paths.rulesWorkspacePath}
          ariaLabel="Open Badge Program workspace"
        >
          <h2>Badge Program</h2>
          <p>
            Review awarding rules, maintain reusable lists, and open focused pages for builder and
            template maintenance.
          </p>
          {page.badgeRules.length === 0 ? (
            <p class="ct-admin__hint">No badge rules found. Create your first rule.</p>
          ) : null}
          <div class="ct-admin__workspace-stats ct-cluster">
            <AdminStatusPill>{ruleCount} active rule records</AdminStatusPill>
            <AdminStatusPill>{badgeTemplateCount} templates</AdminStatusPill>
          </div>
        </AdminWorkspaceCard>
        <AdminWorkspaceCard href={paths.reportingPath} ariaLabel="Open Reporting workspace">
          <h2>Reporting</h2>
          <p>
            Track issuance volume and badge status with filters, definitions, and clear source
            notes.
          </p>
          <div class="ct-admin__workspace-stats ct-cluster">
            <AdminStatusPill>Issued {page.reportingOverview?.counts.issued ?? 0}</AdminStatusPill>
            <AdminStatusPill>
              Pending review {page.reportingOverview?.counts.pendingReview ?? 0}
            </AdminStatusPill>
          </div>
        </AdminWorkspaceCard>
        <AdminWorkspaceCard
          href={paths.accessMembersPath}
          ariaLabel="Open People & Access workspace"
        >
          <h2>People &amp; Access</h2>
          <p>
            Manage members, governance delegation, API keys, LMS connections, and org structure.
          </p>
          <div class="ct-admin__workspace-stats ct-cluster">
            <AdminStatusPill>{String(page.tenantMembers.length)} members</AdminStatusPill>
            <AdminStatusPill>{String(page.activeApiKeys.length)} active keys</AdminStatusPill>
            <AdminStatusPill>{String(page.orgUnits.length)} org units</AdminStatusPill>
          </div>
        </AdminWorkspaceCard>
      </section>
    ),
  };
};
