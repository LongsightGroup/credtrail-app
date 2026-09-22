import type { BadgeWorkflowTask } from "@credtrail/db";
import {
  AdminButtonLink,
  AdminMeta,
  AdminPanel,
  AdminStatusPill,
  AdminWorkspaceCard,
} from "../components";
import {
  buildBadgeRuleVersionDetailPath,
  buildBadgeRuleVersionReviewPath,
} from "../access-admin-helpers";
import type { InstitutionAdminPageInput } from "./page-types";
import type { InstitutionAdminViewContentInput } from "./view-content";
import type { buildInstitutionAdminViewPaths } from "./view-paths";

const taskLabels: Record<BadgeWorkflowTask["action"], string> = {
  revise: "Review feedback and revise",
  configure_approval: "Set up an eligible reviewer",
  review: "Review submission",
  activate: "Review and activate",
  schedule: "Set the term end date",
  placement: "Set course availability",
  resume: "Review suspended rule",
  submit: "Review and submit draft",
};

/** Renders real pending work separately from Home's navigation links. */
export const buildInstitutionAdminHomeViewResources = (input: {
  page: Pick<
    InstitutionAdminPageInput,
    "tenant" | "workflowHome" | "badgeWorkflowResponsibilities" | "operationsAttention"
  >;
  paths: ReturnType<typeof buildInstitutionAdminViewPaths>;
}): InstitutionAdminViewContentInput["home"] => {
  const { page, paths } = input;
  const home = page.workflowHome;
  return {
    workspaceCardsMarkup: (
      <div class="ct-admin__home-layout">
        <section class="ct-admin__workspace-grid ct-grid" aria-label="Institution admin workspaces">
          <AdminWorkspaceCard
            href={paths.operationsManualIssuePath}
            ariaLabel="Open Issuance workspace"
          >
            <h2>Issuance</h2>
            <p>Issue badges, review learner eligibility, and inspect issued badges.</p>
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
              Set up badges and rules, check who must approve them, and choose how badges are
              awarded.
            </p>
            {home?.ruleCount === 0 ? (
              <p class="ct-admin__hint">No badge rules found. Create your first rule.</p>
            ) : null}
            {home === undefined ? null : (
              <div class="ct-admin__workspace-stats ct-cluster">
                <AdminStatusPill>
                  {home.ruleCount} {home.ruleCount === 1 ? "rule" : "rules"}
                </AdminStatusPill>
                <AdminStatusPill>{home.activeRuleCount} active</AdminStatusPill>
              </div>
            )}
          </AdminWorkspaceCard>
          <AdminWorkspaceCard href={paths.reportingPath} ariaLabel="Open Reporting workspace">
            <h2>Reporting</h2>
            <p>
              Track issuance volume and badge status with filters, definitions, and clear source
              notes.
            </p>
          </AdminWorkspaceCard>
          <AdminWorkspaceCard
            href={paths.accessMembersPath}
            ariaLabel="Open People & Access workspace"
          >
            <h2>People &amp; Access</h2>
            <p>
              Manage members, approval policies, issuing permissions, LMS connections, and
              departments.
            </p>
          </AdminWorkspaceCard>
        </section>
        <aside
          id="home-action-items"
          class="ct-admin__home-actions ct-stack"
          aria-labelledby="home-actions-heading"
        >
          <h2 id="home-actions-heading">Action items</h2>
          <AdminMeta>
            <span data-home-refresh-status="true">Refresh to see the latest actions.</span>
          </AdminMeta>
          <AdminButtonLink
            href={`/tenants/${encodeURIComponent(page.tenant.id)}/admin`}
            variant="quiet"
            dataAttributes={{ "data-refresh-home-actions": "true" }}
          >
            Refresh actions
          </AdminButtonLink>
          {page.operationsAttention &&
          (page.operationsAttention.pendingReviews > 0 ||
            page.operationsAttention.failedEmails > 0) ? (
            <AdminPanel as="section" className="ct-admin__workflow-tasks">
              <h3>Learner follow-up</h3>
              <ul class="ct-admin__workflow-task-list">
                {page.operationsAttention.pendingReviews > 0 ? (
                  <li>
                    <div>
                      <strong>
                        {page.operationsAttention.pendingReviews}{" "}
                        {page.operationsAttention.pendingReviews === 1
                          ? "learner review needs"
                          : "learner reviews need"}{" "}
                        a decision
                      </strong>
                      <p>Check supporting information before issuing a badge.</p>
                    </div>
                    <AdminButtonLink
                      href={`${paths.operationsPath}/review-queue?sort=oldest`}
                      variant="secondary"
                    >
                      Review waiting learners
                    </AdminButtonLink>
                  </li>
                ) : null}
                {page.operationsAttention.failedEmails > 0 ? (
                  <li>
                    <div>
                      <strong>
                        {page.operationsAttention.failedEmails}{" "}
                        {page.operationsAttention.failedEmails === 1
                          ? "notification email needs"
                          : "notification emails need"}{" "}
                        attention
                      </strong>
                      <p>The badges are issued. Their latest email attempts failed.</p>
                    </div>
                    <AdminButtonLink
                      href={`${paths.operationsPath}/issued-badges?notificationStatus=failed`}
                      variant="secondary"
                    >
                      Review failed emails
                    </AdminButtonLink>
                  </li>
                ) : null}
              </ul>
            </AdminPanel>
          ) : null}
          {home === undefined || home.actionCount === 0 ? null : (
            <AdminPanel as="section" className="ct-admin__workflow-tasks">
              <h3>Action needed</h3>
              <p class="ct-admin__hint">
                {home.actionCount} {home.actionCount === 1 ? "rule needs" : "rules need"} attention
                {home.actionCount > home.tasks.length
                  ? ` · Showing ${String(home.tasks.length)}`
                  : ""}
                .
              </p>
              <ul class="ct-admin__workflow-task-list">
                {home.tasks.map((task) => {
                  const version = task.version;
                  const responsibility = page.badgeWorkflowResponsibilities?.get(version.id);
                  const href =
                    task.action === "review"
                      ? buildBadgeRuleVersionReviewPath(page.tenant.id, version.ruleId, version.id)
                      : buildBadgeRuleVersionDetailPath(page.tenant.id, version.ruleId, version.id);
                  return (
                    <li>
                      <div>
                        {task.action === "revise" ? (
                          <p>
                            <AdminStatusPill tone="warning">Changes requested</AdminStatusPill>
                          </p>
                        ) : null}
                        <strong>{version.snapshot.name}</strong>
                        <AdminMeta>
                          {version.snapshot.badgeTemplateTitle} · Version {version.versionNumber}
                        </AdminMeta>
                        {responsibility === undefined ? null : (
                          <>
                            {task.action === "revise" ? (
                              <>
                                <p>
                                  Review the feedback, revise this rule, and resubmit it for
                                  approval.
                                </p>
                                <p>{responsibility.approval.detail}</p>
                                <AdminMeta>Rule author: {responsibility.ruleAuthor}</AdminMeta>
                              </>
                            ) : (
                              <p>Approval: {responsibility.approval.label}</p>
                            )}
                            {task.action === "revise" ? null : (
                              <AdminMeta>
                                Badge owner: {responsibility.badgeOwner} · {responsibility.awarding}
                              </AdminMeta>
                            )}
                          </>
                        )}
                        <AdminMeta>
                          {task.action === "revise"
                            ? "An administrator with access to this rule can revise and resubmit it."
                            : task.action === "review"
                              ? "You can review this submission."
                              : "An institution administrator can take the next step."}
                        </AdminMeta>
                      </div>
                      <AdminButtonLink variant="secondary" href={href}>
                        {task.action !== "revise" && responsibility?.approval.kind === "blocked"
                          ? taskLabels.configure_approval
                          : taskLabels[task.action]}
                      </AdminButtonLink>
                    </li>
                  );
                })}
              </ul>
              {home.actionCount > home.tasks.length ? (
                <a href={paths.rulesWorkspacePath}>View all rules</a>
              ) : null}
            </AdminPanel>
          )}
          {home === undefined || home.waitingCount === 0 ? null : (
            <p class="ct-admin__hint">
              {home.waitingCount} of your submitted{" "}
              {home.waitingCount === 1 ? "rules is" : "rules are"} waiting for another reviewer.{" "}
              <a href={paths.rulesWorkspacePath}>View submitted rules</a>.
            </p>
          )}
          {(home?.actionCount ?? 0) === 0 &&
          (home?.waitingCount ?? 0) === 0 &&
          (page.operationsAttention?.pendingReviews ?? 0) === 0 &&
          (page.operationsAttention?.failedEmails ?? 0) === 0 ? (
            <p class="ct-admin__hint">No action items right now.</p>
          ) : null}
        </aside>
      </div>
    ),
  };
};
