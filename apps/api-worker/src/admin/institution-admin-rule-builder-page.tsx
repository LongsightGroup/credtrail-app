import type {
  BadgeIssuanceRuleRecord,
  BadgeIssuanceRuleVersionRecord,
  BadgeTemplateRecord,
  TenantMembershipRole,
  TenantRecord,
} from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import { appPage, type AppPage } from "../ui/render-page";
import { AdminButton, AdminSidebarToggle } from "./components";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

const serializeJsonScriptContent = (value: unknown): string => {
  return JSON.stringify(value)
    .replaceAll("<", "\\u003c")
    .replaceAll(">", "\\u003e")
    .replaceAll("&", "\\u0026")
    .replaceAll("\u2028", "\\u2028")
    .replaceAll("\u2029", "\\u2029");
};

const SidebarLink = (props: {
  href: string;
  label: string;
  isCurrent: boolean;
  extraClass?: string;
}) => {
  const className =
    props.extraClass === undefined
      ? "ct-admin-sidebar__link"
      : `ct-admin-sidebar__link ${props.extraClass}`;

  return (
    <a class={className} href={props.href} aria-current={props.isCurrent ? "page" : undefined}>
      {props.label}
    </a>
  );
};

type RuleBuilderStepTarget = "metadata" | "conditions" | "test" | "review";

const RuleBuilderStepButton = (props: {
  stepNumber: number;
  target: RuleBuilderStepTarget;
  title: string;
  description: string;
}): HonoElement => {
  return (
    <button type="button" class="ct-admin__step-button" data-rule-step-target={props.target}>
      <span class="ct-admin__step-number">{props.stepNumber}</span>
      <span class="ct-admin__step-copy">
        <strong>{props.title}</strong>
        <small>{props.description}</small>
      </span>
    </button>
  );
};

export const institutionAdminRuleBuilderPage = (input: {
  tenant: TenantRecord;
  userId: string;
  userEmail?: string;
  membershipRole: TenantMembershipRole;
  badgeTemplates: readonly BadgeTemplateRecord[];
  badgeRules: readonly BadgeIssuanceRuleRecord[];
  badgeRuleVersions: readonly BadgeIssuanceRuleVersionRecord[];
  switchOrganizationPath?: string | null;
}): AppPage => {
  const versionsByRuleId = new Map<string, BadgeIssuanceRuleVersionRecord[]>();

  for (const version of input.badgeRuleVersions) {
    const versions = versionsByRuleId.get(version.ruleId);

    if (versions === undefined) {
      versionsByRuleId.set(version.ruleId, [version]);
      continue;
    }

    versions.push(version);
  }

  for (const versions of versionsByRuleId.values()) {
    versions.sort((left, right) => right.versionNumber - left.versionNumber);
  }

  const tenantAdminPath = `/tenants/${encodeURIComponent(input.tenant.id)}/admin`;
  const ruleBuilderPath = `${tenantAdminPath}/rules/new`;
  const manualIssueApiPath = `/v1/tenants/${encodeURIComponent(input.tenant.id)}/assertions/manual-issue`;
  const createApiKeyPath = `/v1/tenants/${encodeURIComponent(input.tenant.id)}/api-keys`;
  const createOrgUnitPath = `/v1/tenants/${encodeURIComponent(input.tenant.id)}/org-units`;
  const badgeTemplateApiPathPrefix = `/v1/tenants/${encodeURIComponent(
    input.tenant.id,
  )}/badge-templates`;
  const badgeRuleApiPath = `/v1/tenants/${encodeURIComponent(input.tenant.id)}/badge-rules`;
  const badgeRuleValueListApiPath = `/v1/tenants/${encodeURIComponent(
    input.tenant.id,
  )}/badge-rule-value-lists`;
  const badgeRulePreviewSimulationApiPath = `${badgeRuleApiPath}/preview-simulate`;
  const badgeRuleReviewQueueApiPath = `${badgeRuleApiPath}/review-queue`;
  const assertionsApiPathPrefix = `/v1/tenants/${encodeURIComponent(input.tenant.id)}/assertions`;
  const tenantUsersApiPathPrefix = `/v1/tenants/${encodeURIComponent(input.tenant.id)}/users`;
  const showcasePath = `/showcase/${encodeURIComponent(input.tenant.id)}`;
  const adminAuditLogPath = `/admin/audit-logs?tenantId=${encodeURIComponent(input.tenant.id)}`;
  const switchOrganizationPath = input.switchOrganizationPath?.trim() ?? "";
  const userLabel = input.userEmail ?? input.userId;

  const templateOptions = input.badgeTemplates.map((template, index) => ({
    template,
    isSelected: index === 0,
  }));

  const ruleCloneOptions = input.badgeRules.map((rule) => {
    const versions = versionsByRuleId.get(rule.id) ?? [];
    const latestVersion = versions[0] ?? null;
    const latestLabel =
      latestVersion === null
        ? "none"
        : `v${String(latestVersion.versionNumber)} ${latestVersion.status}`;

    return {
      rule,
      label: `${rule.name} (${rule.id}) · latest ${latestLabel}`,
    };
  });

  const adminPageContextJson = serializeJsonScriptContent({
    tenantAdminPath,
    manualIssueApiPath,
    createApiKeyPath,
    createOrgUnitPath,
    badgeTemplateApiPathPrefix,
    badgeRuleApiPath,
    badgeRuleValueListApiPath,
    badgeRulePreviewSimulationApiPath,
    badgeRuleReviewQueueApiPath,
    assertionsApiPathPrefix,
    tenantUsersApiPathPrefix,
  });

  const rulesWorkspacePath = `${tenantAdminPath}/rules`;
  const operationsPath = `${tenantAdminPath}/operations`;
  const operationsLearnerRecordsPath = `${operationsPath}/learner-records`;
  const operationsLearnerRecordImportsPath = `${operationsPath}/learner-record-imports`;
  const operationsReviewQueuePath = `${operationsPath}/review-queue`;
  const operationsIssuedBadgesPath = `${operationsPath}/issued-badges`;
  const operationsBadgeStatusPath = `${operationsPath}/badge-status`;
  const reportingPath = `${tenantAdminPath}/reporting`;
  const accessPath = `${tenantAdminPath}/access`;
  const accessMembersPath = `${accessPath}/members`;
  const accessGovernancePath = `${accessPath}/governance`;
  const accessApiKeysPath = `${accessPath}/api-keys`;
  const accessOrgUnitsPath = `${accessPath}/org-units`;

  return appPage({
    title: `Rule Builder · ${input.tenant.displayName}`,
    assets: ["institutionAdminCss", "institutionAdminJs"],
    variant: "admin",
    body: (
      <div class="ct-admin-shell">
        <aside class="ct-admin-sidebar">
          <a class="ct-admin-sidebar__brand" href={tenantAdminPath}>
            CredTrail
          </a>
          <nav class="ct-admin-sidebar__nav" aria-label="Admin navigation">
            <SidebarLink href={tenantAdminPath} label="Home" isCurrent={false} />

            <p class="ct-admin-sidebar__section-label">Operations</p>
            <SidebarLink href={operationsPath} label="Overview" isCurrent={false} />
            <SidebarLink
              href={operationsLearnerRecordsPath}
              label="Learner Records"
              isCurrent={false}
              extraClass="ct-admin-sidebar__link--sub"
            />
            <SidebarLink
              href={operationsLearnerRecordImportsPath}
              label="Learner Record Imports"
              isCurrent={false}
              extraClass="ct-admin-sidebar__link--sub"
            />
            <SidebarLink
              href={operationsReviewQueuePath}
              label="Review Queue"
              isCurrent={false}
              extraClass="ct-admin-sidebar__link--sub"
            />
            <SidebarLink
              href={operationsIssuedBadgesPath}
              label="Issued Badges"
              isCurrent={false}
              extraClass="ct-admin-sidebar__link--sub"
            />
            <SidebarLink
              href={operationsBadgeStatusPath}
              label="Badge Status"
              isCurrent={false}
              extraClass="ct-admin-sidebar__link--sub"
            />

            <p class="ct-admin-sidebar__section-label">Reporting</p>
            <SidebarLink href={reportingPath} label="Overview" isCurrent={false} />

            <p class="ct-admin-sidebar__section-label">Configuration</p>
            <SidebarLink href={rulesWorkspacePath} label="Rules" isCurrent={false} />
            <SidebarLink
              href={ruleBuilderPath}
              label="Rule Builder"
              isCurrent={true}
              extraClass="ct-admin-sidebar__link--sub"
            />

            <p class="ct-admin-sidebar__section-label">Access</p>
            <SidebarLink href={accessPath} label="Overview" isCurrent={false} />
            <SidebarLink
              href={accessMembersPath}
              label="Members"
              isCurrent={false}
              extraClass="ct-admin-sidebar__link--sub"
            />
            <SidebarLink
              href={accessGovernancePath}
              label="Governance"
              isCurrent={false}
              extraClass="ct-admin-sidebar__link--sub"
            />
            <SidebarLink
              href={accessApiKeysPath}
              label="API Keys"
              isCurrent={false}
              extraClass="ct-admin-sidebar__link--sub"
            />
            <SidebarLink
              href={accessOrgUnitsPath}
              label="Org Units"
              isCurrent={false}
              extraClass="ct-admin-sidebar__link--sub"
            />
          </nav>
          <div class="ct-admin-sidebar__footer">
            <a
              class="ct-admin-sidebar__footer-link ct-admin-sidebar__link--external"
              href={adminAuditLogPath}
            >
              Audit logs
            </a>
            <a
              class="ct-admin-sidebar__footer-link ct-admin-sidebar__link--external"
              href={showcasePath}
              target="_blank"
              rel="noopener noreferrer"
            >
              Public showcase
            </a>
            {switchOrganizationPath.length === 0 ? null : (
              <a class="ct-admin-sidebar__footer-link" href={switchOrganizationPath}>
                Switch organization
              </a>
            )}
          </div>
        </aside>
        <div class="ct-admin-main">
          <header class="ct-admin-topbar">
            <AdminSidebarToggle />
            <p class="ct-admin-topbar__title">{input.tenant.displayName}</p>
            <div class="ct-admin-topbar__user">
              <span class="ct-admin-topbar__chip">{input.membershipRole}</span>
              <span title={`User ID: ${input.userId}`}>{userLabel}</span>
            </div>
          </header>
          <div class="ct-admin-content ct-admin-content--rule-builder">
            <div class="ct-admin-page-header ct-admin-page-header--compact">
              <h1>Rule Builder</h1>
              <p>Create one badge issuance rule at a time. Draft, test, then submit for review.</p>
              <details class="ct-admin__builder-guide">
                <summary>How rule drafts work</summary>
                <p>
                  Set the rule identity, model the conditions, run a dry run, then create a draft
                  for governance review.
                </p>
              </details>
            </div>

            <section class="ct-admin__builder-shell ct-stack">
              <section
                class="ct-admin__panel ct-admin__builder-stepper-panel ct-stack"
                aria-label="Rule builder workflow"
              >
                <p class="ct-admin__eyebrow">Workflow</p>
                <h2>Build in four passes</h2>
                <ol
                  id="rule-builder-stepper"
                  class="ct-admin__builder-steps"
                  aria-label="Rule builder steps"
                >
                  <li>
                    <RuleBuilderStepButton
                      stepNumber={1}
                      target="metadata"
                      title="Metadata"
                      description="Name the rule and bind it to the right badge and LMS."
                    />
                  </li>
                  <li>
                    <RuleBuilderStepButton
                      stepNumber={2}
                      target="conditions"
                      title="Conditions"
                      description="Shape the qualification logic and keep the JSON in sync."
                    />
                  </li>
                  <li>
                    <RuleBuilderStepButton
                      stepNumber={3}
                      target="test"
                      title="Test"
                      description="Dry-run with representative learner facts before publishing."
                    />
                  </li>
                  <li>
                    <RuleBuilderStepButton
                      stepNumber={4}
                      target="review"
                      title="Review"
                      description="Set governance and create the draft that reviewers will see."
                    />
                  </li>
                </ol>
                <p
                  id="rule-builder-step-progress"
                  class="ct-admin__meta ct-admin__builder-progress"
                  aria-live="polite"
                >
                  Step 1 of 4 · Metadata
                </p>
              </section>

              <div class="ct-admin__builder-main ct-stack">
                <form id="rule-create-form" class="ct-admin__form ct-stack">
                  <section
                    id="builder-step-metadata"
                    class="ct-admin__builder-step"
                    data-rule-step="metadata"
                  >
                    <header class="ct-admin__step-head ct-stack">
                      <p class="ct-admin__step-kicker">Step 1</p>
                      <h3>Rule metadata</h3>
                      <p>
                        Set the permanent rule identity before you work on conditions or testing.
                      </p>
                    </header>
                    <div class="ct-admin__builder-grid ct-grid">
                      <label>
                        Rule name
                        <input
                          name="name"
                          type="text"
                          required
                          placeholder="CS101 Excellence Rule"
                        />
                      </label>
                      <label>
                        Description (optional)
                        <input
                          name="description"
                          type="text"
                          placeholder="Award when learner completes CS101 with strong performance."
                        />
                      </label>
                      <label>
                        Badge template
                        <select name="badgeTemplateId" required>
                          {templateOptions.length === 0 ? (
                            <option value="">No badge templates available</option>
                          ) : (
                            templateOptions.map(({ template, isSelected }) => (
                              <option key={template.id} value={template.id} selected={isSelected}>
                                {template.title} ({template.id})
                              </option>
                            ))
                          )}
                        </select>
                      </label>
                      <label>
                        LMS provider
                        <select name="lmsProviderKind" required>
                          <option value="canvas">Canvas</option>
                          <option value="sakai">Sakai</option>
                          <option value="moodle">Moodle</option>
                          <option value="blackboard_ultra">Blackboard Ultra</option>
                          <option value="d2l_brightspace">D2L Brightspace</option>
                        </select>
                      </label>
                    </div>
                  </section>

                  <section
                    id="builder-step-conditions"
                    class="ct-admin__builder-step"
                    data-rule-step="conditions"
                    hidden
                  >
                    <header class="ct-admin__step-head ct-stack">
                      <p class="ct-admin__step-kicker">Step 2</p>
                      <h3>Condition canvas</h3>
                      <p>
                        Compose the qualification logic on the canvas, then use JSON only for edge
                        cases and transport.
                      </p>
                    </header>
                    <div class="ct-admin__builder-workbench ct-stack">
                      <div class="ct-admin__builder-workbench-main ct-stack">
                        <div class="ct-admin__builder-toolbar ct-cluster">
                          <label class="ct-admin__inline-control">
                            Root logic
                            <select id="rule-builder-root-logic" name="rootLogic">
                              <option value="all" selected>
                                AND (all conditions must pass)
                              </option>
                              <option value="any">OR (any condition can pass)</option>
                            </select>
                          </label>
                          <AdminButton type="button" id="rule-builder-add-condition" size="tiny">
                            Add condition card
                          </AdminButton>
                        </div>
                        <section class="ct-admin__builder-canvas ct-stack">
                          <header class="ct-admin__builder-canvas-header ct-cluster">
                            <strong>Condition Canvas</strong>
                            <span class="ct-admin__meta">
                              Drag cards to reorder. Use Invert for NOT logic.
                            </span>
                          </header>
                          <div class="ct-admin__builder-canvas-meta ct-cluster">
                            <span id="rule-builder-canvas-count" class="ct-admin__status-pill">
                              0 cards
                            </span>
                            <span id="rule-builder-canvas-logic" class="ct-admin__status-pill">
                              AND logic
                            </span>
                          </div>
                          <p
                            id="rule-builder-condition-empty"
                            class="ct-admin__builder-canvas-empty"
                          >
                            No conditions yet. Apply a template or add your first condition card.
                          </p>
                          <div
                            id="rule-builder-condition-list"
                            class="ct-admin__builder-condition-list ct-stack"
                          ></div>
                        </section>
                      </div>

                      <details class="ct-admin__builder-guide">
                        <summary>Condition types</summary>
                        <div class="ct-admin__builder-patterns-head ct-stack">
                          <p class="ct-admin__hint">
                            Good builders keep the available rule types visible so authors do not
                            hunt through raw JSON.
                          </p>
                        </div>
                        <dl class="ct-admin__builder-guide-list">
                          <div>
                            <dt>Course completion</dt>
                            <dd>
                              Matches when course completion facts show learner completion and
                              optional minimum percent.
                            </dd>
                          </div>
                          <div>
                            <dt>Grade threshold</dt>
                            <dd>
                              Matches when a learner score is within configured min/max thresholds.
                            </dd>
                          </div>
                          <div>
                            <dt>Program completion</dt>
                            <dd>
                              Matches when enough required courses are completed for a program path.
                            </dd>
                          </div>
                          <div>
                            <dt>Assignment submission</dt>
                            <dd>
                              Matches when assignment submission, score, and workflow-state
                              constraints pass.
                            </dd>
                          </div>
                          <div>
                            <dt>Time window</dt>
                            <dd>Matches only inside optional not-before / not-after timestamps.</dd>
                          </div>
                          <div>
                            <dt>Prerequisite badge</dt>
                            <dd>
                              Matches when learner already has an earned prerequisite badge
                              template.
                            </dd>
                          </div>
                        </dl>
                      </details>
                    </div>

                    <details class="ct-admin__builder-advanced ct-stack">
                      <summary>Advanced JSON editor</summary>
                      <label>
                        Rule JSON (advanced)
                        <textarea
                          id="rule-builder-definition-json"
                          name="definitionJson"
                          rows={12}
                          spellcheck={false}
                        ></textarea>
                      </label>
                      <div class="ct-admin__builder-inline ct-cluster">
                        <AdminButton id="rule-builder-apply-json" type="button" size="tiny">
                          Apply JSON to builder
                        </AdminButton>
                      </div>
                    </details>
                  </section>

                  <section
                    id="builder-step-test"
                    class="ct-admin__builder-step"
                    data-rule-step="test"
                    hidden
                  >
                    <header class="ct-admin__step-head ct-stack">
                      <p class="ct-admin__step-kicker">Step 3</p>
                      <h3>Test against sample learner facts</h3>
                      <p>
                        Use one representative learner case, then layer advanced fact JSON only when
                        the simple path is insufficient.
                      </p>
                    </header>
                    <div class="ct-admin__builder-test-layout ct-grid">
                      <fieldset class="ct-admin__fieldset ct-stack">
                        <legend>Representative learner facts</legend>
                        <label>
                          Learner ID
                          <input name="testLearnerId" type="text" value="canvas:12345" />
                        </label>
                        <label>
                          Recipient email
                          <input
                            name="testRecipientIdentity"
                            type="email"
                            value="learner@example.edu"
                          />
                        </label>
                        <label>
                          Sample course ID
                          <input name="testCourseId" type="text" value="CS101" />
                        </label>
                        <label>
                          Sample final score
                          <input
                            name="testFinalScore"
                            type="number"
                            min={0}
                            max={100}
                            step="0.01"
                            value="92"
                          />
                        </label>
                        <label class="ct-admin__checkbox-row ct-checkbox-row">
                          <input name="testCompleted" type="checkbox" checked />
                          Learner completed course
                        </label>
                      </fieldset>

                      <div class="ct-admin__builder-test-rail ct-stack">
                        <fieldset class="ct-admin__fieldset ct-stack">
                          <legend>Test presets</legend>
                          <div class="ct-admin__builder-inline ct-cluster">
                            <label class="ct-admin__inline-control">
                              Test fact preset
                              <select id="rule-builder-test-preset" name="testPreset">
                                <option value="canvas_course_grade" selected>
                                  Canvas course + grade
                                </option>
                                <option value="program_completion">Program completion</option>
                                <option value="assignment_submission">Assignment submission</option>
                                <option value="prerequisite_badge">Prerequisite badge</option>
                              </select>
                            </label>
                            <AdminButton
                              id="rule-builder-apply-test-preset"
                              type="button"
                              size="tiny"
                              variant="secondary"
                            >
                              Apply preset
                            </AdminButton>
                          </div>
                          <AdminButton id="rule-builder-test" type="button" size="tiny">
                            Test rule
                          </AdminButton>
                        </fieldset>

                        <details class="ct-admin__builder-advanced ct-stack">
                          <summary>Advanced facts JSON</summary>
                          <label>
                            Advanced facts JSON (optional)
                            <textarea
                              name="testFactsJson"
                              rows={6}
                              spellcheck={false}
                              placeholder='{"grades":[{"courseId":"CS101","learnerId":"canvas:12345","finalScore":92}]}'
                            ></textarea>
                          </label>
                        </details>
                      </div>
                    </div>
                    <pre id="rule-builder-test-output" class="ct-admin__code-output" hidden></pre>
                  </section>

                  <section
                    id="builder-step-review"
                    class="ct-admin__builder-step"
                    data-rule-step="review"
                    hidden
                  >
                    <header class="ct-admin__step-head ct-stack">
                      <p class="ct-admin__step-kicker">Step 4</p>
                      <h3>Governance and release settings</h3>
                      <p>
                        Package the rule the way approvers expect to see it: timing, approval chain,
                        and one short change summary.
                      </p>
                    </header>
                    <div class="ct-admin__builder-review-layout ct-grid">
                      <div class="ct-stack">
                        <label>
                          Approval roles (comma separated)
                          <input name="approvalRoles" type="text" value="admin,owner" />
                        </label>
                        <label>
                          Issuance timing
                          <select name="issuanceTiming">
                            <option value="immediate">Immediate</option>
                            <option value="manual">Manual review trigger</option>
                            <option value="end_of_term">End of term batch</option>
                          </select>
                        </label>
                        <label>
                          Change summary (optional)
                          <input
                            name="changeSummary"
                            type="text"
                            placeholder="Initial draft for committee review."
                          />
                        </label>
                        <label class="ct-admin__checkbox-row ct-checkbox-row">
                          <input name="reviewOnMissingFacts" type="checkbox" />
                          Route missing-data cases to human review instead of treating them as a
                          simple no-match
                        </label>
                      </div>

                      <details id="rule-builder-review-surface" class="ct-admin__builder-guide">
                        <summary>Release checklist</summary>
                        <ul class="ct-admin__builder-checklist">
                          <li>Rule name, badge template, and LMS source are finalized.</li>
                          <li>Condition canvas reflects the JSON you intend to submit.</li>
                          <li>Latest dry run reflects representative learner facts.</li>
                          <li>Approval roles match the governance path reviewers expect.</li>
                        </ul>
                        <p class="ct-admin__hint">
                          Create the draft only when the last test summary and readiness rail are
                          both clean.
                        </p>
                      </details>
                    </div>

                    <details class="ct-admin__builder-simulation ct-stack">
                      <summary>Historical simulation</summary>
                      <header class="ct-admin__step-head ct-stack">
                        <h4>Project impact before activation</h4>
                        <p>
                          Replay this draft against recent rule evaluations for the same badge
                          template.
                        </p>
                      </header>
                      <div class="ct-admin__builder-inline ct-cluster">
                        <label class="ct-admin__inline-control">
                          Sample limit
                          <input
                            id="rule-builder-simulate-limit"
                            type="number"
                            min={1}
                            max={100}
                            step={1}
                            value="25"
                          />
                        </label>
                        <AdminButton
                          id="rule-builder-simulate"
                          type="button"
                          size="tiny"
                          variant="secondary"
                        >
                          Run simulation
                        </AdminButton>
                      </div>
                      <p id="rule-builder-simulate-status" class="ct-admin__status">
                        No historical simulation has been run yet.
                      </p>
                      <pre
                        id="rule-builder-simulate-output"
                        class="ct-admin__code-output"
                        hidden
                      ></pre>
                    </details>
                  </section>
                </form>
              </div>

              <section class="ct-admin__panel ct-admin__builder-rail ct-stack" aria-live="polite">
                <p class="ct-admin__eyebrow">Readiness</p>
                <h2>Draft summary</h2>
                <p class="ct-admin__hint">
                  Keep this rail clean before you submit the rule into governance review.
                </p>
                <dl class="ct-admin__builder-summary-list">
                  <div>
                    <dt>Rule name</dt>
                    <dd id="rule-builder-summary-rule-name" class="ct-admin__builder-summary-value">
                      -
                    </dd>
                  </div>
                  <div>
                    <dt>Condition cards</dt>
                    <dd
                      id="rule-builder-summary-condition-count"
                      class="ct-admin__builder-summary-value"
                    >
                      0
                    </dd>
                  </div>
                  <div>
                    <dt>Root logic</dt>
                    <dd
                      id="rule-builder-summary-root-logic"
                      class="ct-admin__builder-summary-value"
                    >
                      AND
                    </dd>
                  </div>
                  <div>
                    <dt>Definition</dt>
                    <dd id="rule-builder-summary-validity" class="ct-admin__builder-summary-value">
                      Drafting
                    </dd>
                  </div>
                  <div>
                    <dt>Last test</dt>
                    <dd id="rule-builder-summary-last-test" class="ct-admin__builder-summary-value">
                      Not run
                    </dd>
                  </div>
                </dl>
                <p id="rule-builder-summary-message" class="ct-admin__status">
                  Build at least one condition card to create a draft.
                </p>

                <details class="ct-admin__builder-rail-card ct-stack">
                  <summary>Submission path</summary>
                  <ul class="ct-admin__builder-checklist">
                    <li>Prepare the draft in the main workspace.</li>
                    <li>Run at least one dry run in test mode.</li>
                    <li>Set approval roles and issuance timing.</li>
                    <li>Create the rule draft for review.</li>
                  </ul>
                </details>

                <details class="ct-admin__builder-rail-card ct-stack">
                  <summary>Local draft storage</summary>
                  <p class="ct-admin__hint">
                    Saved drafts are stored in this browser and scoped to{" "}
                    <strong>{ruleBuilderPath}</strong>.
                  </p>
                </details>

                <div class="ct-admin__builder-step-nav ct-cluster">
                  <AdminButton
                    id="rule-builder-step-prev"
                    type="button"
                    size="tiny"
                    variant="secondary"
                  >
                    Previous step
                  </AdminButton>
                  <AdminButton
                    id="rule-builder-step-next"
                    type="button"
                    size="tiny"
                    variant="secondary"
                  >
                    Next step
                  </AdminButton>
                  <AdminButton id="rule-builder-submit" type="submit" form="rule-create-form">
                    Create rule draft
                  </AdminButton>
                </div>
                <p id="rule-create-status" class="ct-admin__status"></p>
              </section>

              <details class="ct-admin__panel ct-admin__builder-guide ct-admin__builder-support">
                <summary>Templates, imports, and help</summary>
                <div class="ct-admin__builder-support-grid ct-grid">
                  <section class="ct-admin__builder-support-section ct-stack">
                    <h3>Start from template or clone</h3>
                    <label>
                      Quick-start template
                      <div class="ct-admin__builder-inline ct-cluster">
                        <select id="rule-builder-template-preset" name="templatePreset">
                          <option value="course_completion">Course completion</option>
                          <option value="course_and_grade" selected>
                            Course + grade threshold
                          </option>
                          <option value="program_completion">Program completion</option>
                          <option value="time_limited">Time-limited achievement</option>
                          <option value="prerequisite_chain">Prerequisite badge chain</option>
                          <option value="blank">Blank</option>
                        </select>
                        <AdminButton id="rule-builder-apply-template" type="button" size="tiny">
                          Apply
                        </AdminButton>
                      </div>
                    </label>
                    <label>
                      Clone existing rule (optional)
                      <div class="ct-admin__builder-inline ct-cluster">
                        <select id="rule-builder-clone-rule" name="cloneRuleId">
                          {ruleCloneOptions.length === 0 ? (
                            <option value="">No rules available</option>
                          ) : (
                            <>
                              <option value="">Select rule to clone</option>
                              {ruleCloneOptions.map((option) => (
                                <option key={option.rule.id} value={option.rule.id}>
                                  {option.label}
                                </option>
                              ))}
                            </>
                          )}
                        </select>
                        <AdminButton
                          id="rule-builder-clone-load"
                          type="button"
                          size="tiny"
                          variant="secondary"
                        >
                          Load rule
                        </AdminButton>
                      </div>
                    </label>
                  </section>

                  <section class="ct-admin__builder-support-section ct-stack">
                    <h3>Draft tools</h3>
                    <div class="ct-admin__builder-toolbar ct-cluster">
                      <AdminButton type="button" id="rule-builder-save-draft" size="tiny">
                        Save local draft
                      </AdminButton>
                      <AdminButton
                        type="button"
                        id="rule-builder-load-draft"
                        size="tiny"
                        variant="secondary"
                      >
                        Load local draft
                      </AdminButton>
                      <AdminButton
                        type="button"
                        id="rule-builder-export-json"
                        size="tiny"
                        variant="secondary"
                      >
                        Export JSON
                      </AdminButton>
                      <AdminButton
                        type="button"
                        id="rule-builder-import-json"
                        size="tiny"
                        variant="secondary"
                      >
                        Import JSON
                      </AdminButton>
                      <input
                        id="rule-builder-import-file"
                        type="file"
                        accept="application/json"
                        hidden
                      />
                    </div>
                    <p class="ct-admin__hint">
                      Local drafts stay in this browser. Use export/import when you want a portable
                      review artifact.
                    </p>
                  </section>

                  <section class="ct-admin__builder-support-section ct-stack">
                    <h3>Reusable lists</h3>
                    <p class="ct-admin__hint">
                      Course and badge-template lists appear here and can be used inside condition
                      cards.
                    </p>
                    <div class="ct-admin__table-wrap">
                      <table class="ct-admin__table">
                        <thead>
                          <tr>
                            <th>Label</th>
                            <th>Kind</th>
                            <th>Values</th>
                          </tr>
                        </thead>
                        <tbody id="rule-builder-value-list-body">
                          <tr>
                            <td colspan={3} class="ct-admin__empty">
                              No reusable lists loaded yet.
                            </td>
                          </tr>
                        </tbody>
                      </table>
                    </div>
                  </section>

                  <section
                    id="rule-builder-panel"
                    class="ct-admin__builder-support-section ct-admin__builder-support-section--wide ct-stack"
                  >
                    <h3>Authoring approach</h3>
                    <div class="ct-admin__builder-intro-grid ct-grid">
                      <section class="ct-admin__builder-intro-card ct-stack">
                        <h4>Define scope first</h4>
                        <p>
                          Lock the badge template, LMS source, and rule identity before touching
                          logic.
                        </p>
                      </section>
                      <section class="ct-admin__builder-intro-card ct-stack">
                        <h4>Model the rule visibly</h4>
                        <p>
                          Condition cards stay front and center. JSON only appears when you need to
                          import or inspect.
                        </p>
                      </section>
                      <section class="ct-admin__builder-intro-card ct-stack">
                        <h4>Test before governance</h4>
                        <p>
                          Dry-run against representative facts so approvers receive cleaner, more
                          trustworthy drafts.
                        </p>
                      </section>
                    </div>
                  </section>
                </div>
              </details>
            </section>

            <div id="ct-admin-context" hidden data-context-json={adminPageContextJson}></div>
          </div>
        </div>
      </div>
    ),
  });
};
