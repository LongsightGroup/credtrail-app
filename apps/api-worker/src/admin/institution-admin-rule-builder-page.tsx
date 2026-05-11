import type {
  BadgeIssuanceRuleRecord,
  BadgeIssuanceRuleVersionRecord,
  BadgeTemplateRecord,
  TenantMembershipRole,
  TenantRecord,
} from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import { appPage, type AppPage } from "../ui/render-page";
import {
  AdminButton,
  AdminCheckboxRow,
  AdminEmptyTableRow,
  AdminField,
  AdminFieldset,
  AdminForm,
  AdminShell,
  AdminSidebar,
  AdminStatus,
  AdminTable,
  AdminTopbar,
  type AdminSidebarFooterLink,
  type AdminSidebarSection,
} from "./components";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

const serializeJsonScriptContent = (value: unknown): string => {
  return JSON.stringify(value)
    .replaceAll("<", "\\u003c")
    .replaceAll(">", "\\u003e")
    .replaceAll("&", "\\u0026")
    .replaceAll("\u2028", "\\u2028")
    .replaceAll("\u2029", "\\u2029");
};

type RuleBuilderStepTarget = "metadata" | "conditions" | "test";

const ruleBuilderConditionTypes = [
  { value: "course_completion", label: "Course completion" },
  { value: "grade_threshold", label: "Grade threshold" },
  { value: "program_completion", label: "Program completion" },
  { value: "assignment_submission", label: "Assignment submission" },
  { value: "time_window", label: "Time window" },
  { value: "prerequisite_badge", label: "Prerequisite badge" },
] as const;

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

const RuleBuilderConditionCardTemplate = (): HonoElement => {
  return (
    <template id="rule-builder-condition-card-template">
      <article class="ct-admin__condition-card ct-stack" draggable={true}>
        <header class="ct-admin__condition-header ct-stack">
          <div class="ct-admin__condition-header-row ct-cluster">
            <span class="ct-admin__condition-index" data-condition-index="">
              Requirement
            </span>
            <span class="ct-admin__condition-drag" title="Drag to reorder" aria-hidden="true">
              Move
            </span>
            <div class="ct-admin__condition-actions ct-cluster">
              <AdminButton
                type="button"
                size="tiny"
                variant="ghost"
                ariaLabel="Move requirement up"
                dataAttributes={{ "data-condition-move": "up" }}
              >
                Up
              </AdminButton>
              <AdminButton
                type="button"
                size="tiny"
                variant="ghost"
                ariaLabel="Move requirement down"
                dataAttributes={{ "data-condition-move": "down" }}
              >
                Down
              </AdminButton>
              <AdminButton
                type="button"
                size="tiny"
                variant="danger"
                className="ct-admin__condition-remove"
              >
                Remove
              </AdminButton>
            </div>
          </div>
          <div class="ct-admin__condition-header-fields ct-admin__builder-grid ct-grid">
            <AdminField label="Requirement">
              <select class="ct-admin__condition-type">
                {ruleBuilderConditionTypes.map((conditionType) => (
                  <option value={conditionType.value}>{conditionType.label}</option>
                ))}
              </select>
            </AdminField>
            <details class="ct-admin__condition-advanced">
              <summary>Advanced</summary>
              <AdminCheckboxRow>
                <input type="checkbox" data-field="negate" />
                Exclude learners who match this requirement
              </AdminCheckboxRow>
            </details>
          </div>
        </header>
        <p class="ct-admin__condition-help"></p>
        <div class="ct-admin__condition-fields ct-admin__builder-grid ct-grid"></div>
        <p class="ct-admin__condition-result" data-state="idle" aria-live="polite">
          Not evaluated yet.
        </p>
      </article>
    </template>
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
  const tenantMembersApiPath = `/v1/tenants/${encodeURIComponent(input.tenant.id)}/members`;
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
    tenantMembersApiPath,
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
  const reportingExplorePath = `${reportingPath}/explore`;
  const reportingTrendsPath = `${reportingPath}/trends`;
  const reportingReportsPath = `${reportingPath}/reports`;
  const accessPath = `${tenantAdminPath}/access`;
  const accessMembersPath = `${accessPath}/members`;
  const accessGovernancePath = `${accessPath}/governance`;
  const accessApiKeysPath = `${accessPath}/api-keys`;
  const accessOrgUnitsPath = `${accessPath}/org-units`;
  const sidebarSections: readonly AdminSidebarSection[] = [
    {
      links: [{ href: tenantAdminPath, label: "Home" }],
    },
    {
      label: "Operations",
      links: [
        { href: operationsPath, label: "Overview" },
        { href: operationsLearnerRecordsPath, label: "Learner Records", isSub: true },
        {
          href: operationsLearnerRecordImportsPath,
          label: "Learner Record Imports",
          isSub: true,
        },
        { href: operationsReviewQueuePath, label: "Review Queue", isSub: true },
        { href: operationsIssuedBadgesPath, label: "Issued Badges", isSub: true },
        { href: operationsBadgeStatusPath, label: "Badge Status", isSub: true },
      ],
    },
    {
      label: "Reporting",
      links: [
        { href: reportingPath, label: "Highlights" },
        { href: reportingExplorePath, label: "Explore", isSub: true },
        { href: reportingTrendsPath, label: "Trends", isSub: true },
        { href: reportingReportsPath, label: "Reports", isSub: true },
      ],
    },
    {
      label: "Configuration",
      links: [
        { href: rulesWorkspacePath, label: "Rules" },
        { href: ruleBuilderPath, label: "Rule Builder", isCurrent: true, isSub: true },
      ],
    },
    {
      label: "Access",
      links: [
        { href: accessPath, label: "Overview" },
        { href: accessMembersPath, label: "Members", isSub: true },
        { href: accessGovernancePath, label: "Governance", isSub: true },
        { href: accessApiKeysPath, label: "API Keys", isSub: true },
        { href: accessOrgUnitsPath, label: "Org Units", isSub: true },
      ],
    },
  ];
  const sidebarFooterLinks: readonly AdminSidebarFooterLink[] = [
    { href: adminAuditLogPath, label: "Audit logs", isExternal: true },
    {
      href: showcasePath,
      label: "Public showcase",
      isExternal: true,
      target: "_blank",
      rel: "noopener noreferrer",
    },
    ...(switchOrganizationPath.length === 0
      ? []
      : [{ href: switchOrganizationPath, label: "Switch organization" }]),
  ];

  return appPage({
    title: `Rule Builder · ${input.tenant.displayName}`,
    assets: ["institutionAdminCss", "institutionAdminJs"],
    variant: "admin",
    body: (
      <AdminShell
        sidebar={
          <AdminSidebar
            brandHref={tenantAdminPath}
            sections={sidebarSections}
            footerLinks={sidebarFooterLinks}
          />
        }
        topbar={
          <AdminTopbar
            title={input.tenant.displayName}
            chips={[{ label: input.membershipRole }]}
            userLabel={userLabel}
            userTitle={`User ID: ${input.userId}`}
          />
        }
        contentClassName="ct-admin-content ct-admin-content--rule-builder"
      >
        <div class="ct-admin-page-header ct-admin-page-header--compact">
          <h1>Badge Awarding Rule</h1>
          <p>
            Choose an awarding pattern, define requirements, test with a learner, then create a
            draft for review.
          </p>
          <details class="ct-admin__builder-guide">
            <summary>How awarding rules work</summary>
            <p>
              CredTrail keeps the rule engine complete, but most authors should start from a guided
              pattern and only open expert controls for exceptions.
            </p>
          </details>
        </div>

        <section class="ct-admin__builder-shell ct-stack">
          <section
            class="ct-admin__panel ct-admin__builder-stepper-panel ct-stack"
            aria-label="Rule builder workflow"
          >
            <p class="ct-admin__eyebrow">Workflow</p>
            <h2>Build in three passes</h2>
            <ol
              id="rule-builder-stepper"
              class="ct-admin__builder-steps"
              aria-label="Rule builder steps"
            >
              <li>
                <RuleBuilderStepButton
                  stepNumber={1}
                  target="metadata"
                  title="Awarding pattern"
                  description="Pick the badge, LMS, and starting pattern."
                />
              </li>
              <li>
                <RuleBuilderStepButton
                  stepNumber={2}
                  target="conditions"
                  title="Requirements"
                  description="List the learner requirements for this badge."
                />
              </li>
              <li>
                <RuleBuilderStepButton
                  stepNumber={3}
                  target="test"
                  title="Test & submit"
                  description="Dry-run with a learner, then prepare the draft."
                />
              </li>
            </ol>
            <p
              id="rule-builder-step-progress"
              class="ct-admin__meta ct-admin__builder-progress"
              aria-live="polite"
            >
              Step 1 of 3 · Awarding pattern
            </p>
          </section>

          <div class="ct-admin__builder-main ct-stack">
            <AdminForm id="rule-create-form">
              <section
                id="builder-step-metadata"
                class="ct-admin__builder-step"
                data-rule-step="metadata"
              >
                <header class="ct-admin__step-head ct-stack">
                  <p class="ct-admin__step-kicker">Step 1</p>
                  <h3>Awarding pattern</h3>
                  <p>
                    Start with the common way a learner earns this badge. Advanced logic stays
                    available after the pattern is in place.
                  </p>
                </header>
                <section class="ct-admin__pattern-panel ct-stack">
                  <div class="ct-stack">
                    <h4>Start from a proven pattern</h4>
                    <p>
                      Patterns create the first set of requirements. You can edit every generated
                      row before testing.
                    </p>
                  </div>
                  <div class="ct-admin__builder-inline ct-cluster">
                    <AdminField label="Awarding pattern" className="ct-admin__inline-control">
                      <select id="rule-builder-template-preset" name="templatePreset">
                        <option value="course_completion">Course completed</option>
                        <option value="course_and_grade" selected>
                          Course completed + minimum score
                        </option>
                        <option value="program_completion">Program or pathway completed</option>
                        <option value="assignment_submission">
                          Assignment or evidence submitted
                        </option>
                        <option value="prerequisite_chain">Prerequisite badge required</option>
                        <option value="time_limited">Date-limited earning window</option>
                        <option value="blank">Blank requirements</option>
                      </select>
                    </AdminField>
                    <AdminButton id="rule-builder-apply-template" type="button" size="tiny">
                      Use pattern
                    </AdminButton>
                  </div>
                </section>
                <div class="ct-admin__builder-grid ct-grid">
                  <AdminField label="Internal rule name">
                    <input
                      name="name"
                      type="text"
                      required
                      placeholder="CS101 completion with distinction"
                    />
                  </AdminField>
                  <AdminField label="Description (optional)">
                    <input
                      name="description"
                      type="text"
                      placeholder="Award when learner completes CS101 with strong performance."
                    />
                  </AdminField>
                  <AdminField label="Badge template">
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
                  </AdminField>
                  <AdminField label="LMS provider">
                    <select name="lmsProviderKind" required>
                      <option value="canvas">Canvas</option>
                      <option value="sakai">Sakai</option>
                      <option value="moodle">Moodle</option>
                      <option value="blackboard_ultra">Blackboard Ultra</option>
                      <option value="d2l_brightspace">D2L Brightspace</option>
                    </select>
                  </AdminField>
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
                  <h3>Awarding requirements</h3>
                  <p>Keep the default rule as a simple list: every requirement below must pass.</p>
                </header>
                <div class="ct-admin__builder-workbench ct-stack">
                  <div class="ct-admin__builder-workbench-main ct-stack">
                    <section class="ct-admin__builder-principle ct-stack">
                      <strong>Default earning path</strong>
                      <p>
                        The learner earns the badge when all listed requirements are met. Add
                        alternatives only for true exception paths.
                      </p>
                    </section>
                    <div class="ct-admin__builder-toolbar ct-cluster">
                      <AdminButton type="button" id="rule-builder-add-condition" size="tiny">
                        Add requirement
                      </AdminButton>
                      <details class="ct-admin__builder-advanced ct-admin__builder-advanced--inline">
                        <summary>Advanced logic</summary>
                        <div class="ct-admin__builder-inline ct-cluster">
                          <AdminField label="Earning path" className="ct-admin__inline-control">
                            <select id="rule-builder-root-logic" name="rootLogic">
                              <option value="all" selected>
                                All requirements must pass
                              </option>
                              <option value="any">Any requirement can pass</option>
                            </select>
                          </AdminField>
                          <AdminButton
                            type="button"
                            id="rule-builder-add-alternative-path"
                            size="tiny"
                            variant="secondary"
                          >
                            Add alternative way
                          </AdminButton>
                        </div>
                      </details>
                    </div>
                    <section class="ct-admin__builder-canvas ct-stack">
                      <header class="ct-admin__builder-canvas-header ct-cluster">
                        <strong>Requirements</strong>
                        <span class="ct-admin__meta">
                          Each row describes one fact CredTrail checks.
                        </span>
                      </header>
                      <div class="ct-admin__builder-canvas-meta ct-cluster">
                        <span id="rule-builder-canvas-count" class="ct-admin__status-pill">
                          0 requirements
                        </span>
                        <span id="rule-builder-canvas-logic" class="ct-admin__status-pill">
                          All requirements
                        </span>
                      </div>
                      <p id="rule-builder-condition-empty" class="ct-admin__builder-canvas-empty">
                        No requirements yet. Choose a pattern or add one requirement.
                      </p>
                      <div
                        id="rule-builder-condition-list"
                        class="ct-admin__builder-condition-list ct-stack"
                      ></div>
                    </section>
                  </div>

                  <details class="ct-admin__builder-guide">
                    <summary>Requirement catalog</summary>
                    <div class="ct-admin__builder-patterns-head ct-stack">
                      <p class="ct-admin__hint">
                        These are the requirement rows available in the visual builder.
                      </p>
                    </div>
                    <dl class="ct-admin__builder-guide-list">
                      <div>
                        <dt>Course completion</dt>
                        <dd>
                          Matches when course completion facts show learner completion and optional
                          minimum percent.
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
                          Matches when assignment submission, score, and workflow-state constraints
                          pass.
                        </dd>
                      </div>
                      <div>
                        <dt>Time window</dt>
                        <dd>Matches only inside optional not-before / not-after timestamps.</dd>
                      </div>
                      <div>
                        <dt>Prerequisite badge</dt>
                        <dd>
                          Matches when learner already has an earned prerequisite badge template.
                        </dd>
                      </div>
                    </dl>
                  </details>
                </div>

                <details class="ct-admin__builder-advanced ct-stack">
                  <summary>Generated rule JSON</summary>
                  <AdminField label="Rule JSON (expert override)">
                    <textarea
                      id="rule-builder-definition-json"
                      name="definitionJson"
                      rows={12}
                      spellcheck={false}
                    ></textarea>
                  </AdminField>
                  <div class="ct-admin__builder-inline ct-cluster">
                    <AdminButton id="rule-builder-apply-json" type="button" size="tiny">
                      Apply JSON
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
                  <h3>Test and submit</h3>
                  <p>Run a learner case before sending the draft to governance.</p>
                </header>
                <div class="ct-admin__builder-test-layout ct-grid">
                  <AdminFieldset legend="Test with learner">
                    <AdminField label="Learner ID">
                      <input name="testLearnerId" type="text" value="canvas:12345" />
                    </AdminField>
                    <AdminField label="Recipient email">
                      <input
                        name="testRecipientIdentity"
                        type="email"
                        value="learner@example.edu"
                      />
                    </AdminField>
                    <AdminField label="Sample course ID">
                      <input name="testCourseId" type="text" value="CS101" />
                    </AdminField>
                    <AdminField label="Sample final score">
                      <input
                        name="testFinalScore"
                        type="number"
                        min={0}
                        max={100}
                        step="0.01"
                        value="92"
                      />
                    </AdminField>
                    <AdminCheckboxRow>
                      <input name="testCompleted" type="checkbox" checked />
                      Learner completed course
                    </AdminCheckboxRow>
                  </AdminFieldset>

                  <div class="ct-admin__builder-test-rail ct-stack">
                    <AdminFieldset legend="Sample case">
                      <div class="ct-admin__builder-inline ct-cluster">
                        <AdminField label="Fact preset" className="ct-admin__inline-control">
                          <select id="rule-builder-test-preset" name="testPreset">
                            <option value="canvas_course_grade" selected>
                              Canvas course + grade
                            </option>
                            <option value="program_completion">Program completion</option>
                            <option value="assignment_submission">Assignment submission</option>
                            <option value="prerequisite_badge">Prerequisite badge</option>
                          </select>
                        </AdminField>
                        <AdminButton
                          id="rule-builder-apply-test-preset"
                          type="button"
                          size="tiny"
                          variant="secondary"
                        >
                          Apply preset
                        </AdminButton>
                      </div>
                      <div class="ct-admin__builder-test-actions">
                        <AdminButton id="rule-builder-test" type="button" size="tiny">
                          Test with learner
                        </AdminButton>
                      </div>
                    </AdminFieldset>

                    <details class="ct-admin__builder-advanced ct-stack">
                      <summary>Advanced facts JSON</summary>
                      <AdminField label="Advanced facts JSON (optional)">
                        <textarea
                          name="testFactsJson"
                          rows={6}
                          spellcheck={false}
                          placeholder='{"grades":[{"courseId":"CS101","learnerId":"canvas:12345","finalScore":92}]}'
                        ></textarea>
                      </AdminField>
                    </details>
                  </div>
                </div>
                <pre id="rule-builder-test-output" class="ct-admin__code-output" hidden></pre>

                <section class="ct-admin__builder-governance ct-stack">
                  <header class="ct-admin__step-head ct-stack">
                    <h4>Governance and release settings</h4>
                    <p>
                      Package the rule the way approvers expect to see it: timing, approval chain,
                      and one short change summary.
                    </p>
                  </header>
                  <div class="ct-admin__builder-review-layout ct-grid">
                    <div class="ct-stack">
                      <AdminField label="Approval roles (comma separated)">
                        <input name="approvalRoles" type="text" value="admin,owner" />
                      </AdminField>
                      <AdminField label="Issuance timing">
                        <select name="issuanceTiming">
                          <option value="immediate">Immediate</option>
                          <option value="manual">Manual review trigger</option>
                          <option value="end_of_term">End of term batch</option>
                        </select>
                      </AdminField>
                      <AdminField label="Change summary (optional)">
                        <input
                          name="changeSummary"
                          type="text"
                          placeholder="Initial draft for committee review."
                        />
                      </AdminField>
                      <AdminCheckboxRow>
                        <input name="reviewOnMissingFacts" type="checkbox" />
                        Send missing-data cases to human review
                      </AdminCheckboxRow>
                    </div>

                    <details id="rule-builder-review-surface" class="ct-admin__builder-guide">
                      <summary>Release checklist</summary>
                      <ul class="ct-admin__builder-checklist">
                        <li>Rule name, badge template, and LMS source are finalized.</li>
                        <li>Requirements match the earning policy reviewers expect.</li>
                        <li>Latest test reflects a representative learner case.</li>
                        <li>Approval roles match the governance path.</li>
                      </ul>
                      <p class="ct-admin__hint">
                        Create the draft only when the latest test and readiness rail are both
                        clean.
                      </p>
                    </details>
                  </div>
                </section>

                <details class="ct-admin__builder-simulation ct-stack">
                  <summary>Historical simulation</summary>
                  <header class="ct-admin__step-head ct-stack">
                    <h4>Project impact before activation</h4>
                    <p>
                      Replay this draft against recent rule evaluations for the same badge template.
                    </p>
                  </header>
                  <div class="ct-admin__builder-inline ct-cluster">
                    <AdminField label="Sample limit" className="ct-admin__inline-control">
                      <input
                        id="rule-builder-simulate-limit"
                        type="number"
                        min={1}
                        max={100}
                        step={1}
                        value="25"
                      />
                    </AdminField>
                    <AdminButton
                      id="rule-builder-simulate"
                      type="button"
                      size="tiny"
                      variant="secondary"
                    >
                      Run simulation
                    </AdminButton>
                  </div>
                  <AdminStatus id="rule-builder-simulate-status">
                    No historical simulation has been run yet.
                  </AdminStatus>
                  <pre id="rule-builder-simulate-output" class="ct-admin__code-output" hidden></pre>
                </details>
              </section>
            </AdminForm>
          </div>

          <section class="ct-admin__panel ct-admin__builder-rail ct-stack" aria-live="polite">
            <p class="ct-admin__eyebrow">Readiness</p>
            <h2>Draft readiness</h2>
            <p class="ct-admin__hint">
              Use this rail to see whether the draft is ready for governance review.
            </p>
            <dl class="ct-admin__builder-summary-list">
              <div>
                <dt>Name</dt>
                <dd id="rule-builder-summary-rule-name" class="ct-admin__builder-summary-value">
                  -
                </dd>
              </div>
              <div>
                <dt>Requirements</dt>
                <dd
                  id="rule-builder-summary-condition-count"
                  class="ct-admin__builder-summary-value"
                >
                  0
                </dd>
              </div>
              <div>
                <dt>Earning path</dt>
                <dd id="rule-builder-summary-root-logic" class="ct-admin__builder-summary-value">
                  All requirements
                </dd>
              </div>
              <div>
                <dt>Rule definition</dt>
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
            <AdminStatus id="rule-builder-summary-message">
              Add at least one requirement to create a draft.
            </AdminStatus>

            <details class="ct-admin__builder-rail-card ct-stack">
              <summary>Submission path</summary>
              <ul class="ct-admin__builder-checklist">
                <li>Choose an awarding pattern and badge template.</li>
                <li>Confirm the requirements match the earning policy.</li>
                <li>Run at least one learner test.</li>
                <li>Set approval roles and issuance timing.</li>
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
            <AdminStatus id="rule-create-status"></AdminStatus>
          </section>

          <details class="ct-admin__panel ct-admin__builder-guide ct-admin__builder-support">
            <summary>Advanced tools and reusable lists</summary>
            <div class="ct-admin__builder-support-grid ct-grid">
              <section class="ct-admin__builder-support-section ct-stack">
                <h3>Start from existing rule</h3>
                <AdminField label="Clone existing rule (optional)">
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
                </AdminField>
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
                  Course and badge-template lists appear here and can be used inside requirement
                  rows.
                </p>
                <AdminTable
                  headers={["Label", "Kind", "Values"]}
                  tbodyId="rule-builder-value-list-body"
                >
                  <AdminEmptyTableRow colSpan={3}>No reusable lists loaded yet.</AdminEmptyTableRow>
                </AdminTable>
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
                      Choose the badge template, LMS source, and awarding pattern before editing
                      requirements.
                    </p>
                  </section>
                  <section class="ct-admin__builder-intro-card ct-stack">
                    <h4>Keep requirements visible</h4>
                    <p>
                      Requirement rows stay front and center. JSON only appears when you need to
                      import, export, or inspect.
                    </p>
                  </section>
                  <section class="ct-admin__builder-intro-card ct-stack">
                    <h4>Test before governance</h4>
                    <p>
                      Test against representative learner facts so approvers receive cleaner, more
                      trustworthy drafts.
                    </p>
                  </section>
                </div>
              </section>
            </div>
          </details>
        </section>

        <RuleBuilderConditionCardTemplate />
        <div id="ct-admin-context" hidden data-context-json={adminPageContextJson}></div>
      </AdminShell>
    ),
  });
};
