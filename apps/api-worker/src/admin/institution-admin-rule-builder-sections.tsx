import type {
  BadgeIssuanceRuleRecord,
  BadgeIssuanceRuleVersionRecord,
  BadgeTemplateRecord,
  TenantLmsConnectionRecord,
} from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import { badgeRuleLmsProviderLabel } from "../badges/badge-rule-lms-provider-label";
import {
  AdminActions,
  AdminButton,
  AdminCheckboxRow,
  AdminField,
  AdminFieldset,
  AdminStatus,
} from "./components";
import { CtCheckboxField, CtInput, CtSelect, CtTextarea } from "../ui/forms";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString> | null;
type RuleBuilderStepTarget = "metadata" | "conditions" | "test";

interface RuleBuilderTemplateOption {
  readonly template: BadgeTemplateRecord;
  readonly isSelected: boolean;
  readonly ruleUsageNames: readonly string[];
}

const ruleBuilderConditionTypes = [
  { value: "course_completion", label: "Course completion" },
  { value: "grade_threshold", label: "Grade threshold" },
  { value: "program_completion", label: "Course pathway completion" },
  { value: "assignment_submission", label: "Gradebook item submitted" },
  { value: "survey_completion", label: "Survey completion" },
  { value: "time_window", label: "Time window" },
  { value: "prerequisite_badge", label: "Prerequisite badge" },
  { value: "custom_field", label: "Custom field" },
] as const;

const RuleBuilderStepButton = (props: {
  readonly stepNumber: number;
  readonly target: RuleBuilderStepTarget;
  readonly title: string;
  readonly description: string;
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

export const RuleBuilderConditionCardTemplate = (): HonoElement => {
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
            <AdminActions className="ct-admin__condition-actions">
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
            </AdminActions>
          </div>
          <p class="ct-admin__condition-summary">Requirement details will appear here.</p>
        </header>
        <details class="ct-admin__condition-details" open>
          <summary>Edit requirement details</summary>
          <div class="ct-admin__condition-header-fields ct-admin__builder-grid ct-grid">
            <AdminField label="Requirement type">
              <CtSelect className="ct-admin__condition-type">
                {ruleBuilderConditionTypes.map((conditionType) => (
                  <option value={conditionType.value}>{conditionType.label}</option>
                ))}
              </CtSelect>
            </AdminField>
            <AdminCheckboxRow
              name="negate"
              label="Exclude learners who match this requirement"
              dataAttributes={{ "data-field": "negate" }}
            />
          </div>
          <div class="ct-admin__condition-fields ct-admin__builder-grid ct-grid"></div>
        </details>
        <p class="ct-admin__condition-result" data-state="idle" aria-live="polite">
          Not evaluated yet.
        </p>
      </article>
    </template>
  );
};

export const RuleBuilderCloneSettings = (props: {
  readonly ruleCloneOptions: readonly {
    readonly rule: BadgeIssuanceRuleRecord;
    readonly label: string;
  }[];
}): HonoElement => {
  if (props.ruleCloneOptions.length === 0) {
    return null;
  }

  return (
    <details class="ct-admin__builder-clone ct-stack">
      <summary>Copy existing rule settings</summary>
      <p class="ct-admin__hint">
        Preload settings from a rule you already use, then review the badge, source, and
        requirements before submitting.
      </p>
      <AdminActions className="ct-admin__builder-inline">
        <CtSelect
          id="rule-builder-clone-rule"
          name="cloneRuleId"
          ariaLabel="Rule to copy settings from"
        >
          <option value="">Select rule to copy</option>
          {props.ruleCloneOptions.map((option) => (
            <option key={option.rule.id} value={option.rule.id}>
              {option.label}
            </option>
          ))}
        </CtSelect>
        <AdminButton id="rule-builder-clone-load" type="button" size="tiny" variant="secondary">
          Copy settings
        </AdminButton>
      </AdminActions>
    </details>
  );
};

// An editable ARIA combobox requires a listbox popup rather than another select.
/* oxlint-disable jsx-a11y/prefer-tag-over-role */
export const RuleBuilderMetadataStep = (props: {
  readonly isEditMode: boolean;
  readonly templateOptions: readonly RuleBuilderTemplateOption[];
  readonly artworkActionTemplateCount: number;
  readonly connectedLmsConnections: readonly TenantLmsConnectionRecord[];
  readonly defaultLmsConnectionId: string;
  readonly defaultLmsConnection: TenantLmsConnectionRecord | null;
  readonly hasUnusableLmsConnections: boolean;
  readonly createTemplateForRulePath: string;
  readonly accessLmsConnectionsPath: string;
  readonly editRule: {
    readonly latestVersion: BadgeIssuanceRuleVersionRecord;
  } | null;
}): HonoElement => {
  const hasSelectedTemplate = props.templateOptions.some((option) => option.isSelected);
  const savedTemplateUnavailable =
    props.isEditMode &&
    !props.templateOptions.some(
      ({ template }) => template.id === props.editRule?.latestVersion.snapshot.badgeTemplateId,
    );

  return (
    <li class="ct-admin__stepper-step" data-rule-step-row="metadata">
      <div class="ct-admin__stepper-header">
        <RuleBuilderStepButton
          stepNumber={1}
          target="metadata"
          title="Awarding pattern"
          description="Choose the badge and how learners qualify."
        />
      </div>
      <div class="ct-admin__stepper-content">
        <section
          id="builder-step-metadata"
          class="ct-admin__builder-step"
          data-rule-step="metadata"
        >
          <section class="ct-admin__step-panel ct-admin__pattern-panel ct-stack">
            <h3 tabindex={-1}>Set up this rule</h3>
            <p class="ct-admin__step-panel-lead">
              Choose the badge, LMS connection, and how learners earn it.
            </p>
            <div class="ct-admin__builder-grid ct-grid">
              <div class="ct-admin__template-picker ct-stack">
                <div id="rule-builder-badge-template-fallback-field">
                  <AdminField label="Badge template">
                    <CtSelect
                      id="rule-builder-badge-template-select"
                      name="badgeTemplateId"
                      required
                      disabled={props.templateOptions.length === 0}
                      describedBy={[
                        "rule-builder-badge-template-search-status",
                        "rule-builder-badge-template-reuse-message",
                      ]}
                    >
                      {savedTemplateUnavailable ? (
                        <option value="" selected disabled>
                          Saved badge template is unavailable. Choose another.
                        </option>
                      ) : props.templateOptions.length === 0 ? (
                        <option value="" selected>
                          No badge templates are ready for rules
                        </option>
                      ) : (
                        <option value="" selected={!hasSelectedTemplate} disabled>
                          Choose a badge template
                        </option>
                      )}
                      {props.templateOptions.map(({ template, isSelected, ruleUsageNames }) => (
                        <option
                          key={template.id}
                          value={template.id}
                          selected={isSelected}
                          data-template-title={template.title}
                          data-rule-usage-count={ruleUsageNames.length}
                          data-rule-usage-names={ruleUsageNames.join(" · ")}
                        >
                          {template.title}
                          {ruleUsageNames.length === 0
                            ? ""
                            : `, used by ${String(ruleUsageNames.length)} other ${
                                ruleUsageNames.length === 1 ? "rule" : "rules"
                              }`}
                        </option>
                      ))}
                    </CtSelect>
                  </AdminField>
                </div>
                <div
                  id="rule-builder-badge-template-enhanced-field"
                  class="ct-field ct-admin__field"
                  hidden
                >
                  <label class="ct-field__label" htmlFor="rule-builder-badge-template-combobox">
                    Badge template
                  </label>
                  <div class="ct-admin__template-combobox">
                    <input
                      id="rule-builder-badge-template-combobox"
                      class="ct-input ct-field__control"
                      type="search"
                      placeholder="Search badge templates"
                      autocomplete="off"
                      role="combobox"
                      aria-autocomplete="list"
                      aria-controls="rule-builder-badge-template-listbox"
                      aria-expanded="false"
                      aria-describedby="rule-builder-badge-template-search-status rule-builder-badge-template-reuse-message"
                    />
                    <div
                      id="rule-builder-badge-template-listbox"
                      class="ct-admin__template-listbox"
                      role="listbox"
                      aria-label="Badge templates"
                      hidden
                    ></div>
                  </div>
                </div>
                <p
                  id="rule-builder-badge-template-search-status"
                  class="ct-admin__hint"
                  aria-live="polite"
                >
                  {props.templateOptions.length === 0
                    ? props.artworkActionTemplateCount > 0
                      ? "No badge templates with managed artwork are ready for rules."
                      : "Create a badge template before building a rule."
                    : `${String(props.templateOptions.length)} badge ${
                        props.templateOptions.length === 1 ? "template" : "templates"
                      } ready for rules, A to Z.`}
                </p>
                <div
                  id="rule-builder-badge-template-reuse"
                  class="ct-admin__template-reuse ct-stack"
                  hidden
                >
                  <p id="rule-builder-badge-template-reuse-message"></p>
                  <CtCheckboxField
                    id="rule-builder-badge-template-reuse-confirmation"
                    name="badgeTemplateReuseAcknowledged"
                    label="I confirm this rule is another valid way to earn the same badge."
                  />
                </div>
              </div>
              <p class="ct-admin__hint ct-admin__builder-field-span">
                {props.artworkActionTemplateCount > 0
                  ? `${String(props.artworkActionTemplateCount)} badge ${
                      props.artworkActionTemplateCount === 1 ? "template needs" : "templates need"
                    } artwork. `
                  : "Need a new template? "}
                <a href={props.createTemplateForRulePath}>
                  {props.artworkActionTemplateCount > 0
                    ? "Add artwork in Badge Templates"
                    : "Create one in Badge Templates and continue here"}
                </a>
                .
              </p>
              <AdminField label="LMS connection">
                <CtSelect
                  id="rule-builder-lms-connection"
                  name="lmsConnectionId"
                  required
                  disabled={props.connectedLmsConnections.length === 0}
                >
                  {props.isEditMode &&
                  props.connectedLmsConnections.length > 0 &&
                  props.defaultLmsConnectionId.length === 0 ? (
                    <option value="" selected>
                      {props.editRule?.latestVersion.snapshot.lmsConnectionId === null
                        ? "Choose an LMS connection"
                        : "Saved LMS connection is unavailable — choose another"}
                    </option>
                  ) : null}
                  {props.connectedLmsConnections.length === 0 ? (
                    <option value="">
                      {props.hasUnusableLmsConnections
                        ? "LMS connection needs credentials"
                        : "No LMS connection configured"}
                    </option>
                  ) : (
                    props.connectedLmsConnections.map((connection) => (
                      <option
                        key={connection.id}
                        value={connection.id}
                        data-provider-kind={connection.providerKind}
                        selected={connection.id === props.defaultLmsConnectionId}
                      >
                        {`${connection.displayName} (${badgeRuleLmsProviderLabel(connection.providerKind)})`}
                      </option>
                    ))
                  )}
                </CtSelect>
                <CtInput
                  id="rule-builder-lms-provider-kind"
                  name="lmsProviderKind"
                  type="hidden"
                  value={
                    props.editRule?.latestVersion.snapshot.lmsProviderKind ??
                    props.defaultLmsConnection?.providerKind ??
                    ""
                  }
                />
              </AdminField>
              {props.connectedLmsConnections.length === 0 ? (
                <div class="ct-admin__builder-prereq ct-admin__builder-field-span">
                  <span>
                    {props.hasUnusableLmsConnections
                      ? "The saved LMS connection is not usable yet. Add a Canvas token or Sakai username and password before building rules."
                      : "Create an LMS connection before building rules."}
                  </span>
                  <a class="ct-admin__text-action" href={props.accessLmsConnectionsPath}>
                    {props.hasUnusableLmsConnections
                      ? "Update LMS connection"
                      : "Create LMS connection"}
                  </a>
                </div>
              ) : null}
              <div
                id="rule-builder-lms-status"
                class="ct-admin__builder-lms-status ct-admin__builder-field-span"
                data-tone="info"
                role="alert"
                hidden={true}
              >
                <span data-rule-builder-lms-status-message="true"></span>
                <a class="ct-admin__text-action" href={props.accessLmsConnectionsPath}>
                  Update LMS connection
                </a>
              </div>
              <AdminField label="Awarding pattern" className="ct-admin__builder-field-span">
                <CtSelect id="rule-builder-template-preset" name="templatePreset">
                  <option value="course_completion">Course completed</option>
                  <option value="course_and_grade" selected>
                    Course completed + minimum score
                  </option>
                  <option value="program_completion">Course pathway completed</option>
                  <option value="assignment_submission">
                    Assignment, assessment, or gradebook item submitted
                  </option>
                  <option value="survey_completion">Survey completed</option>
                  <option value="prerequisite_chain">Prerequisite badge required</option>
                  <option value="time_limited">Date-limited earning window</option>
                </CtSelect>
              </AdminField>
              <AdminField label="Description (optional)" className="ct-admin__builder-field-span">
                <CtInput
                  name="description"
                  type="text"
                  value={props.editRule?.latestVersion.snapshot.description ?? ""}
                  placeholder="Award when learner completes the course with strong performance."
                />
              </AdminField>
            </div>
            <CtInput
              type="hidden"
              name="name"
              id="rule-builder-name"
              value={props.editRule?.latestVersion.snapshot.name ?? ""}
              dataAttributes={{
                "data-rule-builder-preserve-name": props.isEditMode ? "true" : "false",
              }}
            />
          </section>
        </section>
      </div>
    </li>
  );
};
/* oxlint-enable jsx-a11y/prefer-tag-over-role */

export const RuleBuilderConditionsStep = (props: {
  readonly rulesListPath: string;
}): HonoElement => {
  return (
    <li class="ct-admin__stepper-step" data-rule-step-row="conditions">
      <div class="ct-admin__stepper-header">
        <RuleBuilderStepButton
          stepNumber={2}
          target="conditions"
          title="Requirements"
          description="Confirm what learners must complete."
        />
      </div>
      <div class="ct-admin__stepper-content">
        <section
          id="builder-step-conditions"
          class="ct-admin__builder-step"
          data-rule-step="conditions"
          hidden
        >
          <header class="ct-admin__step-head ct-stack">
            <h3 tabindex={-1}>Awarding requirements</h3>
            <p>Review what a learner needs to do before CredTrail awards the badge.</p>
          </header>
          <div class="ct-admin__builder-workbench ct-stack">
            <div class="ct-admin__builder-workbench-main ct-stack">
              <AdminActions className="ct-admin__builder-toolbar">
                <CtInput id="rule-builder-root-logic" name="rootLogic" type="hidden" value="all" />
                <AdminButton type="button" id="rule-builder-add-condition" size="tiny">
                  Add requirement
                </AdminButton>
                <AdminButton
                  type="button"
                  id="rule-builder-add-alternative-path"
                  size="tiny"
                  variant="secondary"
                >
                  Add another way to earn it
                </AdminButton>
                <AdminButton
                  type="button"
                  id="rule-builder-require-every-requirement"
                  size="tiny"
                  variant="secondary"
                  hidden
                >
                  Require every requirement
                </AdminButton>
              </AdminActions>
              <section class="ct-admin__builder-canvas ct-stack">
                <header class="ct-admin__builder-canvas-header ct-cluster">
                  <strong>Requirements</strong>
                  <span class="ct-admin__meta">
                    Each requirement describes what a learner must do.
                  </span>
                </header>
                <p class="ct-admin__hint">
                  Reusable course or template lists are managed on the{" "}
                  <a href={props.rulesListPath}>Rules page</a>. Reload this builder after creating a
                  new list there.
                </p>
                <div class="ct-admin__builder-canvas-meta ct-cluster">
                  <span id="rule-builder-canvas-count" class="ct-admin__status-pill">
                    0 requirements
                  </span>
                  <span id="rule-builder-canvas-logic" class="ct-admin__status-pill">
                    Learner must meet every requirement
                  </span>
                </div>
                <div
                  id="rule-builder-condition-list"
                  class="ct-admin__builder-condition-list ct-stack"
                ></div>
              </section>
              <section
                class="ct-admin__builder-flow ct-stack"
                aria-labelledby="rule-builder-flow-title"
              >
                <header class="ct-admin__builder-canvas-header ct-cluster">
                  <strong id="rule-builder-flow-title">Rule flow preview</strong>
                  <span id="rule-builder-flow-mode" class="ct-admin__meta">
                    Waiting for requirements.
                  </span>
                </header>
                <p id="rule-builder-flow-empty" class="ct-admin__builder-canvas-empty">
                  Add requirements to preview the earning path.
                </p>
                <ol
                  id="rule-builder-flow-list"
                  class="ct-admin__builder-flow-list"
                  aria-label="Generated rule flow"
                ></ol>
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
                    Matches when gradebook items show full completion or the minimum percentage you
                    set.
                  </dd>
                </div>
                <div>
                  <dt>Gradebook score requirement</dt>
                  <dd>Matches when a learner's gradebook score is within the configured range.</dd>
                </div>
                <div>
                  <dt>Course pathway completion</dt>
                  <dd>Matches when enough required courses are completed for a course path.</dd>
                </div>
                <div>
                  <dt>Assignment, assessment, or gradebook item submitted</dt>
                  <dd>
                    Matches when gradebook item submission, score, and workflow-state constraints
                    pass.
                  </dd>
                </div>
                <div>
                  <dt>Survey completion</dt>
                  <dd>
                    Matches when completion facts show that a learner finished a required survey.
                  </dd>
                </div>
                <div>
                  <dt>Time window</dt>
                  <dd>Matches only inside optional not-before / not-after timestamps.</dd>
                </div>
                <div>
                  <dt>Prerequisite badge</dt>
                  <dd>Matches when learner already has an earned prerequisite badge template.</dd>
                </div>
                <div>
                  <dt>Custom field</dt>
                  <dd>
                    Matches institution-specific learner attributes such as cohort, pathway, or
                    standing.
                  </dd>
                </div>
              </dl>
            </details>
          </div>
          <details class="ct-admin__builder-advanced ct-stack">
            <summary>Generated rule JSON</summary>
            <AdminField label="Rule JSON (expert override)">
              <CtTextarea
                id="rule-builder-definition-json"
                name="definitionJson"
                rows={12}
                variant="code"
              />
            </AdminField>
            <AdminActions className="ct-admin__builder-inline">
              <AdminButton id="rule-builder-apply-json" type="button" size="tiny">
                Apply JSON
              </AdminButton>
            </AdminActions>
          </details>
        </section>
      </div>
    </li>
  );
};

export const RuleBuilderTestStep = (): HonoElement => {
  return (
    <li class="ct-admin__stepper-step" data-rule-step-row="test">
      <div class="ct-admin__stepper-header">
        <RuleBuilderStepButton
          stepNumber={3}
          target="test"
          title="Test and submit"
          description="Check the rule with a learner, then submit it."
        />
      </div>
      <div class="ct-admin__stepper-content">
        <section id="builder-step-test" class="ct-admin__builder-step" data-rule-step="test" hidden>
          <header class="ct-stack">
            <h3 tabindex={-1}>Check the rule</h3>
            <p>Testing never issues a badge.</p>
          </header>
          <div class="ct-admin__builder-test-layout ct-stack">
            <AdminFieldset legend="Test rule using">
              <AdminCheckboxRow
                name="testDataSource"
                type="radio"
                value="lms"
                label="A learner in the selected LMS"
                checked
              />
              <AdminCheckboxRow
                name="testDataSource"
                type="radio"
                value="example"
                label="Generated example data"
              />
              <div id="rule-builder-live-test-fields" class="ct-stack">
                <p class="ct-admin__hint">
                  Choose a learner from the courses in this rule. CredTrail checks their current LMS
                  records.
                </p>
                <div id="rule-builder-learner-filter" class="ct-stack" hidden>
                  <AdminField label="Search learners">
                    <CtInput
                      id="rule-builder-learner-filter-query"
                      type="search"
                      autocomplete="off"
                      placeholder="Name, email, or LMS ID"
                      describedBy="rule-builder-learner-filter-help"
                    />
                  </AdminField>
                  <p id="rule-builder-learner-filter-help" class="ct-admin__hint">
                    This roster is too large for one list. Search to narrow it.
                  </p>
                </div>
                <AdminField label="Learner to test">
                  <CtSelect
                    id="rule-builder-learner-select"
                    disabled
                    describedBy="rule-builder-learner-status"
                  >
                    <option value="">Learners load when this step opens</option>
                  </CtSelect>
                </AdminField>
                <p id="rule-builder-learner-status" class="ct-admin__hint" aria-live="polite">
                  CredTrail loads learners from the courses configured in this rule.
                </p>
                <CtInput name="testLearnerId" type="hidden" />
                <div id="rule-builder-test-recipient-fields" class="ct-stack" hidden>
                  <p class="ct-admin__hint">
                    This rule checks for a previously issued badge, so CredTrail also needs the
                    learner's credential email.
                  </p>
                  <AdminField label="Credential email">
                    <CtInput name="testRecipientIdentity" type="email" autocomplete="email" />
                  </AdminField>
                </div>
              </div>
              <div id="rule-builder-example-test-fields" class="ct-stack" hidden>
                <p class="ct-admin__hint">
                  Example data does not read the LMS. CredTrail generates matching facts from the
                  requirements below so you can check the rule structure.
                </p>
                <AdminField label="Example final score">
                  <CtInput
                    name="testFinalScore"
                    type="number"
                    min="0"
                    max="100"
                    step="0.01"
                    value="92"
                  />
                </AdminField>
                <AdminField label="Example gradebook items completed %">
                  <CtInput
                    name="testCompletionPercent"
                    type="number"
                    min="0"
                    max="100"
                    step="0.01"
                    value="100"
                  />
                </AdminField>
              </div>
              <div class="ct-admin__builder-test-actions">
                <AdminButton id="rule-builder-test" type="button" size="tiny">
                  Test learner
                </AdminButton>
              </div>
              <p
                id="rule-builder-test-result"
                class="ct-admin__status ct-admin__builder-test-result"
                aria-live="polite"
              >
                Choose an LMS learner, then run the test.
              </p>
            </AdminFieldset>
            <details
              id="rule-builder-example-test-advanced"
              class="ct-admin__builder-advanced ct-stack"
              hidden
            >
              <summary>Advanced test facts</summary>
              <AdminField label="Advanced facts JSON (optional)">
                <CtTextarea
                  name="testFactsJson"
                  rows={6}
                  variant="code"
                  placeholder='{"grades":[{"courseId":"CS101","learnerId":"example-learner","finalScore":92}]}'
                />
              </AdminField>
            </details>
          </div>
          <pre id="rule-builder-test-output" class="ct-admin__code-output" hidden></pre>
          <details class="ct-admin__builder-advanced ct-stack">
            <summary>Governance and release settings</summary>
            <p class="ct-admin__hint">
              Approval follows institution policy. Automatic issuance checks learners when the rule
              is activated and every hour afterward.
            </p>
            <div class="ct-admin__builder-review-layout ct-grid">
              <div class="ct-stack">
                <AdminField label="Issuance timing">
                  <CtSelect name="issuanceTiming">
                    <option value="immediate">Automatic</option>
                    <option value="manual">Instructor confirmation</option>
                    <option value="end_of_term">End-of-term batch</option>
                  </CtSelect>
                </AdminField>
                <AdminField label="Change summary (optional)">
                  <CtInput
                    name="changeSummary"
                    type="text"
                    placeholder="Initial draft for committee review."
                  />
                </AdminField>
                <AdminCheckboxRow
                  name="reviewOnMissingFacts"
                  label="Send missing-data cases to human review"
                />
              </div>
            </div>
          </details>
          <div class="ct-admin__builder-approval-note ct-stack">
            <strong>CredTrail follows your institution's approval policy.</strong>
            <p>
              You cannot approve a rule version you create or submit. Rules that require review go
              to another eligible approver; automatic-approval policies approve the version
              immediately.
            </p>
          </div>
        </section>
      </div>
    </li>
  );
};

export const RuleBuilderWorkflowFooter = (props: { readonly isEditMode: boolean }): HonoElement => {
  return (
    <footer id="rule-builder-step-footer" class="ct-admin__builder-step-footer">
      <p id="rule-builder-step-callout" class="ct-admin__builder-step-callout" aria-live="polite">
        Choose an awarding pattern, badge, and LMS connection, then select Continue.
      </p>
      <AdminActions className="ct-admin__builder-step-nav">
        <AdminButton id="rule-builder-step-next" type="button" size="tiny">
          Continue to Requirements
        </AdminButton>
        <AdminButton
          id="rule-builder-submit"
          type="submit"
          form="rule-create-form"
          hidden={true}
          name="action"
          value="submit_for_approval"
        >
          {props.isEditMode ? "Save and submit for approval" : "Create and submit for approval"}
        </AdminButton>
        <AdminButton
          id="rule-builder-save-formal-draft"
          type="submit"
          form="rule-create-form"
          variant="secondary"
          hidden={true}
          name="action"
          value="save_draft"
        >
          {props.isEditMode ? "Save draft version" : "Create rule draft"}
        </AdminButton>
      </AdminActions>
      <AdminStatus id="rule-create-status"></AdminStatus>
    </footer>
  );
};

export const RuleBuilderSaveDraftFooter = (): HonoElement => {
  return (
    <footer class="ct-admin__builder-step-footer">
      <AdminActions className="ct-admin__builder-step-nav">
        <AdminButton id="rule-builder-save-draft" type="button" size="tiny" variant="secondary">
          Save unfinished work
        </AdminButton>
      </AdminActions>
      <p id="rule-builder-draft-status" class="ct-admin__meta" aria-live="polite">
        Unfinished work not saved yet.
      </p>
    </footer>
  );
};

export const RuleBuilderAdvancedJsonTools = (): HonoElement => {
  return (
    <details class="ct-admin__panel ct-admin__builder-guide ct-admin__builder-support">
      <summary>Advanced JSON tools</summary>
      <div class="ct-admin__builder-support-grid ct-grid">
        <section class="ct-admin__builder-support-section ct-stack">
          <h3>Import and export</h3>
          <AdminActions className="ct-admin__builder-toolbar">
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
            <CtInput id="rule-builder-import-file" type="file" accept="application/json" hidden />
          </AdminActions>
          <p class="ct-admin__hint">
            Export JSON to move the rule definition between sessions, or import a saved definition.
          </p>
        </section>
        <section class="ct-admin__builder-support-section ct-stack">
          <h3>Advanced requirement tools</h3>
          <p class="ct-admin__hint">
            Use generated JSON for custom institutional fields or blank rule drafts. LMS course and
            gradebook item references still need to validate against the selected connection when
            you create the draft.
          </p>
        </section>
      </div>
    </details>
  );
};
