import type {
  BadgeTemplateRecord,
  LearnerPathwayAdminProgressRecord,
  LearnerPathwayProgressState,
  LearnerPathwayRecord,
  LearnerPathwayRequirementRecord,
  LearnerPathwayVersionSummaryRecord,
  TenantMembershipRole,
  TenantOrgUnitRecord,
  TenantRecord,
} from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import { CtInput, CtSelect, CtTextarea } from "../ui/forms";
import type { AppPage } from "../ui/render-page";
import { formatIsoTimestamp } from "../utils/display-format";
import {
  AdminActions,
  AdminButton,
  AdminButtonLink,
  AdminEmptyTableRow,
  AdminField,
  AdminForm,
  AdminListHeader,
  AdminPanel,
  AdminStatusPill,
  AdminTable,
} from "./components";
import {
  renderInstitutionAdminPageHeader,
  renderInstitutionAdminShellPage,
} from "./institution-admin-shell";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

interface LearnerPathwayShellInput {
  tenant: TenantRecord;
  userId: string;
  userEmail?: string | undefined;
  membershipRole: TenantMembershipRole;
  switchOrganizationPath?: string | null | undefined;
}

interface LearnerPathwayReferenceData {
  orgUnits: readonly TenantOrgUnitRecord[];
  badgeTemplates: readonly BadgeTemplateRecord[];
}

const pathwaysPath = (tenantId: string): string =>
  `/tenants/${encodeURIComponent(tenantId)}/admin/operations/pathways`;

const pathwayPath = (tenantId: string, pathwayId: string): string =>
  `${pathwaysPath(tenantId)}/${encodeURIComponent(pathwayId)}`;

const pathwayStatusLabel = (status: LearnerPathwayRecord["status"]): string => {
  switch (status) {
    case "draft":
      return "Draft";
    case "published":
      return "Published";
    case "retired":
      return "Retired";
  }
};

const pathwayDisplayStatus = (pathway: LearnerPathwayRecord): { label: string; tone: string } =>
  pathway.version.status === "draft"
    ? { label: `Draft v${String(pathway.version.number)}`, tone: "draft" }
    : { label: pathwayStatusLabel(pathway.status), tone: pathway.status };

type LearnerPathwayProgressStateTag = LearnerPathwayProgressState["_tag"];

const evaluationPresentation = {
  complete: { label: "Complete", tone: "active" },
  eligible: { label: "Approved for issuance", tone: "active" },
  issued: { label: "Credential issued", tone: "active" },
  needs_review: { label: "Needs review", tone: "pending_review" },
  invalidated: { label: "Invalidated", tone: "revoked" },
  in_progress: { label: "In progress", tone: "draft" },
} satisfies Record<LearnerPathwayProgressStateTag, { label: string; tone: string }>;

const progressStateMessages = {
  eligible: "Final credential eligible — issuance is awaiting an administrator decision.",
  issued: "The final credential was issued through the governed handoff.",
  needs_review: "Final credential review is pending in this governed handoff.",
  invalidated: "Prior completion was invalidated after its qualifying evidence changed.",
  complete: "Completion recorded; no credential was issued automatically.",
  in_progress: "The learner is still working toward the pathway requirements.",
} satisfies Record<LearnerPathwayProgressStateTag, string>;

const evaluationLabel = (
  progress: LearnerPathwayAdminProgressRecord,
): { label: string; tone: string } => evaluationPresentation[progress.state._tag];

const progressStateMessage = (progress: LearnerPathwayAdminProgressRecord): string =>
  progressStateMessages[progress.state._tag];

const pathwayShellPage = (
  input: LearnerPathwayShellInput,
  title: string,
  children: HonoElement,
): AppPage => {
  return renderInstitutionAdminShellPage({
    tenant: input.tenant,
    userId: input.userId,
    ...(input.userEmail === undefined ? {} : { userEmail: input.userEmail }),
    membershipRole: input.membershipRole,
    ...(input.switchOrganizationPath === undefined
      ? {}
      : { switchOrganizationPath: input.switchOrganizationPath }),
    view: "operationsPathways",
    title,
    assets: ["institutionAdminCss", "institutionAdminShellJs"],
    contextJson: { tenantId: input.tenant.id, view: "operationsPathways" },
    children,
  });
};

const Notice = (props: { notice: string | null; error: string | null }): HonoElement | null => {
  const message = props.error ?? props.notice;

  if (message === null) {
    return null;
  }

  return (
    <div
      class={`ct-admin__status ${props.error === null ? "ct-admin__status--success" : "ct-admin__status--error"}`}
      role={props.error === null ? "status" : "alert"}
    >
      {message}
    </div>
  );
};

export const learnerPathwaysAdminPage = (
  input: LearnerPathwayShellInput & {
    pathways: readonly LearnerPathwayRecord[];
    notice: string | null;
    error: string | null;
  },
): AppPage => {
  const basePath = pathwaysPath(input.tenant.id);

  return pathwayShellPage(
    input,
    `Pathways · ${input.tenant.displayName}`,
    <div class="ct-stack">
      {renderInstitutionAdminPageHeader(
        "Learner pathways",
        "Define institution-owned programs and follow each learner’s verified evidence through completion.",
      )}
      <Notice notice={input.notice} error={input.error} />
      <AdminPanel variant="table" stack={false}>
        <AdminListHeader
          title="Programs"
          description="Published versions stay immutable so prior evaluations remain explainable."
          action={<AdminButtonLink href={`${basePath}/new`}>New pathway</AdminButtonLink>}
        />
        <AdminTable
          headers={["Pathway", "Owner", "Version", "Requirements", "Active learners", "Status", ""]}
        >
          {input.pathways.length === 0 ? (
            <AdminEmptyTableRow colSpan={7}>
              No pathways yet. Create the first program when its outcome and evidence requirements
              are clear.
            </AdminEmptyTableRow>
          ) : (
            input.pathways.map((pathway) => {
              const displayStatus = pathwayDisplayStatus(pathway);
              return (
                <tr key={pathway.id}>
                  <th scope="row">
                    <a href={pathwayPath(input.tenant.id, pathway.id)}>{pathway.version.title}</a>
                    <p class="ct-admin__meta">{pathway.version.learnerDescription}</p>
                  </th>
                  <td>{pathway.ownerOrgUnitName}</td>
                  <td>{String(pathway.version.number)}</td>
                  <td>{String(pathway.requirementCount)}</td>
                  <td>{String(pathway.activeEnrollmentCount)}</td>
                  <td>
                    <AdminStatusPill tone={displayStatus.tone}>
                      {displayStatus.label}
                    </AdminStatusPill>
                  </td>
                  <td>
                    <AdminButtonLink href={pathwayPath(input.tenant.id, pathway.id)} size="tiny">
                      {pathway.version.status === "draft" ? "Continue setup" : "View program"}
                    </AdminButtonLink>
                  </td>
                </tr>
              );
            })
          )}
        </AdminTable>
      </AdminPanel>
    </div>,
  );
};

const requirementOptionValue = (requirement: LearnerPathwayRequirementRecord): string =>
  requirement.requirementKind === "badge_template"
    ? `badge:${requirement.badgeTemplateId ?? ""}`
    : `record:${requirement.learnerRecordType ?? ""}`;

const RequirementOptions = (props: {
  badgeTemplates: readonly BadgeTemplateRecord[];
  selected?: string | undefined;
  allowEmpty: boolean;
}): HonoElement => {
  const recordTypes = [
    ["course", "Verified course completion"],
    ["certificate", "Verified certificate"],
    ["license", "Verified license"],
    ["competency", "Verified competency"],
    ["work_based_learning", "Verified work-based learning"],
    ["experience", "Verified experience"],
    ["membership", "Verified membership"],
    ["custom", "Other institution-verified record"],
  ] as const;

  return (
    <>
      {props.allowEmpty ? (
        <option value="">No additional requirement</option>
      ) : (
        <option value="">Choose evidence</option>
      )}
      <optgroup label="Issued badges">
        {props.badgeTemplates
          .filter((template) => !template.isArchived)
          .map((template) => {
            const value = `badge:${template.id}`;
            return (
              <option value={value} selected={props.selected === value ? true : undefined}>
                {template.title}
              </option>
            );
          })}
      </optgroup>
      <optgroup label="Institution-verified learner records">
        {recordTypes.map(([value, label]) => {
          const optionValue = `record:${value}`;
          return (
            <option
              value={optionValue}
              selected={props.selected === optionValue ? true : undefined}
            >
              {label}
            </option>
          );
        })}
      </optgroup>
    </>
  );
};

export const learnerPathwayBuilderPage = (
  input: LearnerPathwayShellInput &
    LearnerPathwayReferenceData & {
      draft: LearnerPathwayRecord | null;
      requirements: readonly LearnerPathwayRequirementRecord[];
      error: string | null;
    },
): AppPage => {
  const basePath = pathwaysPath(input.tenant.id);
  const action =
    input.draft === null ? basePath : `${pathwayPath(input.tenant.id, input.draft.id)}/edit`;
  const selectedRequirements = input.requirements.map(requirementOptionValue);
  const formTitle = input.draft === null ? "New pathway" : `Edit ${input.draft.version.title}`;

  return pathwayShellPage(
    input,
    `${formTitle} · ${input.tenant.displayName}`,
    <div class="ct-stack">
      {renderInstitutionAdminPageHeader(
        formTitle,
        "Set the learner outcome, order the evidence requirements, then choose what completion should do.",
      )}
      <Notice notice={null} error={input.error} />
      <AdminPanel>
        <AdminForm method="post" action={action} className="ct-admin__form ct-stack">
          <fieldset class="ct-stack">
            <legend>1. Program outcome and owner</legend>
            <AdminField label="Pathway name">
              <CtInput name="title" required maxlength={200} value={input.draft?.version.title} />
            </AdminField>
            <AdminField label="What learners are working toward">
              <CtTextarea
                name="learnerDescription"
                required
                maxlength={4000}
                rows={4}
                value={input.draft?.version.learnerDescription}
              />
            </AdminField>
            <AdminField label="Program owner">
              <CtSelect name="ownerOrgUnitId" required>
                <option value="">Choose an organization unit</option>
                {input.orgUnits
                  .filter((unit) => unit.isActive)
                  .map((unit) => (
                    <option
                      value={unit.id}
                      selected={input.draft?.ownerOrgUnitId === unit.id ? true : undefined}
                    >
                      {unit.displayName}
                    </option>
                  ))}
              </CtSelect>
            </AdminField>
          </fieldset>
          <fieldset class="ct-stack">
            <legend>2. Ordered requirements</legend>
            <p class="ct-admin__meta">
              Only issuer-verified evidence can satisfy these requirements. Learner-added items
              remain visible but never count automatically.
            </p>
            <AdminField label="Requirement 1">
              <CtSelect name="requirement" required>
                <RequirementOptions
                  badgeTemplates={input.badgeTemplates}
                  selected={selectedRequirements[0]}
                  allowEmpty={false}
                />
              </CtSelect>
            </AdminField>
            <details open={selectedRequirements.length > 1 ? true : undefined}>
              <summary>Add more requirements</summary>
              <div class="ct-stack">
                {[1, 2, 3, 4].map((index) => (
                  <AdminField label={`Requirement ${String(index + 1)}`}>
                    <CtSelect name="requirement">
                      <RequirementOptions
                        badgeTemplates={input.badgeTemplates}
                        selected={selectedRequirements[index]}
                        allowEmpty
                      />
                    </CtSelect>
                  </AdminField>
                ))}
              </div>
            </details>
          </fieldset>
          <fieldset class="ct-stack">
            <legend>3. Completion behavior</legend>
            <AdminField label="When every requirement is satisfied">
              <CtSelect name="completionBehavior" required>
                <option
                  value="mark_complete"
                  selected={
                    input.draft?.version.completionBehavior === "mark_complete" ? true : undefined
                  }
                >
                  Mark the pathway complete
                </option>
                <option
                  value="credential_eligible"
                  selected={
                    input.draft?.version.completionBehavior === "credential_eligible"
                      ? true
                      : undefined
                  }
                >
                  Mark eligible for a final credential
                </option>
                <option
                  value="review_required"
                  selected={
                    input.draft?.version.completionBehavior === "review_required" ? true : undefined
                  }
                >
                  Send the final credential to review
                </option>
              </CtSelect>
            </AdminField>
            <AdminField label="Final credential">
              <CtSelect name="finalBadgeTemplateId">
                <option value="">Not used for completion-only pathways</option>
                {input.badgeTemplates
                  .filter((template) => !template.isArchived)
                  .map((template) => (
                    <option
                      value={template.id}
                      selected={
                        input.draft?.version.finalBadgeTemplateId === template.id ? true : undefined
                      }
                    >
                      {template.title}
                    </option>
                  ))}
              </CtSelect>
            </AdminField>
          </fieldset>
          <AdminActions>
            <AdminButton type="submit">
              {input.draft === null ? "Create pathway draft" : "Save draft"}
            </AdminButton>
            <AdminButtonLink href={basePath} variant="quiet">
              Cancel
            </AdminButtonLink>
          </AdminActions>
        </AdminForm>
      </AdminPanel>
    </div>,
  );
};

const RequirementState = (props: {
  state: LearnerPathwayAdminProgressRecord["evaluation"]["requirements"][number]["state"];
}): HonoElement => {
  const label = {
    met: "Met",
    not_recorded: "No evidence recorded yet",
    in_review: "Needs review",
    waived: "Waived",
    invalidated: "Invalidated",
  }[props.state];
  return <AdminStatusPill tone={props.state}>{label}</AdminStatusPill>;
};

export const learnerPathwayDetailPage = (
  input: LearnerPathwayShellInput & {
    pathway: LearnerPathwayRecord;
    requirements: readonly LearnerPathwayRequirementRecord[];
    versions: readonly LearnerPathwayVersionSummaryRecord[];
    progress: readonly LearnerPathwayAdminProgressRecord[];
    notice: string | null;
    error: string | null;
    isHistoricalView?: boolean | undefined;
  },
): AppPage => {
  const basePath = pathwaysPath(input.tenant.id);
  const detailPath = pathwayPath(input.tenant.id, input.pathway.id);
  const completionBehaviorLabel =
    input.pathway.version.completionBehavior === "mark_complete"
      ? "Record pathway completion"
      : input.pathway.version.completionBehavior === "credential_eligible"
        ? "Flag the final credential as eligible for administrator issuance"
        : "Send the final credential decision to administrator review";

  return pathwayShellPage(
    input,
    `${input.pathway.version.title} · ${input.tenant.displayName}`,
    <div class="ct-stack">
      {renderInstitutionAdminPageHeader(
        input.pathway.version.title,
        input.pathway.version.learnerDescription,
        <p class="ct-admin__meta">
          Version {String(input.pathway.version.number)} · {String(input.pathway.requirementCount)}{" "}
          ordered requirements
        </p>,
      )}
      <Notice notice={input.notice} error={input.error} />
      <AdminPanel>
        <AdminListHeader
          title="Version definition"
          description="Requirements are evaluated in this order using institution-verified evidence only."
        />
        <ol>
          {input.requirements.map((requirement) => (
            <li key={requirement.id}>
              <strong>{requirement.title}</strong>
              {requirement.description === null ? null : <p>{requirement.description}</p>}
            </li>
          ))}
        </ol>
        <p>
          <strong>On completion:</strong> {completionBehaviorLabel}.
        </p>
      </AdminPanel>
      <AdminPanel>
        <AdminListHeader
          title="Program governance"
          description={
            input.isHistoricalView === true
              ? "This historical definition is immutable and remains available for audit and prior learner evaluations."
              : input.pathway.version.status === "draft"
                ? "Review this draft, continue setup if needed, then publish it when the definition is ready."
                : "Published versions cannot be edited. Create a new version for material changes."
          }
        />
        <AdminActions>
          {input.isHistoricalView === true ? null : input.pathway.version.status === "draft" ? (
            <>
              <AdminButtonLink href={`${detailPath}/edit`}>Continue setup</AdminButtonLink>
              <AdminForm
                method="post"
                action={`${detailPath}/publish`}
                className="ct-admin__inline-action-form"
              >
                <AdminButton type="submit" variant="secondary">
                  Publish version
                </AdminButton>
              </AdminForm>
            </>
          ) : input.pathway.status === "published" ? (
            <>
              <AdminForm
                method="post"
                action={`${detailPath}/versions`}
                className="ct-admin__inline-action-form"
              >
                <AdminButton type="submit" variant="secondary">
                  Create new version
                </AdminButton>
              </AdminForm>
            </>
          ) : null}
          <AdminButtonLink href={basePath} variant="quiet">
            Back to pathways
          </AdminButtonLink>
        </AdminActions>
        {input.isHistoricalView === true || input.pathway.version.status !== "published" ? null : (
          <details>
            <summary>Retire this pathway</summary>
            <p>
              Retirement stops new enrollments. Existing enrollments, evaluation history, and
              completion decisions remain available.
            </p>
            <AdminForm
              method="post"
              action={`${detailPath}/retire`}
              className="ct-admin__inline-action-form"
            >
              <CtInput name="confirmation" type="hidden" value="retire" />
              <AdminButton type="submit" variant="danger">
                Retire and stop new enrollments
              </AdminButton>
            </AdminForm>
          </details>
        )}
      </AdminPanel>
      <AdminPanel variant="table" stack={false}>
        <AdminListHeader
          title="Version history"
          description="Every published definition remains inspectable."
        />
        <AdminTable headers={["Version", "Title", "Requirements", "Status", "Published"]}>
          {input.versions.map((version) => (
            <tr key={version.id}>
              <th scope="row">
                <a href={`${detailPath}/versions/${encodeURIComponent(version.id)}`}>
                  {String(version.number)}
                </a>
              </th>
              <td>{version.title}</td>
              <td>{String(version.requirementCount)}</td>
              <td>
                <AdminStatusPill tone={version.status}>
                  {version.status === "draft"
                    ? "Draft"
                    : version.status === "published"
                      ? "Published"
                      : "Superseded"}
                </AdminStatusPill>
              </td>
              <td>
                {version.publishedAt === null
                  ? "Not published"
                  : `${formatIsoTimestamp(version.publishedAt)} UTC`}
              </td>
            </tr>
          ))}
        </AdminTable>
      </AdminPanel>
      {input.isHistoricalView === true || input.pathway.version.status !== "published" ? null : (
        <AdminPanel>
          <AdminListHeader
            title="Enroll a learner"
            description="Enrollment locks the learner to this published version so future changes do not rewrite history."
          />
          <AdminForm method="post" action={`${detailPath}/enroll`}>
            <AdminField label="Learner email">
              <CtInput
                name="learnerEmail"
                type="email"
                required
                maxlength={320}
                autocomplete="off"
              />
            </AdminField>
            <AdminButton type="submit">Enroll learner</AdminButton>
          </AdminForm>
        </AdminPanel>
      )}
      {input.isHistoricalView === true ? null : (
        <AdminPanel variant="table" stack={false}>
          <AdminListHeader
            title="Learner progress"
            description="Current status is recalculated from governed evidence; prior evaluations remain in the audit record."
          />
          <AdminTable headers={["Learner", "Progress", "Requirement evidence", "Evaluated"]}>
            {input.progress.length === 0 ? (
              <AdminEmptyTableRow colSpan={4}>
                No learners are enrolled in this pathway.
              </AdminEmptyTableRow>
            ) : (
              input.progress.map((entry) => {
                const status = evaluationLabel(entry);
                return (
                  <tr key={entry.enrollmentId}>
                    <th scope="row">
                      {entry.learnerDisplayName ?? entry.learnerSubjectId}
                      <p class="ct-admin__meta">
                        Enrolled in version {String(entry.versionNumber)}
                      </p>
                    </th>
                    <td>
                      <AdminStatusPill tone={status.tone}>{status.label}</AdminStatusPill>
                      <p class="ct-admin__meta">{progressStateMessage(entry)}</p>
                      {entry.state._tag === "needs_review" ? (
                        <AdminForm
                          method="post"
                          action={`${detailPath}/enrollments/${encodeURIComponent(entry.enrollmentId)}/completion-review`}
                          className="ct-admin__inline-action-form"
                        >
                          <CtInput name="decision" type="hidden" value="approve_for_issuance" />
                          <AdminButton type="submit" size="tiny" variant="secondary">
                            Approve for issuance
                          </AdminButton>
                        </AdminForm>
                      ) : entry.state._tag === "eligible" ? (
                        <AdminButtonLink
                          href={`/tenants/${encodeURIComponent(input.tenant.id)}/admin/operations/issue?${new URLSearchParams(
                            {
                              pathwayHandoffId: entry.state.handoffId,
                              badgeTemplateId: entry.state.badgeTemplateId,
                            },
                          ).toString()}`}
                          size="tiny"
                        >
                          Review issuance
                        </AdminButtonLink>
                      ) : entry.state._tag === "issued" ? (
                        <AdminButtonLink
                          href={`/badges/${encodeURIComponent(entry.state.assertionPublicId)}`}
                          size="tiny"
                          variant="secondary"
                        >
                          View final credential
                        </AdminButtonLink>
                      ) : null}
                    </td>
                    <td>
                      <ol>
                        {entry.evaluation.requirements.map((requirement) => (
                          <li key={requirement.requirementId}>
                            <strong>{requirement.title}</strong>{" "}
                            <RequirementState state={requirement.state} />
                            <p class="ct-admin__meta">{requirement.rationale}</p>
                            {requirement.state === "not_recorded" ||
                            requirement.state === "invalidated" ? (
                              <AdminForm
                                method="post"
                                action={`${detailPath}/enrollments/${encodeURIComponent(entry.enrollmentId)}/waivers`}
                                className="ct-admin__inline-action-form"
                              >
                                <CtInput
                                  name="requirementId"
                                  type="hidden"
                                  value={requirement.requirementId}
                                />
                                <AdminField label="Approved exception reason" compact>
                                  <CtInput name="reason" required maxlength={1000} />
                                </AdminField>
                                <AdminButton type="submit" size="tiny" variant="secondary">
                                  Approve exception
                                </AdminButton>
                              </AdminForm>
                            ) : requirement.state === "waived" ? (
                              <details>
                                <summary>Revoke approved exception</summary>
                                <AdminForm
                                  method="post"
                                  action={`${detailPath}/enrollments/${encodeURIComponent(entry.enrollmentId)}/waivers/revoke`}
                                  className="ct-admin__inline-action-form"
                                >
                                  <CtInput
                                    name="requirementId"
                                    type="hidden"
                                    value={requirement.requirementId}
                                  />
                                  <CtInput name="decision" type="hidden" value="revoke_exception" />
                                  <AdminButton type="submit" size="tiny" variant="danger">
                                    Revoke exception and recalculate
                                  </AdminButton>
                                </AdminForm>
                              </details>
                            ) : null}
                          </li>
                        ))}
                      </ol>
                    </td>
                    <td>
                      {formatIsoTimestamp(entry.evaluation.evaluatedAt)} UTC
                      <details>
                        <summary>
                          Recent evaluation history ({String(entry.evaluationHistory.length)})
                        </summary>
                        <ol>
                          {entry.evaluationHistory.map((evaluation) => (
                            <li key={evaluation.id}>
                              {formatIsoTimestamp(evaluation.evaluatedAt)} UTC: {evaluation.result}{" "}
                              — {evaluation.rationale}
                            </li>
                          ))}
                        </ol>
                      </details>
                    </td>
                  </tr>
                );
              })
            )}
          </AdminTable>
        </AdminPanel>
      )}
    </div>,
  );
};
