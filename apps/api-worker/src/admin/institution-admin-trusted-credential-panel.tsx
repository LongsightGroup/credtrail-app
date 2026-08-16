import type { BadgeTemplateRecord } from "@credtrail/db";
import type { TrustEdCredentialMetadata } from "@credtrail/validation";
import type { HtmlEscapedString } from "hono/utils/html";
import {
  emptyTrustEdCredentialMetadata,
  parseTrustEdCredentialMetadataJsonResult,
  type TrustEdCredentialMetadataParseResult,
} from "../badges/trusted-credential-metadata";
import { evaluateTrustEdCredentialReadiness } from "../badges/trusted-credential-readiness";
import { adminStatusPillClass } from "./admin-status-pill-class";
import { AdminButton, AdminField, AdminPanel, AdminStatus } from "./components";
import { CtInput, CtTextarea } from "../ui/forms";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

interface TrustEdEditorMetadataState {
  parseResult: TrustEdCredentialMetadataParseResult;
  formMetadata: TrustEdCredentialMetadata;
  readinessMetadata: TrustEdCredentialMetadata | null;
}

const metadataWithTemplateCriteriaUri = (
  metadata: TrustEdCredentialMetadata,
  templateCriteriaUri: string | null,
): TrustEdCredentialMetadata => {
  if (templateCriteriaUri === null || metadata.criteria?.uri !== null) {
    return metadata;
  }

  return {
    ...metadata,
    criteria: {
      text: metadata.criteria?.text ?? null,
      uri: templateCriteriaUri,
    },
  };
};

const trustEdEditorMetadataState = (template: BadgeTemplateRecord): TrustEdEditorMetadataState => {
  const parseResult = parseTrustEdCredentialMetadataJsonResult(
    template.trustedCredentialMetadataJson,
  );
  const validMetadata = parseResult.status === "valid" ? parseResult.metadata : null;

  return {
    parseResult,
    // Empty form metadata keeps authoring fields renderable for empty/invalid records.
    formMetadata: validMetadata ?? emptyTrustEdCredentialMetadata(),
    // Null readiness metadata intentionally means "not evaluated"; an empty object would mean "evaluated, incomplete".
    readinessMetadata:
      validMetadata === null
        ? null
        : metadataWithTemplateCriteriaUri(validMetadata, template.criteriaUri),
  };
};

const trustedReadinessTone = (status: "not_evaluated" | "incomplete" | "ready"): string => {
  switch (status) {
    case "ready":
      return "active";
    case "incomplete":
      return "warning";
    case "not_evaluated":
      return "draft";
  }
};

interface TrustEdTextField {
  label: string;
  name: string;
  value: string | null | undefined;
  type?: "text" | "url" | "date";
  maxLength?: number;
}

interface TrustEdTextareaField {
  label: string;
  name: string;
  value: string | null | undefined;
  rows: number;
  maxLength: number;
}

type TrustEdField =
  | (TrustEdTextField & {
      kind: "text";
    })
  | (TrustEdTextareaField & {
      kind: "textarea";
    });

const TrustEdTextField = (field: TrustEdTextField): HonoElement => {
  return (
    <AdminField label={field.label}>
      <CtInput
        form="badge-template-edit-form"
        name={field.name}
        type={field.type ?? "text"}
        maxlength={field.maxLength}
        value={field.value ?? ""}
      />
    </AdminField>
  );
};

const TrustEdTextareaField = (field: TrustEdTextareaField): HonoElement => {
  return (
    <AdminField label={field.label}>
      <CtTextarea
        form="badge-template-edit-form"
        name={field.name}
        rows={field.rows}
        maxlength={field.maxLength}
        value={field.value ?? ""}
      />
    </AdminField>
  );
};

const TrustEdFieldControl = (field: TrustEdField): HonoElement => {
  return field.kind === "textarea" ? (
    <TrustEdTextareaField {...field} />
  ) : (
    <TrustEdTextField {...field} />
  );
};

interface TrustEdRepeatableGroup<RowValue> {
  groupName: string;
  title: string;
  summary: string;
  addLabel: string;
  rows: readonly RowValue[];
  emptyRow: RowValue;
  showEmptyRow: boolean;
  open: boolean;
  fieldsForRow: (row: RowValue, index: number | "__INDEX__") => TrustEdField[];
}

const TRUSTED_MISSING_REQUIRED_PREVIEW_LIMIT = 4;

const trustedRepeatableEntryLabel = (entryCount: number): string => {
  if (entryCount === 0) {
    return "No entries";
  }

  if (entryCount === 1) {
    return "1 entry";
  }

  return `${String(entryCount)} entries`;
};

const TrustEdRepeatableGroup = <RowValue,>(
  group: TrustEdRepeatableGroup<RowValue>,
): HonoElement => {
  const visibleRows =
    group.rows.length > 0 ? [...group.rows] : group.showEmptyRow ? [group.emptyRow] : [];
  const entryLabel = trustedRepeatableEntryLabel(group.rows.length);

  return (
    <details
      class="ct-admin__template-editor-trusted-repeatable"
      data-trusted-repeatable={group.groupName}
      data-trusted-repeatable-title={group.title}
      data-trusted-repeatable-next-index={String(visibleRows.length)}
      open={group.open}
    >
      <summary class="ct-admin__template-editor-trusted-repeatable-summary">
        <span>
          <strong>{group.title}</strong>
          <small>{group.summary}</small>
        </span>
        <span class="ct-admin__status-pill">{entryLabel}</span>
      </summary>
      <div class="ct-admin__template-editor-trusted-repeatable-header">
        <AdminButton
          type="button"
          variant="secondary"
          size="tiny"
          dataAttributes={{ "data-trusted-repeatable-add": group.groupName }}
        >
          {group.addLabel}
        </AdminButton>
      </div>
      <div class="ct-admin__template-editor-trusted-repeatable-rows">
        {visibleRows.map((row, index) => (
          <div
            class="ct-admin__template-editor-trusted-repeatable-row"
            data-trusted-repeatable-row={group.groupName}
            data-trusted-repeatable-index={String(index)}
          >
            <div class="ct-admin__template-editor-trusted-repeatable-row-header">
              <span>{`${group.title} ${index + 1}`}</span>
              <AdminButton
                type="button"
                variant="quiet"
                size="tiny"
                dataAttributes={{ "data-trusted-repeatable-remove": group.groupName }}
              >
                Remove
              </AdminButton>
            </div>
            <div class="ct-admin__template-editor-trusted-grid">
              {group.fieldsForRow(row, index).map((field) => (
                <TrustEdFieldControl {...field} />
              ))}
            </div>
          </div>
        ))}
      </div>
      <template data-trusted-repeatable-template={group.groupName}>
        <div
          class="ct-admin__template-editor-trusted-repeatable-row"
          data-trusted-repeatable-row={group.groupName}
          data-trusted-repeatable-index="__INDEX__"
        >
          <div class="ct-admin__template-editor-trusted-repeatable-row-header">
            <span>{`${group.title} __ROW_NUMBER__`}</span>
            <AdminButton
              type="button"
              variant="quiet"
              size="tiny"
              dataAttributes={{ "data-trusted-repeatable-remove": group.groupName }}
            >
              Remove
            </AdminButton>
          </div>
          <div class="ct-admin__template-editor-trusted-grid">
            {group.fieldsForRow(group.emptyRow, "__INDEX__").map((field) => (
              <TrustEdFieldControl {...field} />
            ))}
          </div>
        </div>
      </template>
    </details>
  );
};

export const renderTrustEdCredentialPanel = (template: BadgeTemplateRecord): HonoElement => {
  const metadataState = trustEdEditorMetadataState(template);
  const metadata = metadataState.formMetadata;
  const readiness = evaluateTrustEdCredentialReadiness(metadataState.readinessMetadata);
  const missingRequired = readiness.checks.filter((check) => {
    return check.category === "required" && check.status === "missing";
  });
  const missingRecommended = readiness.checks.filter((check) => {
    return check.category === "recommended" && check.status === "missing";
  });
  const fields: TrustEdField[] = [
    {
      kind: "text",
      label: "Awarding authority",
      name: "trustedIssuerAuthorityName",
      value: metadata.issuerAuthority?.name,
      maxLength: 300,
    },
    {
      kind: "text",
      label: "Authority URL",
      name: "trustedIssuerAuthorityUri",
      value: metadata.issuerAuthority?.uri,
      type: "url",
      maxLength: 2048,
    },
    {
      kind: "text",
      label: "Authority type",
      name: "trustedIssuerAuthorityType",
      value: metadata.issuerAuthority?.authorityType,
      maxLength: 300,
    },
    {
      kind: "textarea",
      label: "Criteria summary",
      name: "trustedCriteriaText",
      value: metadata.criteria?.text,
      rows: 2,
      maxLength: 4000,
    },
    {
      kind: "text",
      label: "Achievement type",
      name: "trustedAchievementType",
      value: metadata.achievementType,
      maxLength: 300,
    },
    {
      kind: "text",
      label: "Duration",
      name: "trustedDurationValue",
      value: metadata.duration?.value,
      maxLength: 300,
    },
    {
      kind: "text",
      label: "Credits available",
      name: "trustedCreditsAvailable",
      value: metadata.credits?.available,
      maxLength: 300,
    },
    {
      kind: "text",
      label: "Credits earned",
      name: "trustedCreditsEarned",
      value: metadata.credits?.earned,
      maxLength: 300,
    },
  ];
  const requiredCheckIds = new Set(missingRequired.map((check) => check.id));
  const missingRequiredPreview = missingRequired.slice(0, TRUSTED_MISSING_REQUIRED_PREVIEW_LIMIT);
  const hiddenMissingRequiredCount = missingRequired.length - missingRequiredPreview.length;
  const trustEdEditorOpen =
    metadataState.parseResult.status === "invalid" || readiness.status === "incomplete";
  const repeatableGroups: HonoElement[] = [
    <TrustEdRepeatableGroup
      groupName="trustedSkills"
      title="Skill"
      summary="Skills or competencies represented by this badge."
      addLabel="Add skill"
      rows={metadata.skills}
      emptyRow={{ name: null, identifierUri: null, source: null }}
      showEmptyRow={metadata.skills.length === 0 && requiredCheckIds.has("skills")}
      open={metadata.skills.length > 0 || requiredCheckIds.has("skills")}
      fieldsForRow={(skill, index) => [
        {
          kind: "text",
          label: "Skill",
          name: `trustedSkills[${index}].name`,
          value: skill.name,
          maxLength: 300,
        },
        {
          kind: "text",
          label: "Skill URL",
          name: `trustedSkills[${index}].identifierUri`,
          value: skill.identifierUri,
          type: "url",
          maxLength: 2048,
        },
        {
          kind: "text",
          label: "Skill source",
          name: `trustedSkills[${index}].source`,
          value: skill.source,
          maxLength: 300,
        },
      ]}
    />,
    <TrustEdRepeatableGroup
      groupName="trustedFrameworkAlignments"
      title="Framework alignment"
      summary="External framework targets such as CASE, CTDL, or RSD."
      addLabel="Add alignment"
      rows={metadata.frameworkAlignments}
      emptyRow={{
        targetName: null,
        targetUri: null,
        frameworkName: null,
        frameworkUri: null,
      }}
      showEmptyRow={
        metadata.frameworkAlignments.length === 0 && requiredCheckIds.has("framework_alignment")
      }
      open={metadata.frameworkAlignments.length > 0 || requiredCheckIds.has("framework_alignment")}
      fieldsForRow={(alignment, index) => [
        {
          kind: "text",
          label: "Framework target",
          name: `trustedFrameworkAlignments[${index}].targetName`,
          value: alignment.targetName,
          maxLength: 300,
        },
        {
          kind: "text",
          label: "Framework target URL",
          name: `trustedFrameworkAlignments[${index}].targetUri`,
          value: alignment.targetUri,
          type: "url",
          maxLength: 2048,
        },
        {
          kind: "text",
          label: "Framework name",
          name: `trustedFrameworkAlignments[${index}].frameworkName`,
          value: alignment.frameworkName,
          maxLength: 300,
        },
        {
          kind: "text",
          label: "Framework URL",
          name: `trustedFrameworkAlignments[${index}].frameworkUri`,
          value: alignment.frameworkUri,
          type: "url",
          maxLength: 2048,
        },
      ]}
    />,
    <TrustEdRepeatableGroup
      groupName="trustedEvidence"
      title="Evidence"
      summary="Artifacts that support learner achievement."
      addLabel="Add evidence"
      rows={metadata.evidence}
      emptyRow={{ name: null, uri: null, description: null }}
      showEmptyRow={metadata.evidence.length === 0 && requiredCheckIds.has("evidence")}
      open={metadata.evidence.length > 0 || requiredCheckIds.has("evidence")}
      fieldsForRow={(evidence, index) => [
        {
          kind: "text",
          label: "Evidence name",
          name: `trustedEvidence[${index}].name`,
          value: evidence.name,
          maxLength: 300,
        },
        {
          kind: "text",
          label: "Evidence URL",
          name: `trustedEvidence[${index}].uri`,
          value: evidence.uri,
          type: "url",
          maxLength: 2048,
        },
        {
          kind: "textarea",
          label: "Evidence description",
          name: `trustedEvidence[${index}].description`,
          value: evidence.description,
          rows: 2,
          maxLength: 4000,
        },
      ]}
    />,
    <TrustEdRepeatableGroup
      groupName="trustedResults"
      title="Result"
      summary="Result values and dates used for review."
      addLabel="Add result"
      rows={metadata.results}
      emptyRow={{ value: null, resultDate: null }}
      showEmptyRow={metadata.results.length === 0 && requiredCheckIds.has("result")}
      open={metadata.results.length > 0 || requiredCheckIds.has("result")}
      fieldsForRow={(result, index) => [
        {
          kind: "text",
          label: "Result",
          name: `trustedResults[${index}].value`,
          value: result.value,
          maxLength: 300,
        },
        {
          kind: "text",
          label: "Result date",
          name: `trustedResults[${index}].resultDate`,
          value: result.resultDate,
          type: "date",
        },
      ]}
    />,
    <TrustEdRepeatableGroup
      groupName="trustedAssessments"
      title="Assessment"
      summary="How the learner was assessed."
      addLabel="Add assessment"
      rows={metadata.assessments}
      emptyRow={{ description: null, assessmentDate: null }}
      showEmptyRow={metadata.assessments.length === 0 && requiredCheckIds.has("assessment")}
      open={metadata.assessments.length > 0 || requiredCheckIds.has("assessment")}
      fieldsForRow={(assessment, index) => [
        {
          kind: "textarea",
          label: "Assessment description",
          name: `trustedAssessments[${index}].description`,
          value: assessment.description,
          rows: 2,
          maxLength: 4000,
        },
        {
          kind: "text",
          label: "Assessment date",
          name: `trustedAssessments[${index}].assessmentDate`,
          value: assessment.assessmentDate,
          type: "date",
        },
      ]}
    />,
    <TrustEdRepeatableGroup
      groupName="trustedRubrics"
      title="Rubric"
      summary="Optional rubric details when applicable."
      addLabel="Add rubric"
      rows={metadata.rubrics}
      emptyRow={{ name: null, uri: null }}
      showEmptyRow={false}
      open={metadata.rubrics.length > 0}
      fieldsForRow={(rubric, index) => [
        {
          kind: "text",
          label: "Rubric",
          name: `trustedRubrics[${index}].name`,
          value: rubric.name,
          maxLength: 300,
        },
        {
          kind: "text",
          label: "Rubric URL",
          name: `trustedRubrics[${index}].uri`,
          value: rubric.uri,
          type: "url",
          maxLength: 2048,
        },
      ]}
    />,
    <TrustEdRepeatableGroup
      groupName="trustedEndorsements"
      title="Endorsement"
      summary="Optional third-party endorsement details."
      addLabel="Add endorsement"
      rows={metadata.endorsements}
      emptyRow={{ endorserName: null, endorserUri: null }}
      showEmptyRow={false}
      open={metadata.endorsements.length > 0}
      fieldsForRow={(endorsement, index) => [
        {
          kind: "text",
          label: "Endorser",
          name: `trustedEndorsements[${index}].endorserName`,
          value: endorsement.endorserName,
          maxLength: 300,
        },
        {
          kind: "text",
          label: "Endorser URL",
          name: `trustedEndorsements[${index}].endorserUri`,
          value: endorsement.endorserUri,
          type: "url",
          maxLength: 2048,
        },
      ]}
    />,
  ];

  return (
    <AdminPanel
      as="section"
      id="template-editor-trusted-credential"
      className="ct-admin__template-editor-page-panel ct-admin__template-editor-section ct-admin__template-editor-section--trusted"
    >
      <header class="ct-admin__template-editor-section-header ct-admin__template-editor-section-header--split">
        <div>
          <h2>TrustEd readiness</h2>
          <p>
            Add TrustEd-ready public details only if this badge needs them. You can still issue the
            badge without them.
          </p>
        </div>
        <span class={adminStatusPillClass(trustedReadinessTone(readiness.status))}>
          {readiness.status === "ready"
            ? "TrustEd-ready"
            : readiness.status === "incomplete"
              ? "Incomplete"
              : "Not evaluated"}
        </span>
      </header>
      {metadataState.parseResult.status === "invalid" ? (
        <AdminStatus data-tone="error">
          Stored TrustEd metadata is invalid. Review and save this section to repair it.{" "}
          {metadataState.parseResult.error}
        </AdminStatus>
      ) : readiness.status === "not_evaluated" ? (
        <AdminStatus>No TrustEd details have been added yet.</AdminStatus>
      ) : missingRequired.length === 0 ? (
        <AdminStatus data-tone="success">
          Required TrustEd Credential checklist metadata is present for this template.
        </AdminStatus>
      ) : (
        <AdminStatus data-tone="warning">
          Add the missing required checklist metadata to make this template TrustEd-ready.
        </AdminStatus>
      )}
      <div class="ct-admin__template-editor-trusted-card">
        {readiness.status !== "not_evaluated" ? (
          <div class="ct-admin__template-editor-trusted-summary">
            <div>
              <strong>
                {String(
                  readiness.checks.length - missingRequired.length - missingRecommended.length,
                )}
              </strong>
              <span>checks satisfied</span>
            </div>
            <div>
              <strong>{String(missingRequired.length)}</strong>
              <span>required missing</span>
            </div>
            <div>
              <strong>{String(missingRecommended.length)}</strong>
              <span>recommended missing</span>
            </div>
          </div>
        ) : null}
        {readiness.status === "not_evaluated" ? (
          <p class="ct-admin__template-editor-trusted-card-note">
            TrustEd details are optional for this badge.
          </p>
        ) : missingRequired.length === 0 ? (
          <p class="ct-admin__template-editor-trusted-card-note">
            Required TrustEd fields are complete. Recommended fields stay optional.
          </p>
        ) : (
          <>
            <ul class="ct-admin__template-editor-trusted-missing">
              {missingRequiredPreview.map((check) => (
                <li>{check.message}</li>
              ))}
            </ul>
            {hiddenMissingRequiredCount > 0 ? (
              <p class="ct-admin__template-editor-trusted-missing-more">
                {`${String(hiddenMissingRequiredCount)} more required ${
                  hiddenMissingRequiredCount === 1 ? "item" : "items"
                } in the checklist below.`}
              </p>
            ) : null}
          </>
        )}
      </div>
      <details
        class="ct-admin__template-editor-advanced ct-admin__template-editor-trusted-editor"
        open={trustEdEditorOpen}
      >
        <summary>Complete TrustEd checklist</summary>
        <div class="ct-admin__template-editor-trusted-grid">
          {fields.map((field) => (
            <TrustEdFieldControl {...field} />
          ))}
        </div>
        <div class="ct-admin__template-editor-trusted-repeatables">{repeatableGroups}</div>
        <ul class="ct-admin__template-editor-trusted-checks">
          {readiness.checks.map((check) => (
            <li data-status={check.status} data-category={check.category}>
              <strong>{check.label}</strong>
              <span>{check.message}</span>
            </li>
          ))}
        </ul>
        <div class="ct-admin__template-editor-submit">
          <AdminButton form="badge-template-edit-form" type="submit">
            Save TrustEd metadata
          </AdminButton>
        </div>
      </details>
    </AdminPanel>
  );
};
