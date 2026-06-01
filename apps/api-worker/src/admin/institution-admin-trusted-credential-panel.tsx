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

const repeatableRows = <ValueType,>(
  items: readonly ValueType[],
  emptyRow: ValueType,
): ValueType[] => {
  return items.length > 0 ? [...items] : [emptyRow];
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
      <input
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
      <textarea
        form="badge-template-edit-form"
        name={field.name}
        rows={field.rows}
        maxlength={field.maxLength}
      >
        {field.value ?? ""}
      </textarea>
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
  addLabel: string;
  rows: RowValue[];
  fieldsForRow: (row: RowValue, index: number | "__INDEX__") => TrustEdField[];
}

const TrustEdRepeatableGroup = <RowValue,>(
  group: TrustEdRepeatableGroup<RowValue>,
): HonoElement => {
  return (
    <fieldset
      class="ct-admin__template-editor-trusted-repeatable"
      data-trusted-repeatable={group.groupName}
      data-trusted-repeatable-next-index={String(group.rows.length)}
    >
      <legend class="ct-admin__template-editor-trusted-repeatable-title">{group.title}</legend>
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
        {group.rows.map((row, index) => (
          <div
            class="ct-admin__template-editor-trusted-repeatable-row"
            data-trusted-repeatable-row={group.groupName}
            data-trusted-repeatable-index={String(index)}
          >
            <div class="ct-admin__template-editor-trusted-repeatable-row-header">
              <span>{`${group.title} ${index + 1}`}</span>
              <AdminButton
                type="button"
                variant="ghost"
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
              variant="ghost"
              size="tiny"
              dataAttributes={{ "data-trusted-repeatable-remove": group.groupName }}
            >
              Remove
            </AdminButton>
          </div>
          <div class="ct-admin__template-editor-trusted-grid">
            {group.fieldsForRow({} as RowValue, "__INDEX__").map((field) => (
              <TrustEdFieldControl {...field} />
            ))}
          </div>
        </div>
      </template>
    </fieldset>
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
  const repeatableGroups: HonoElement[] = [
    <TrustEdRepeatableGroup
      groupName="trustedSkills"
      title="Skill"
      addLabel="Add skill"
      rows={repeatableRows(metadata.skills, { name: null, identifierUri: null, source: null })}
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
      addLabel="Add alignment"
      rows={repeatableRows(metadata.frameworkAlignments, {
        targetName: null,
        targetUri: null,
        frameworkName: null,
        frameworkUri: null,
      })}
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
      addLabel="Add evidence"
      rows={repeatableRows(metadata.evidence, { name: null, uri: null, description: null })}
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
      addLabel="Add result"
      rows={repeatableRows(metadata.results, { value: null, resultDate: null })}
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
      addLabel="Add assessment"
      rows={repeatableRows(metadata.assessments, { description: null, assessmentDate: null })}
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
      addLabel="Add rubric"
      rows={repeatableRows(metadata.rubrics, { name: null, uri: null })}
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
      addLabel="Add endorsement"
      rows={repeatableRows(metadata.endorsements, { endorserName: null, endorserUri: null })}
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
          <h2>TrustEd authoring checklist</h2>
          <p>
            Add skills, evidence, results, assessment, and framework alignment for more inspectable
            credentials. Issuance is not blocked by this advisory checklist.
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
      ) : missingRequired.length === 0 ? (
        <AdminStatus data-tone="success">
          Required TrustEd Credential checklist metadata is present for this template.
        </AdminStatus>
      ) : (
        <AdminStatus data-tone="warning">
          Add the missing required checklist metadata to make this template TrustEd-ready.
        </AdminStatus>
      )}
      <div class="ct-admin__template-editor-trusted-summary">
        <div>
          <strong>
            {String(readiness.checks.length - missingRequired.length - missingRecommended.length)}
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
      <details class="ct-admin__template-editor-advanced" open={readiness.status !== "ready"}>
        <summary>TrustEd metadata</summary>
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
      </details>
      <div class="ct-admin__template-editor-submit">
        <AdminButton form="badge-template-edit-form" type="submit">
          Save TrustEd metadata
        </AdminButton>
      </div>
    </AdminPanel>
  );
};
