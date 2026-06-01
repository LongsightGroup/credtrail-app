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

const trustEdEditorMetadataState = (template: BadgeTemplateRecord): TrustEdEditorMetadataState => {
  const parseResult = parseTrustEdCredentialMetadataJsonResult(
    template.trustedCredentialMetadataJson,
  );

  return {
    parseResult,
    // Empty form metadata keeps authoring fields renderable for empty/invalid records.
    formMetadata:
      parseResult.status === "valid" ? parseResult.metadata : emptyTrustEdCredentialMetadata(),
    // Null readiness metadata intentionally means "not evaluated"; an empty object would mean "evaluated, incomplete".
    readinessMetadata: parseResult.status === "valid" ? parseResult.metadata : null,
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

const firstOrNull = <ValueType,>(items: readonly ValueType[]): ValueType | null => {
  return items[0] ?? null;
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

export const renderTrustEdCredentialPanel = (template: BadgeTemplateRecord): HonoElement => {
  // v1 authoring exposes one row per repeatable field; saving writes at most one array entry.
  const metadataState = trustEdEditorMetadataState(template);
  const metadata = metadataState.formMetadata;
  const readiness = evaluateTrustEdCredentialReadiness(metadataState.readinessMetadata);
  const skill = firstOrNull(metadata.skills);
  const alignment = firstOrNull(metadata.frameworkAlignments);
  const evidence = firstOrNull(metadata.evidence);
  const result = firstOrNull(metadata.results);
  const assessment = firstOrNull(metadata.assessments);
  const rubric = firstOrNull(metadata.rubrics);
  const endorsement = firstOrNull(metadata.endorsements);
  const missingRequired = readiness.checks.filter((check) => {
    return check.category === "required" && check.status === "missing";
  });
  const missingRecommended = readiness.checks.filter((check) => {
    return check.category === "recommended" && check.status === "missing";
  });
  const textFields: TrustEdTextField[] = [
    { label: "Skill", name: "trustedSkillName", value: skill?.name, maxLength: 300 },
    {
      label: "Skill URL",
      name: "trustedSkillIdentifierUri",
      value: skill?.identifierUri,
      type: "url",
      maxLength: 2048,
    },
    { label: "Skill source", name: "trustedSkillSource", value: skill?.source, maxLength: 300 },
    {
      label: "Framework target",
      name: "trustedFrameworkTargetName",
      value: alignment?.targetName,
      maxLength: 300,
    },
    {
      label: "Framework target URL",
      name: "trustedFrameworkTargetUri",
      value: alignment?.targetUri,
      type: "url",
      maxLength: 2048,
    },
    {
      label: "Framework name",
      name: "trustedFrameworkName",
      value: alignment?.frameworkName,
      maxLength: 300,
    },
    {
      label: "Framework URL",
      name: "trustedFrameworkUri",
      value: alignment?.frameworkUri,
      type: "url",
      maxLength: 2048,
    },
    {
      label: "Awarding authority",
      name: "trustedIssuerAuthorityName",
      value: metadata.issuerAuthority?.name,
      maxLength: 300,
    },
    {
      label: "Authority URL",
      name: "trustedIssuerAuthorityUri",
      value: metadata.issuerAuthority?.uri,
      type: "url",
      maxLength: 2048,
    },
    {
      label: "Authority type",
      name: "trustedIssuerAuthorityType",
      value: metadata.issuerAuthority?.authorityType,
      maxLength: 300,
    },
    {
      label: "Evidence name",
      name: "trustedEvidenceName",
      value: evidence?.name,
      maxLength: 300,
    },
    {
      label: "Evidence URL",
      name: "trustedEvidenceUri",
      value: evidence?.uri,
      type: "url",
      maxLength: 2048,
    },
    { label: "Result", name: "trustedResultValue", value: result?.value, maxLength: 300 },
    { label: "Result date", name: "trustedResultDate", value: result?.resultDate, type: "date" },
    {
      label: "Criteria URL",
      name: "trustedCriteriaUri",
      value: metadata.criteria?.uri ?? template.criteriaUri,
      type: "url",
      maxLength: 2048,
    },
    {
      label: "Assessment date",
      name: "trustedAssessmentDate",
      value: assessment?.assessmentDate,
      type: "date",
    },
    {
      label: "Achievement type",
      name: "trustedAchievementType",
      value: metadata.achievementType,
      maxLength: 300,
    },
    { label: "Rubric", name: "trustedRubricName", value: rubric?.name, maxLength: 300 },
    {
      label: "Rubric URL",
      name: "trustedRubricUri",
      value: rubric?.uri,
      type: "url",
      maxLength: 2048,
    },
    {
      label: "Duration",
      name: "trustedDurationValue",
      value: metadata.duration?.value,
      maxLength: 300,
    },
    {
      label: "Credits available",
      name: "trustedCreditsAvailable",
      value: metadata.credits?.available,
      maxLength: 300,
    },
    {
      label: "Credits earned",
      name: "trustedCreditsEarned",
      value: metadata.credits?.earned,
      maxLength: 300,
    },
    {
      label: "Endorser",
      name: "trustedEndorserName",
      value: endorsement?.endorserName,
      maxLength: 300,
    },
    {
      label: "Endorser URL",
      name: "trustedEndorserUri",
      value: endorsement?.endorserUri,
      type: "url",
      maxLength: 2048,
    },
  ];
  const textareaFields: TrustEdTextareaField[] = [
    {
      label: "Evidence description",
      name: "trustedEvidenceDescription",
      value: evidence?.description,
      rows: 2,
      maxLength: 4000,
    },
    {
      label: "Criteria summary",
      name: "trustedCriteriaText",
      value: metadata.criteria?.text,
      rows: 2,
      maxLength: 4000,
    },
    {
      label: "Assessment description",
      name: "trustedAssessmentDescription",
      value: assessment?.description,
      rows: 2,
      maxLength: 4000,
    },
  ];
  const evidenceDescriptionField = textareaFields[0];
  const criteriaSummaryField = textareaFields[1];
  const assessmentDescriptionField = textareaFields[2];

  if (
    evidenceDescriptionField === undefined ||
    criteriaSummaryField === undefined ||
    assessmentDescriptionField === undefined
  ) {
    throw new Error("TrustEd textarea field configuration is incomplete");
  }

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
          {textFields.slice(0, 12).map((field) => (
            <TrustEdTextField {...field} />
          ))}
          <TrustEdTextareaField {...evidenceDescriptionField} />
          {textFields.slice(12, 15).map((field) => (
            <TrustEdTextField {...field} />
          ))}
          <TrustEdTextareaField {...criteriaSummaryField} />
          {textFields.slice(15, 16).map((field) => (
            <TrustEdTextField {...field} />
          ))}
          <TrustEdTextareaField {...assessmentDescriptionField} />
          {textFields.slice(16).map((field) => (
            <TrustEdTextField {...field} />
          ))}
        </div>
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
