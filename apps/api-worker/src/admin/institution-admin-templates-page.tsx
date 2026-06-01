import type {
  BadgeTemplateImageRevisionRecord,
  BadgeTemplateRecord,
  TenantMembershipRole,
  TenantRecord,
} from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import {
  AdminButton,
  AdminButtonLink,
  AdminCheckboxRow,
  AdminEmptyTableRow,
  AdminField,
  AdminForm,
  AdminPanel,
  AdminStatus,
  AdminTable,
} from "./components";
import { adminStatusPillClass } from "./admin-status-pill-class";
import type { BadgeTemplateHistoryTimelineEntry } from "../badges/badge-template-history";
import {
  badgeTemplateHistoryHref,
  buildBadgeTemplateListPageQuery,
  toBadgeTemplateClientRecord,
  type BadgeTemplateListPageQueryOptions,
} from "./badge-template-admin-helpers";
import {
  BadgeTemplateHistoryTimeline,
  BadgeTemplateImageRevisionList,
} from "./badge-template-history-panel";
import {
  BadgeTemplateEditorArtworkActions,
  BadgeTemplateEditorCurrentArtwork,
  BadgeTemplateEditorPreviewFrame,
  BadgeTemplateEditorReadyStatus,
} from "./badge-template-editor-artwork";
import {
  emptyTrustEdCredentialMetadata,
  parseTrustEdCredentialMetadataJson,
} from "../badges/trusted-credential-metadata";
import { evaluateTrustEdCredentialReadiness } from "../badges/trusted-credential-readiness";
import type { TrustEdCredentialMetadata } from "@credtrail/validation";
import {
  BadgeTemplateAdminTableRow,
  badgeTemplateCriteriaRegistryHref,
  badgeTemplateShowcaseHref,
} from "./badge-template-table-row";
import {
  buildInstitutionAdminShellPaths,
  renderInstitutionAdminPageHeader,
  renderInstitutionAdminShellPage,
} from "./institution-admin-shell";
import type { AppPage } from "../ui/render-page";
import { formatIsoTimestamp } from "../utils/display-format";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

const trustEdMetadataForTemplate = (template: BadgeTemplateRecord): TrustEdCredentialMetadata => {
  return (
    parseTrustEdCredentialMetadataJson(template.trustedCredentialMetadataJson) ??
    emptyTrustEdCredentialMetadata()
  );
};

const trustEdReadinessMetadataForTemplate = (
  template: BadgeTemplateRecord,
): TrustEdCredentialMetadata | null => {
  return parseTrustEdCredentialMetadataJson(template.trustedCredentialMetadataJson);
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

const firstOrNull = <T,>(items: readonly T[]): T | null => {
  return items[0] ?? null;
};

export interface BadgeTemplateHistoryPanel {
  templateId: string;
  templateTitle: string;
  timeline: readonly BadgeTemplateHistoryTimelineEntry[];
  imageRevisionCount: number;
  revisions: readonly BadgeTemplateImageRevisionRecord[];
}

export interface InstitutionAdminBadgeTemplatesPageOptions {
  searchQuery: string;
  includeArchived: boolean;
  returnToRuleBuilder: boolean;
  /** When set with history=1, auto-opens the template audit dialog on load. */
  deepLinkHistoryTemplateId: string | null;
  deepLinkHistoryUnavailable: "not_found" | null;
  historyLoadError?: string | null;
  listNotice?: string | null;
  listError?: string | null;
}

export interface InstitutionAdminRuleTemplatesPageInput {
  tenant: TenantRecord;
  userId: string;
  userEmail?: string;
  membershipRole: TenantMembershipRole;
  badgeTemplates: readonly BadgeTemplateRecord[];
  badgeTemplateImageRevisionCountsById?: Readonly<Record<string, number>>;
  badgeTemplatesPage: InstitutionAdminBadgeTemplatesPageOptions;
  historyPanel?: BadgeTemplateHistoryPanel | null;
  switchOrganizationPath?: string | null;
}

export interface InstitutionAdminRuleTemplateEditorPageInput {
  tenant: TenantRecord;
  userId: string;
  userEmail?: string;
  membershipRole: TenantMembershipRole;
  badgeTemplate: BadgeTemplateRecord;
  badgeTemplateImageRevisionCount: number;
  returnToRuleBuilder: boolean;
  listPageQuery?: BadgeTemplateListPageQueryOptions;
  detailsNotice?: { tone: "success" | "error"; message: string } | null;
  artworkNotice?: { tone: "success" | "error"; message: string } | null;
  switchOrganizationPath?: string | null;
}

const addDisclosureControlMarkup = (
  <span class="ct-admin__add-disclosure-control">
    <span class="ct-admin__add-disclosure-control-open">Open form</span>
    <span class="ct-admin__add-disclosure-control-close">Hide form</span>
  </span>
);

const renderTemplateCreatePanel = (rulesTemplatesPath: string): HonoElement => {
  return (
    <details id="template-create-panel" class="ct-admin__panel ct-admin__add-disclosure">
      <summary class="ct-admin__add-disclosure-summary">
        <span>
          <strong>Create Badge Template</strong>
          <small>Start with the badge name. CredTrail opens artwork setup after creation.</small>
        </span>
        {addDisclosureControlMarkup}
      </summary>
      <AdminForm
        id="badge-template-create-form"
        method="post"
        action={rulesTemplatesPath}
        className="ct-admin__form ct-admin__add-disclosure-form ct-admin__add-disclosure-form--template-create ct-grid"
      >
        <AdminField label="Badge name">
          <input
            name="title"
            type="text"
            required
            maxlength={200}
            autocomplete="off"
            aria-describedby="badge-template-create-title-hint"
          />
          <span id="badge-template-create-title-hint" class="ct-admin__field-hint">
            The name administrators, learners, and public viewers will see.
          </span>
        </AdminField>
        <AdminField label="Description" className="ct-admin__template-create-field--wide">
          <textarea
            name="description"
            rows={3}
            maxlength={2000}
            aria-describedby="badge-template-create-description-hint"
          ></textarea>
          <span id="badge-template-create-description-hint" class="ct-admin__field-hint">
            Optional short summary shown with issued badge records.
          </span>
        </AdminField>
        <div class="ct-admin__template-create-actions">
          <AdminButton type="submit">Create and add artwork</AdminButton>
        </div>
      </AdminForm>
      <p
        id="badge-template-create-status"
        class="ct-admin__status ct-admin__template-create-status"
        aria-live="polite"
      ></p>
    </details>
  );
};

const renderTrustEdCredentialPanel = (template: BadgeTemplateRecord): HonoElement => {
  // v1 authoring exposes one row per repeatable field; saving writes at most one array entry.
  const metadata = trustEdMetadataForTemplate(template);
  const readiness = evaluateTrustEdCredentialReadiness(
    trustEdReadinessMetadataForTemplate(template),
  );
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
            Skills, evidence, results, assessment, and framework alignment for inspectable
            credentials.
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
      {missingRequired.length === 0 ? (
        <AdminStatus data-tone="success">
          Required TrustEd Credential metadata is present for this template.
        </AdminStatus>
      ) : (
        <AdminStatus data-tone="warning">
          Add the missing required metadata before issuing this as TrustEd-ready.
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
          <AdminField label="Skill">
            <input
              form="badge-template-edit-form"
              name="trustedSkillName"
              type="text"
              maxlength={300}
              value={skill?.name ?? ""}
            />
          </AdminField>
          <AdminField label="Skill URL">
            <input
              form="badge-template-edit-form"
              name="trustedSkillIdentifierUri"
              type="url"
              maxlength={2048}
              value={skill?.identifierUri ?? ""}
            />
          </AdminField>
          <AdminField label="Skill source">
            <input
              form="badge-template-edit-form"
              name="trustedSkillSource"
              type="text"
              maxlength={300}
              value={skill?.source ?? ""}
            />
          </AdminField>
          <AdminField label="Framework target">
            <input
              form="badge-template-edit-form"
              name="trustedFrameworkTargetName"
              type="text"
              maxlength={300}
              value={alignment?.targetName ?? ""}
            />
          </AdminField>
          <AdminField label="Framework target URL">
            <input
              form="badge-template-edit-form"
              name="trustedFrameworkTargetUri"
              type="url"
              maxlength={2048}
              value={alignment?.targetUri ?? ""}
            />
          </AdminField>
          <AdminField label="Framework name">
            <input
              form="badge-template-edit-form"
              name="trustedFrameworkName"
              type="text"
              maxlength={300}
              value={alignment?.frameworkName ?? ""}
            />
          </AdminField>
          <AdminField label="Framework URL">
            <input
              form="badge-template-edit-form"
              name="trustedFrameworkUri"
              type="url"
              maxlength={2048}
              value={alignment?.frameworkUri ?? ""}
            />
          </AdminField>
          <AdminField label="Awarding authority">
            <input
              form="badge-template-edit-form"
              name="trustedIssuerAuthorityName"
              type="text"
              maxlength={300}
              value={metadata.issuerAuthority?.name ?? ""}
            />
          </AdminField>
          <AdminField label="Authority URL">
            <input
              form="badge-template-edit-form"
              name="trustedIssuerAuthorityUri"
              type="url"
              maxlength={2048}
              value={metadata.issuerAuthority?.uri ?? ""}
            />
          </AdminField>
          <AdminField label="Authority type">
            <input
              form="badge-template-edit-form"
              name="trustedIssuerAuthorityType"
              type="text"
              maxlength={300}
              value={metadata.issuerAuthority?.authorityType ?? ""}
            />
          </AdminField>
          <AdminField label="Evidence name">
            <input
              form="badge-template-edit-form"
              name="trustedEvidenceName"
              type="text"
              maxlength={300}
              value={evidence?.name ?? ""}
            />
          </AdminField>
          <AdminField label="Evidence URL">
            <input
              form="badge-template-edit-form"
              name="trustedEvidenceUri"
              type="url"
              maxlength={2048}
              value={evidence?.uri ?? ""}
            />
          </AdminField>
          <AdminField label="Evidence description">
            <textarea
              form="badge-template-edit-form"
              name="trustedEvidenceDescription"
              rows={2}
              maxlength={4000}
            >
              {evidence?.description ?? ""}
            </textarea>
          </AdminField>
          <AdminField label="Result">
            <input
              form="badge-template-edit-form"
              name="trustedResultValue"
              type="text"
              maxlength={300}
              value={result?.value ?? ""}
            />
          </AdminField>
          <AdminField label="Result date">
            <input
              form="badge-template-edit-form"
              name="trustedResultDate"
              type="date"
              value={result?.resultDate ?? ""}
            />
          </AdminField>
          <AdminField label="Criteria summary">
            <textarea
              form="badge-template-edit-form"
              name="trustedCriteriaText"
              rows={2}
              maxlength={4000}
            >
              {metadata.criteria?.text ?? ""}
            </textarea>
          </AdminField>
          <AdminField label="Criteria URL">
            <input
              form="badge-template-edit-form"
              name="trustedCriteriaUri"
              type="url"
              maxlength={2048}
              value={metadata.criteria?.uri ?? template.criteriaUri ?? ""}
            />
          </AdminField>
          <AdminField label="Assessment description">
            <textarea
              form="badge-template-edit-form"
              name="trustedAssessmentDescription"
              rows={2}
              maxlength={4000}
            >
              {assessment?.description ?? ""}
            </textarea>
          </AdminField>
          <AdminField label="Assessment date">
            <input
              form="badge-template-edit-form"
              name="trustedAssessmentDate"
              type="date"
              value={assessment?.assessmentDate ?? ""}
            />
          </AdminField>
          <AdminField label="Achievement type">
            <input
              form="badge-template-edit-form"
              name="trustedAchievementType"
              type="text"
              maxlength={300}
              value={metadata.achievementType ?? ""}
            />
          </AdminField>
          <AdminField label="Rubric">
            <input
              form="badge-template-edit-form"
              name="trustedRubricName"
              type="text"
              maxlength={300}
              value={rubric?.name ?? ""}
            />
          </AdminField>
          <AdminField label="Rubric URL">
            <input
              form="badge-template-edit-form"
              name="trustedRubricUri"
              type="url"
              maxlength={2048}
              value={rubric?.uri ?? ""}
            />
          </AdminField>
          <AdminField label="Duration">
            <input
              form="badge-template-edit-form"
              name="trustedDurationValue"
              type="text"
              maxlength={300}
              value={metadata.duration?.value ?? ""}
            />
          </AdminField>
          <AdminField label="Credits available">
            <input
              form="badge-template-edit-form"
              name="trustedCreditsAvailable"
              type="text"
              maxlength={300}
              value={metadata.credits?.available ?? ""}
            />
          </AdminField>
          <AdminField label="Credits earned">
            <input
              form="badge-template-edit-form"
              name="trustedCreditsEarned"
              type="text"
              maxlength={300}
              value={metadata.credits?.earned ?? ""}
            />
          </AdminField>
          <AdminField label="Endorser">
            <input
              form="badge-template-edit-form"
              name="trustedEndorserName"
              type="text"
              maxlength={300}
              value={endorsement?.endorserName ?? ""}
            />
          </AdminField>
          <AdminField label="Endorser URL">
            <input
              form="badge-template-edit-form"
              name="trustedEndorserUri"
              type="url"
              maxlength={2048}
              value={endorsement?.endorserUri ?? ""}
            />
          </AdminField>
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

const renderTemplateEditorFields = (input: {
  selectedTemplate: BadgeTemplateRecord;
  imageRevisionCount: number;
  rulesTemplatesPath: string;
  templateHistoryHref: string;
  detailsNotice?: { tone: "success" | "error"; message: string } | null;
  artworkNotice?: { tone: "success" | "error"; message: string } | null;
}): HonoElement => {
  const template = input.selectedTemplate;
  const detailsFormAction = `${input.rulesTemplatesPath}/${encodeURIComponent(template.id)}/details`;
  const imageUploadPath = `${input.rulesTemplatesPath}/${encodeURIComponent(template.id)}/image-upload`;
  const imageApplyPath = `${input.rulesTemplatesPath}/${encodeURIComponent(template.id)}/image-generations/apply`;
  const revisionLabel =
    input.imageRevisionCount === 1
      ? "1 image version"
      : `${input.imageRevisionCount} image versions`;
  return (
    <>
      {/* Identity-only form: inputs and submit button bind by id via the HTML `form` attribute. */}
      <form
        id="badge-template-edit-form"
        method="post"
        action={detailsFormAction}
        class="ct-admin__template-editor-identity-form"
        hidden
      ></form>
      <div class="ct-admin__template-editor-body">
        <AdminPanel
          as="section"
          id="template-editor-details"
          className="ct-admin__template-editor-page-panel ct-admin__template-editor-section"
        >
          <header class="ct-admin__template-editor-section-header">
            <h2>Template details</h2>
            <p>Name, description, and criteria shown on issued badge records.</p>
          </header>
          {input.detailsNotice === null || input.detailsNotice === undefined ? null : (
            <AdminStatus id="badge-template-details-notice" data-tone={input.detailsNotice.tone}>
              {input.detailsNotice.message}
            </AdminStatus>
          )}
          <div class="ct-admin__template-editor-fields">
            <input
              form="badge-template-edit-form"
              type="hidden"
              name="badgeTemplateId"
              value={template.id}
            />
            <AdminField label="Badge name">
              <input
                form="badge-template-edit-form"
                name="title"
                type="text"
                required
                maxlength={200}
                value={template.title}
              />
            </AdminField>
            <AdminField label="Description">
              <textarea
                form="badge-template-edit-form"
                class="ct-admin__template-editor-prose-textarea"
                name="description"
                rows={3}
                maxlength={2000}
              >
                {template.description ?? ""}
              </textarea>
            </AdminField>
            <AdminField label="Criteria page URL">
              <input
                form="badge-template-edit-form"
                name="criteriaUri"
                type="url"
                maxlength={2048}
                value={template.criteriaUri ?? ""}
              />
            </AdminField>
          </div>
          <div class="ct-admin__template-editor-submit">
            <AdminButton form="badge-template-edit-form" type="submit">
              Save template details
            </AdminButton>
          </div>
        </AdminPanel>
        {renderTrustEdCredentialPanel(template)}
        <AdminPanel
          as="section"
          id="template-editor-artwork"
          className="ct-admin__template-editor-page-panel ct-admin__template-editor-section ct-admin__template-editor-section--artwork"
        >
          <header class="ct-admin__template-editor-section-header">
            <h2>Artwork</h2>
            <p>One approved image is used for issued badges and public badge pages.</p>
          </header>
          {input.artworkNotice === null || input.artworkNotice === undefined ? null : (
            <AdminStatus id="badge-template-artwork-notice" data-tone={input.artworkNotice.tone}>
              {input.artworkNotice.message}
            </AdminStatus>
          )}
          <BadgeTemplateEditorCurrentArtwork template={template} />
          <BadgeTemplateEditorArtworkActions
            template={template}
            imageUploadPath={imageUploadPath}
            imageApplyPath={imageApplyPath}
          />
        </AdminPanel>
        <AdminPanel
          as="section"
          id="template-editor-public-record"
          className="ct-admin__template-editor-page-panel ct-admin__template-editor-section"
        >
          <header class="ct-admin__template-editor-section-header">
            <h2>Public record</h2>
            <p>Public pages, URL key, and edit history for this template.</p>
          </header>
          <dl class="ct-admin__template-editor-meta-list">
            <div>
              <dt>URL key</dt>
              <dd>{template.slug}</dd>
            </div>
            <div>
              <dt>Activity</dt>
              <dd id="badge-template-editor-activity-summary">
                {revisionLabel}. Last updated {formatIsoTimestamp(template.updatedAt)}.
              </dd>
            </div>
          </dl>
          <details class="ct-admin__template-editor-advanced">
            <summary>Edit URL key</summary>
            <AdminField label="URL key">
              <input
                form="badge-template-edit-form"
                name="slug"
                type="text"
                required
                maxlength={120}
                value={template.slug}
              />
            </AdminField>
            <div class="ct-admin__template-editor-submit">
              <AdminButton form="badge-template-edit-form" type="submit" variant="secondary">
                Save URL key
              </AdminButton>
            </div>
          </details>
          <div class="ct-admin__template-editor-link-row">
            <a
              id="badge-template-editor-public-link"
              class="ct-admin__text-action"
              href={badgeTemplateShowcaseHref(template.tenantId, template.id)}
              target="_blank"
              rel="noopener noreferrer"
            >
              View public badge page ↗
            </a>
            <a
              id="badge-template-editor-criteria-link"
              class="ct-admin__text-action"
              href={badgeTemplateCriteriaRegistryHref(template.tenantId, template.id)}
              target="_blank"
              rel="noopener noreferrer"
            >
              View public criteria page ↗
            </a>
            <a
              href={input.templateHistoryHref}
              class="ct-admin__text-action"
              id="badge-template-editor-history-link"
            >
              View full history
            </a>
          </div>
        </AdminPanel>
      </div>
    </>
  );
};

const renderBadgeTemplateHistoryDialog = (input: {
  rulesTemplatesPath: string;
  historyPanel: BadgeTemplateHistoryPanel | null;
  listPageQuery: BadgeTemplateListPageQueryOptions;
  historyLoadError?: string | null;
  autoOpenHistoryTemplateId?: string | null;
}): HonoElement => {
  const panel = input.historyPanel;
  const imageRevisionCount = panel?.imageRevisionCount ?? 0;
  const restorePathPrefix =
    panel === null
      ? ""
      : `${input.rulesTemplatesPath}/${encodeURIComponent(panel.templateId)}/image-revisions`;
  const autoOpenHistoryTemplateId = input.autoOpenHistoryTemplateId ?? panel?.templateId ?? "";

  return (
    <dialog
      id="badge-template-history-dialog"
      class="ct-admin__history-dialog"
      data-auto-open-history-template-id={autoOpenHistoryTemplateId}
    >
      <div class="ct-admin__history-dialog-surface">
        <header class="ct-admin__history-dialog-header">
          <div>
            <h2 id="badge-template-history-dialog-title">Template history</h2>
            <p id="badge-template-history-dialog-subtitle" class="ct-admin__meta">
              {panel === null ? "" : panel.templateTitle}
            </p>
          </div>
          <AdminButton
            type="button"
            id="badge-template-history-dialog-close"
            variant="secondary"
            size="tiny"
          >
            Close
          </AdminButton>
        </header>
        {input.historyLoadError !== null &&
        input.historyLoadError !== undefined &&
        input.historyLoadError.length > 0 ? (
          <AdminStatus id="badge-template-history-status" data-tone="error">
            {input.historyLoadError}
          </AdminStatus>
        ) : panel === null ? (
          <AdminStatus id="badge-template-history-status"></AdminStatus>
        ) : (
          <AdminStatus id="badge-template-history-status" data-tone="success">
            Showing recent changes for this template.
          </AdminStatus>
        )}
        <div id="badge-template-history-audit-list" class="ct-admin__history-audit-list">
          {panel === null ? null : <BadgeTemplateHistoryTimeline timeline={panel.timeline} />}
        </div>
        <details
          id="badge-template-image-history-section"
          class="ct-admin__history-image-section"
          hidden={imageRevisionCount === 0}
          open={imageRevisionCount > 0}
        >
          <summary>
            Image versions
            {panel !== null && panel.imageRevisionCount > panel.revisions.length
              ? ` (showing latest ${String(panel.revisions.length)} of ${String(panel.imageRevisionCount)})`
              : null}
          </summary>
          <div id="badge-template-image-revision-list" class="ct-admin__image-revision-list">
            {panel === null ? null : (
              <BadgeTemplateImageRevisionList
                revisions={panel.revisions}
                restorePathPrefix={restorePathPrefix}
                listPageQuery={input.listPageQuery}
              />
            )}
          </div>
        </details>
      </div>
    </dialog>
  );
};

const listPageQueryOptions = (
  badgeTemplatesPage: InstitutionAdminBadgeTemplatesPageOptions,
): BadgeTemplateListPageQueryOptions => {
  return {
    searchQuery: badgeTemplatesPage.searchQuery,
    includeArchived: badgeTemplatesPage.includeArchived,
    returnToRuleBuilder: badgeTemplatesPage.returnToRuleBuilder,
  };
};

const renderBadgeTemplatesTable = (input: {
  badgeTemplates: readonly BadgeTemplateRecord[];
  badgeTemplatesPage: InstitutionAdminBadgeTemplatesPageOptions;
  badgeTemplateImageRevisionCountsById: Readonly<Record<string, number>>;
  rulesTemplatesPath: string;
  tenantId: string;
}): HonoElement => {
  const listPageQuery = listPageQueryOptions(input.badgeTemplatesPage);
  const templateRows =
    input.badgeTemplates.length === 0 ? (
      <AdminEmptyTableRow colSpan={5}>
        {input.badgeTemplatesPage.searchQuery.length > 0 || input.badgeTemplatesPage.includeArchived
          ? "No badge templates match these filters."
          : "No badge templates found."}
      </AdminEmptyTableRow>
    ) : (
      input.badgeTemplates.map((template) => {
        const imageRevisionCount = input.badgeTemplateImageRevisionCountsById[template.id] ?? 0;
        return (
          <BadgeTemplateAdminTableRow
            tenantId={input.tenantId}
            template={template}
            imageRevisionCount={imageRevisionCount}
            historyHref={badgeTemplateHistoryHref(
              input.rulesTemplatesPath,
              template.id,
              listPageQuery,
            )}
            rulesTemplatesPath={input.rulesTemplatesPath}
            listPageQuery={listPageQuery}
          />
        );
      })
    );

  return (
    <AdminPanel variant="table">
      <h2>Badge Templates ({String(input.badgeTemplates.length)})</h2>
      <p>Template records, public links, and artwork maintenance live together here.</p>
      <AdminForm
        method="get"
        action={input.rulesTemplatesPath}
        className="ct-admin__form ct-admin__form--inline ct-grid"
      >
        <AdminField label="Search">
          <input
            name="q"
            type="search"
            value={input.badgeTemplatesPage.searchQuery}
            placeholder="Search badge templates"
          />
        </AdminField>
        <AdminCheckboxRow>
          <input
            type="checkbox"
            name="includeArchived"
            value="1"
            checked={input.badgeTemplatesPage.includeArchived}
          />
          Include archived templates
        </AdminCheckboxRow>
        <AdminButton type="submit">Apply filters</AdminButton>
        {input.badgeTemplatesPage.searchQuery.length > 0 ||
        input.badgeTemplatesPage.includeArchived ? (
          <AdminButtonLink href={input.rulesTemplatesPath} variant="ghost">
            Clear filters
          </AdminButtonLink>
        ) : null}
      </AdminForm>
      <AdminStatus id="badge-template-table-status" aria-live="polite"></AdminStatus>
      <AdminTable
        tbodyId="badge-template-table-body"
        headers={["Image", "Template", "Status", "Updated", "Actions"]}
      >
        {templateRows}
      </AdminTable>
    </AdminPanel>
  );
};

export const institutionAdminRuleTemplatesPage = (
  input: InstitutionAdminRuleTemplatesPageInput,
): AppPage => {
  const paths = buildInstitutionAdminShellPaths(input.tenant.id);
  const listPageQuery = listPageQueryOptions(input.badgeTemplatesPage);
  const badgeTemplateRecords = input.badgeTemplates.map(toBadgeTemplateClientRecord);

  return renderInstitutionAdminShellPage({
    tenant: input.tenant,
    userId: input.userId,
    ...(input.userEmail === undefined ? {} : { userEmail: input.userEmail }),
    membershipRole: input.membershipRole,
    view: "rulesTemplates",
    title: `Badge Templates · Rules · Institution Admin · ${input.tenant.displayName}`,
    assets: [
      "institutionAdminCss",
      "institutionAdminShellJs",
      "institutionAdminBadgeTemplateListJs",
    ],
    ...(input.switchOrganizationPath === undefined
      ? {}
      : { switchOrganizationPath: input.switchOrganizationPath }),
    contextJson: {
      tenantAdminPath: paths.tenantAdminPath,
      badgeTemplateEditorPathPrefix: paths.rulesTemplatesPath,
      badgeTemplateListPagePath: paths.rulesTemplatesPath,
      ruleBuilderPath: paths.ruleBuilderPath,
      showcasePath: paths.showcasePath,
      badgeTemplateListPageQuery: listPageQuery,
      badgeTemplateRecords,
      // Avoids the substring "History" in JSON keys (breaks unrelated page tests).
      autoOpenTemplateAuditTemplateId: input.badgeTemplatesPage.deepLinkHistoryTemplateId,
    },
    children: (
      <>
        {renderInstitutionAdminPageHeader(
          "Badge Templates",
          "Manage template records, artwork, and public template links without crowding the rules overview.",
        )}
        <section class="ct-admin ct-stack">
          {input.badgeTemplatesPage.deepLinkHistoryUnavailable === "not_found" ? (
            <AdminStatus id="badge-template-history-deeplink-status" data-tone="error">
              The requested template history link does not match a badge template in this tenant.
            </AdminStatus>
          ) : input.badgeTemplatesPage.historyLoadError !== null &&
            input.badgeTemplatesPage.historyLoadError !== undefined &&
            input.badgeTemplatesPage.historyLoadError.length > 0 ? (
            <AdminStatus id="badge-template-history-deeplink-status" data-tone="error">
              {input.badgeTemplatesPage.historyLoadError}
            </AdminStatus>
          ) : null}
          {input.badgeTemplatesPage.listError !== null &&
          input.badgeTemplatesPage.listError !== undefined &&
          input.badgeTemplatesPage.listError.length > 0 ? (
            <AdminStatus id="badge-template-list-notice" data-tone="error">
              {input.badgeTemplatesPage.listError}
            </AdminStatus>
          ) : input.badgeTemplatesPage.listNotice !== null &&
            input.badgeTemplatesPage.listNotice !== undefined &&
            input.badgeTemplatesPage.listNotice.length > 0 ? (
            <AdminStatus id="badge-template-list-notice" data-tone="success">
              {input.badgeTemplatesPage.listNotice}
            </AdminStatus>
          ) : null}
          {renderTemplateCreatePanel(paths.rulesTemplatesPath)}
          {renderBadgeTemplatesTable({
            badgeTemplates: input.badgeTemplates,
            badgeTemplatesPage: input.badgeTemplatesPage,
            badgeTemplateImageRevisionCountsById: input.badgeTemplateImageRevisionCountsById ?? {},
            rulesTemplatesPath: paths.rulesTemplatesPath,
            tenantId: input.tenant.id,
          })}
          {renderBadgeTemplateHistoryDialog({
            rulesTemplatesPath: paths.rulesTemplatesPath,
            historyPanel: input.historyPanel ?? null,
            listPageQuery,
            historyLoadError: input.badgeTemplatesPage.historyLoadError ?? null,
            autoOpenHistoryTemplateId: input.badgeTemplatesPage.deepLinkHistoryTemplateId,
          })}
        </section>
      </>
    ),
  });
};

export const institutionAdminRuleTemplateEditorPage = (
  input: InstitutionAdminRuleTemplateEditorPageInput,
): AppPage => {
  const paths = buildInstitutionAdminShellPaths(input.tenant.id);
  const template = input.badgeTemplate;
  const badgeTemplateRecords = [toBadgeTemplateClientRecord(template)];
  const listPageQuery = {
    searchQuery: input.listPageQuery?.searchQuery ?? "",
    includeArchived: (input.listPageQuery?.includeArchived ?? false) || template.isArchived,
    returnToRuleBuilder: input.listPageQuery?.returnToRuleBuilder ?? input.returnToRuleBuilder,
  };
  const listPageQueryString = buildBadgeTemplateListPageQuery(listPageQuery).toString();
  const rulesTemplatesHref =
    listPageQueryString.length > 0
      ? `${paths.rulesTemplatesPath}?${listPageQueryString}`
      : paths.rulesTemplatesPath;
  const templateHistoryHref = badgeTemplateHistoryHref(
    paths.rulesTemplatesPath,
    template.id,
    listPageQuery,
  );

  return renderInstitutionAdminShellPage({
    tenant: input.tenant,
    userId: input.userId,
    ...(input.userEmail === undefined ? {} : { userEmail: input.userEmail }),
    membershipRole: input.membershipRole,
    view: "rulesTemplates",
    title: `${template.title} · Badge Template · Institution Admin · ${input.tenant.displayName}`,
    assets: [
      "institutionAdminCss",
      "institutionAdminTemplateEditorCss",
      "institutionAdminShellJs",
      "institutionAdminBadgeTemplateEditorJs",
    ],
    ...(input.switchOrganizationPath === undefined
      ? {}
      : { switchOrganizationPath: input.switchOrganizationPath }),
    contextJson: {
      tenantAdminPath: paths.tenantAdminPath,
      badgeTemplateApiPathPrefix: `/v1/tenants/${encodeURIComponent(input.tenant.id)}/badge-templates`,
      badgeTemplateEditorPathPrefix: paths.rulesTemplatesPath,
      ruleBuilderPath: paths.ruleBuilderPath,
      showcasePath: paths.showcasePath,
      badgeTemplateRecords,
      autoOpenTemplateAuditTemplateId: null,
      templateHistoryHref,
    },
    children: (
      <>
        {renderInstitutionAdminPageHeader(
          "Edit Badge Template",
          "Prepare the badge details, artwork, criteria, and public record before using it in rules.",
        )}
        <section class="ct-admin ct-stack">
          <a class="ct-admin__text-action" href={rulesTemplatesHref}>
            Back to badge templates
          </a>
          <AdminPanel className="ct-admin__template-editor-overview">
            <BadgeTemplateEditorPreviewFrame template={template} />
            <div class="ct-admin__template-editor-summary">
              <div>
                <div class="ct-admin__template-editor-title-row">
                  <h2>{template.title}</h2>
                  <BadgeTemplateEditorReadyStatus template={template} />
                </div>
                <p>
                  {template.description ??
                    "Add a short description so learners and public viewers know what this badge represents."}
                </p>
              </div>
              <div class="ct-admin__template-editor-summary-actions">
                <AdminButtonLink
                  href={badgeTemplateShowcaseHref(input.tenant.id, template.id)}
                  variant="secondary"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  View public page
                </AdminButtonLink>
                <AdminButtonLink
                  href={badgeTemplateCriteriaRegistryHref(input.tenant.id, template.id)}
                  variant="ghost"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  View criteria
                </AdminButtonLink>
              </div>
            </div>
          </AdminPanel>
          {renderTemplateEditorFields({
            selectedTemplate: template,
            imageRevisionCount: input.badgeTemplateImageRevisionCount,
            rulesTemplatesPath: paths.rulesTemplatesPath,
            templateHistoryHref,
            detailsNotice: input.detailsNotice ?? null,
            artworkNotice: input.artworkNotice ?? null,
          })}
          {renderBadgeTemplateHistoryDialog({
            rulesTemplatesPath: paths.rulesTemplatesPath,
            historyPanel: null,
            listPageQuery,
          })}
        </section>
      </>
    ),
  });
};
