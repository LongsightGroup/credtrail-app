import type {
  BadgeTemplateImageRevisionRecord,
  BadgeTemplateRecord,
  TenantMembershipRole,
  TenantRecord,
} from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import {
  AdminActions,
  AdminButton,
  AdminButtonLink,
  AdminCheckboxRow,
  AdminEmptyTableRow,
  AdminField,
  AdminForm,
  AdminInlineActionPanel,
  AdminInlinePanelCloseButton,
  AdminInlinePanelTriggerButton,
  AdminListHeader,
  AdminPanel,
  AdminStatus,
  AdminTable,
} from "./components";
import type { BadgeTemplateHistoryTimelineEntry } from "../badges/badge-template-history";
import type { BadgeTemplateArtworkReadiness } from "../badges/badge-achievement-snapshot";
import {
  badgeTemplateHistoryHref,
  toBadgeTemplateClientRecord,
  type BadgeTemplateListPageQueryOptions,
} from "./badge-template-admin-helpers";
import {
  BadgeTemplateHistoryTimeline,
  BadgeTemplateImageRevisionList,
} from "./badge-template-history-panel";
import {
  badgeTemplateCriteriaRegistryHref,
  badgeTemplateShowcaseHref,
} from "../badges/badge-template-public-links";
import {
  BadgeTemplateEditorArtworkActions,
  BadgeTemplateEditorCurrentArtwork,
  BadgeTemplateEditorPreviewFrame,
  BadgeTemplateEditorReadyStatus,
} from "./badge-template-editor-artwork";
import { renderTrustEdCredentialPanel } from "./institution-admin-trusted-credential-panel";
import { BadgeTemplateAdminTableRow } from "./badge-template-table-row";
import {
  buildInstitutionAdminShellPaths,
  renderInstitutionAdminPageHeader,
  renderInstitutionAdminShellPage,
} from "./institution-admin-shell";
import type { AppPage } from "../ui/render-page";
import { CtFieldHint, CtInput, CtTextarea } from "../ui/forms";
import { formatIsoTimestamp } from "../utils/display-format";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

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
  badgeTemplateArtworkReadiness: BadgeTemplateArtworkReadiness;
  returnToRuleBuilder: boolean;
  listPageQuery?: BadgeTemplateListPageQueryOptions;
  detailsNotice?: { tone: "success" | "error"; message: string } | null;
  artworkNotice?: { tone: "success" | "error"; message: string } | null;
  switchOrganizationPath?: string | null;
}

const renderTemplateCreatePanel = (rulesTemplatesPath: string): HonoElement => {
  return (
    <AdminInlineActionPanel
      id="template-create-panel"
      title="Create badge template"
      description="Start with the badge name. CredTrail opens artwork setup after creation."
    >
      <AdminForm
        id="badge-template-create-form"
        method="post"
        action={rulesTemplatesPath}
        className="ct-admin__form ct-admin__inline-action-form ct-admin__inline-action-form--template-create ct-grid"
      >
        <AdminField label="Badge name">
          <CtInput
            name="title"
            type="text"
            required
            maxlength={200}
            autocomplete="off"
            describedBy="badge-template-create-title-hint"
          />
          <CtFieldHint id="badge-template-create-title-hint">
            The name administrators, learners, and public viewers will see.
          </CtFieldHint>
        </AdminField>
        <AdminField label="Description" className="ct-admin__template-create-field--wide">
          <CtTextarea
            name="description"
            rows={3}
            maxlength={2000}
            variant="prose"
            describedBy="badge-template-create-description-hint"
          />
          <CtFieldHint id="badge-template-create-description-hint">
            Optional short summary shown with issued badge records.
          </CtFieldHint>
        </AdminField>
        <div class="ct-admin__template-create-actions">
          <AdminButton type="submit">Create and add artwork</AdminButton>
          <AdminInlinePanelCloseButton panelId="template-create-panel">
            Cancel
          </AdminInlinePanelCloseButton>
        </div>
      </AdminForm>
      <p
        id="badge-template-create-status"
        class="ct-admin__status ct-admin__template-create-status"
        aria-live="polite"
      ></p>
    </AdminInlineActionPanel>
  );
};

const renderTemplateEditorFields = (input: {
  selectedTemplate: BadgeTemplateRecord;
  badgeTemplateArtworkReadiness: BadgeTemplateArtworkReadiness;
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
            <p>Name, description, and criteria used for future badge issuance.</p>
          </header>
          <AdminStatus data-tone="info">
            Existing credentials and governed rule versions keep the badge details, criteria,
            artwork, and trust metadata saved when they were issued or created. Changes here apply
            only to future direct issuance and future rule versions.
          </AdminStatus>
          {input.detailsNotice === null || input.detailsNotice === undefined ? null : (
            <AdminStatus id="badge-template-details-notice" data-tone={input.detailsNotice.tone}>
              {input.detailsNotice.message}
            </AdminStatus>
          )}
          <div class="ct-admin__template-editor-fields">
            <CtInput
              form="badge-template-edit-form"
              type="hidden"
              name="badgeTemplateId"
              value={template.id}
            />
            <AdminField label="Badge name">
              <CtInput
                form="badge-template-edit-form"
                name="title"
                type="text"
                required
                maxlength={200}
                value={template.title}
              />
            </AdminField>
            <AdminField label="Description">
              <CtTextarea
                form="badge-template-edit-form"
                name="description"
                rows={3}
                maxlength={2000}
                variant="prose"
                value={template.description ?? ""}
              />
            </AdminField>
            <AdminField label="Criteria page URL">
              <CtInput
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
            <p>This image is used for future issuance and future rule versions.</p>
          </header>
          {input.artworkNotice === null || input.artworkNotice === undefined ? null : (
            <AdminStatus id="badge-template-artwork-notice" data-tone={input.artworkNotice.tone}>
              {input.artworkNotice.message}
            </AdminStatus>
          )}
          <BadgeTemplateEditorCurrentArtwork
            template={template}
            artworkReadiness={input.badgeTemplateArtworkReadiness}
          />
          <BadgeTemplateEditorArtworkActions
            template={template}
            artworkReadiness={input.badgeTemplateArtworkReadiness}
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
              <dd>
                <span>{template.slug}</span>
                <details class="ct-admin__template-editor-advanced ct-admin__template-editor-inline-edit">
                  <summary aria-label="Edit URL key">Edit</summary>
                  <AdminField label="URL key">
                    <CtInput
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
              </dd>
            </div>
            <div>
              <dt>Activity</dt>
              <dd id="badge-template-editor-activity-summary">
                {revisionLabel}. Last updated {formatIsoTimestamp(template.updatedAt)}.
              </dd>
            </div>
          </dl>
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
      <AdminListHeader
        title={`Badge Templates (${String(input.badgeTemplates.length)})`}
        description="Template records, public links, and artwork maintenance live together here."
        action={
          <AdminInlinePanelTriggerButton panelId="template-create-panel">
            New badge template
          </AdminInlinePanelTriggerButton>
        }
      />
      {renderTemplateCreatePanel(input.rulesTemplatesPath)}
      <AdminForm
        method="get"
        action={input.rulesTemplatesPath}
        className="ct-admin__form ct-admin__form--inline ct-grid"
      >
        <AdminField label="Search">
          <CtInput
            name="q"
            type="search"
            value={input.badgeTemplatesPage.searchQuery}
            placeholder="Search badge templates"
          />
        </AdminField>
        <AdminCheckboxRow
          name="includeArchived"
          value="1"
          label="Include archived templates"
          checked={input.badgeTemplatesPage.includeArchived}
        />
        <AdminButton type="submit">Apply filters</AdminButton>
        {input.badgeTemplatesPage.searchQuery.length > 0 ||
        input.badgeTemplatesPage.includeArchived ? (
          <AdminButtonLink href={input.rulesTemplatesPath} variant="quiet">
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
          <AdminPanel className="ct-admin__template-editor-overview">
            <BadgeTemplateEditorPreviewFrame template={template} />
            <div class="ct-admin__template-editor-summary">
              <div>
                <div class="ct-admin__template-editor-title-row">
                  <h2>{template.title}</h2>
                  <BadgeTemplateEditorReadyStatus
                    template={template}
                    artworkReadiness={input.badgeTemplateArtworkReadiness}
                  />
                </div>
                <p>
                  {template.description ??
                    "Add a short description so learners and public viewers know what this badge represents."}
                </p>
              </div>
              <AdminActions>
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
                  variant="quiet"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  View criteria
                </AdminButtonLink>
              </AdminActions>
            </div>
          </AdminPanel>
          {renderTemplateEditorFields({
            selectedTemplate: template,
            badgeTemplateArtworkReadiness: input.badgeTemplateArtworkReadiness,
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
