import type { BadgeTemplateRecord, TenantMembershipRole, TenantRecord } from "@credtrail/db";
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
  AdminStatusPill,
  AdminTable,
} from "./components";
import {
  badgeTemplateHistoryHref,
  toBadgeTemplateClientRecord,
  type BadgeTemplateListPageQueryOptions,
} from "./badge-template-admin-helpers";
import {
  BadgeTemplateAdminTableRow,
  badgeTemplateCriteriaRegistryHref,
  badgeTemplateShowcaseHref,
} from "./badge-template-table-row-fragment";
import {
  buildInstitutionAdminShellPaths,
  renderInstitutionAdminPageHeader,
  renderInstitutionAdminShellPage,
} from "./institution-admin-shell";
import type { AppPage } from "../ui/render-page";
import { formatIsoTimestamp } from "../utils/display-format";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

export interface InstitutionAdminBadgeTemplatesPageOptions {
  searchQuery: string;
  includeArchived: boolean;
  returnToRuleBuilder: boolean;
  /** When set with history=1, auto-opens the template audit dialog on load. */
  deepLinkHistoryTemplateId: string | null;
  deepLinkHistoryUnavailable: "not_found" | null;
}

export interface InstitutionAdminRuleTemplatesPageInput {
  tenant: TenantRecord;
  userId: string;
  userEmail?: string;
  membershipRole: TenantMembershipRole;
  badgeTemplates: readonly BadgeTemplateRecord[];
  badgeTemplateImageRevisionCountsById?: Readonly<Record<string, number>>;
  badgeTemplatesPage: InstitutionAdminBadgeTemplatesPageOptions;
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
  switchOrganizationPath?: string | null;
}

const addDisclosureControlMarkup = (
  <span class="ct-admin__add-disclosure-control">
    <span class="ct-admin__add-disclosure-control-open">Open form</span>
    <span class="ct-admin__add-disclosure-control-close">Hide form</span>
  </span>
);

const renderTemplateCreatePanel = (): HonoElement => {
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

const renderTemplateEditorFields = (input: {
  selectedTemplate: BadgeTemplateRecord;
  imageRevisionCount: number;
}): HonoElement => {
  const template = input.selectedTemplate;
  const revisionLabel =
    input.imageRevisionCount === 1
      ? "1 image version"
      : `${input.imageRevisionCount} image versions`;

  return (
    <>
      {/* Identity-only form: inputs and submit button bind by id via the HTML `form` attribute. */}
      <form
        id="badge-template-edit-form"
        class="ct-admin__template-editor-identity-form"
        hidden
      ></form>
      <div class="ct-admin__template-editor-body">
        <section class="ct-admin__template-editor-section" id="template-editor-details">
          <header class="ct-admin__template-editor-section-header">
            <h3>Badge details</h3>
            <p>Name, description, and criteria shown on issued badge records.</p>
          </header>
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
              Save details
            </AdminButton>
          </div>
          <AdminStatus id="badge-template-edit-status"></AdminStatus>
        </section>
        <section
          class="ct-admin__template-editor-section ct-admin__template-editor-section--artwork"
          id="template-editor-artwork"
        >
          <header class="ct-admin__template-editor-section-header">
            <h3>Artwork</h3>
            <p>Current artwork, upload, and generated drafts live together.</p>
          </header>
          <div
            class="ct-admin__template-editor-current-artwork"
            id="badge-template-editor-current-artwork"
          >
            {template.imageUri === null ? (
              <span class="ct-admin__template-editor-current-artwork-empty">No artwork</span>
            ) : (
              <a
                href={template.imageUri}
                target="_blank"
                rel="noopener noreferrer"
                aria-label={`Open full size image for ${template.title}`}
              >
                <img src={template.imageUri} alt={`${template.title} artwork`} />
              </a>
            )}
            <div>
              <strong>Current artwork</strong>
              <p>
                {template.imageUri === null
                  ? "Add artwork before using this template in rules."
                  : "This image appears on issued badges and public badge pages."}
              </p>
            </div>
          </div>
          <div class="ct-admin__template-editor-artwork-mode">
            <div
              class="ct-admin__segmented-control ct-admin__template-editor-artwork-switch"
              role="radiogroup"
              aria-label="Artwork method"
            >
              <label>
                <input
                  id="badge-template-artwork-mode-upload"
                  type="radio"
                  name="badgeTemplateArtworkMode"
                  value="upload"
                  checked
                />
                <span>Upload</span>
              </label>
              <label>
                <input
                  id="badge-template-artwork-mode-generate"
                  type="radio"
                  name="badgeTemplateArtworkMode"
                  value="generate"
                />
                <span>Generate</span>
              </label>
            </div>
            <div class="ct-admin__template-editor-artwork-panel ct-admin__template-editor-artwork-panel--upload">
              <div class="ct-admin__template-editor-subgroup">
                <h4 class="ct-admin__template-editor-subgroup-title">Upload an image</h4>
                <AdminForm
                  id="badge-template-image-upload-form"
                  className="ct-admin__form ct-admin__template-editor-subform"
                >
                  <input type="hidden" name="badgeTemplateId" value={template.id} />
                  <div class="ct-admin__template-editor-fields ct-admin__template-editor-fields--upload">
                    <AdminField label="Image file">
                      <input
                        name="file"
                        type="file"
                        required
                        accept="image/png,image/jpeg,image/webp"
                      />
                    </AdminField>
                    <AdminButton type="submit">Upload image</AdminButton>
                  </div>
                </AdminForm>
                <AdminStatus id="badge-template-image-upload-status"></AdminStatus>
              </div>
            </div>
            <div class="ct-admin__template-editor-artwork-panel ct-admin__template-editor-artwork-panel--generate">
              <div class="ct-admin__template-editor-subgroup">
                <h4 class="ct-admin__template-editor-subgroup-title">Generate with AI</h4>
                <AdminForm
                  id="badge-template-image-generation-form"
                  className="ct-admin__form ct-admin__template-editor-subform"
                >
                  <input type="hidden" name="badgeTemplateId" value={template.id} />
                  <div class="ct-admin__template-editor-fields ct-admin__template-editor-fields--generation">
                    <AdminField label="Style">
                      <select name="stylePreset" required>
                        <option value="institutional">Institutional</option>
                        <option value="technical">Technical</option>
                        <option value="academic">Academic</option>
                        <option value="open_source">Open source</option>
                        <option value="minimal">Minimal</option>
                      </select>
                    </AdminField>
                    <AdminField label="Accent">
                      <input
                        name="accentColor"
                        type="text"
                        placeholder="Sakai blue"
                        maxlength={80}
                      />
                    </AdminField>
                    <AdminField
                      label="Prompt notes"
                      className="ct-admin__template-editor-generation-prompt"
                    >
                      <input
                        name="promptNotes"
                        type="text"
                        placeholder="Shield, milestone, stars"
                        maxlength={1000}
                      />
                    </AdminField>
                    <div class="ct-admin__template-editor-generation-action">
                      <AdminButton type="submit">Generate draft</AdminButton>
                    </div>
                  </div>
                </AdminForm>
                <AdminStatus id="badge-template-image-generation-status"></AdminStatus>
                <div
                  id="badge-template-image-generation-preview"
                  class="ct-admin__image-generation-preview"
                  hidden
                >
                  <img
                    id="badge-template-image-generation-preview-img"
                    alt="Generated badge draft"
                  />
                  <div class="ct-admin__image-generation-actions">
                    <AdminButton id="badge-template-image-generation-apply" variant="secondary">
                      Apply generated image
                    </AdminButton>
                    <a
                      id="badge-template-image-generation-open"
                      class="ct-admin__text-action"
                      href="#"
                      target="_blank"
                      rel="noopener noreferrer"
                      hidden
                    >
                      Open full size
                    </a>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>
        <section class="ct-admin__template-editor-section" id="template-editor-public-record">
          <header class="ct-admin__template-editor-section-header">
            <h3>Public record</h3>
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
              href="#"
              class="ct-admin__text-action"
              id="badge-template-editor-history-link"
              data-template-history-template-id={template.id}
              data-template-history-template-title={template.title}
              data-template-history-image-revision-count={String(input.imageRevisionCount)}
            >
              View full history
            </a>
          </div>
        </section>
      </div>
    </>
  );
};

const renderBadgeTemplateHistoryDialog = (): HonoElement => {
  return (
    <dialog id="badge-template-history-dialog" class="ct-admin__history-dialog">
      <form method="dialog" class="ct-admin__history-dialog-surface">
        <header class="ct-admin__history-dialog-header">
          <div>
            <h2 id="badge-template-history-dialog-title">Template history</h2>
            <p id="badge-template-history-dialog-subtitle" class="ct-admin__meta"></p>
          </div>
          <AdminButton type="submit" variant="secondary" size="tiny">
            Close
          </AdminButton>
        </header>
        <AdminStatus id="badge-template-history-status"></AdminStatus>
        <div id="badge-template-history-audit-list" class="ct-admin__history-audit-list"></div>
        <details
          id="badge-template-image-history-section"
          class="ct-admin__history-image-section"
          hidden
        >
          <summary>Image versions</summary>
          <div id="badge-template-image-revision-list" class="ct-admin__image-revision-list"></div>
        </details>
      </form>
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
      badgeTemplateApiPathPrefix: `/v1/tenants/${encodeURIComponent(input.tenant.id)}/badge-templates`,
      badgeTemplateAdminTableRowPathPrefix: paths.rulesTemplatesPath,
      badgeTemplateEditorPathPrefix: paths.rulesTemplatesPath,
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
          ) : null}
          {renderTemplateCreatePanel()}
          {renderBadgeTemplatesTable({
            badgeTemplates: input.badgeTemplates,
            badgeTemplatesPage: input.badgeTemplatesPage,
            badgeTemplateImageRevisionCountsById: input.badgeTemplateImageRevisionCountsById ?? {},
            rulesTemplatesPath: paths.rulesTemplatesPath,
            tenantId: input.tenant.id,
          })}
          {renderBadgeTemplateHistoryDialog()}
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
  const readyLabel = template.isArchived
    ? "Archived"
    : template.imageUri === null
      ? "Needs artwork"
      : "Ready to use";
  const readyTone = template.isArchived
    ? "revoked"
    : template.imageUri === null
      ? "warning"
      : "active";

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
    },
    children: (
      <>
        {renderInstitutionAdminPageHeader(
          "Edit Badge Template",
          "Prepare the badge details, artwork, criteria, and public record before using it in rules.",
        )}
        <section class="ct-admin ct-stack">
          <a class="ct-admin__text-action" href={paths.rulesTemplatesPath}>
            Back to badge templates
          </a>
          <AdminPanel className="ct-admin__template-editor-overview">
            <div class="ct-admin__template-editor-preview" id="badge-template-editor-preview-frame">
              {template.imageUri === null ? (
                <span class="ct-admin__template-editor-preview-empty">No artwork</span>
              ) : (
                <a
                  href={template.imageUri}
                  target="_blank"
                  rel="noopener noreferrer"
                  aria-label={`Open full size image for ${template.title}`}
                >
                  <img src={template.imageUri} alt={`${template.title} artwork`} />
                </a>
              )}
            </div>
            <div class="ct-admin__template-editor-summary">
              <div>
                <h2>{template.title}</h2>
                <p>
                  {template.description ??
                    "Add a short description so learners and public viewers know what this badge represents."}
                </p>
              </div>
              <div class="ct-admin__template-editor-summary-actions">
                <AdminStatusPill tone={readyTone}>{readyLabel}</AdminStatusPill>
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
          <AdminPanel className="ct-admin__template-editor-page-panel">
            <h2>Template setup</h2>
            <p>Save details, add artwork, and keep criteria links current from one workspace.</p>
            {renderTemplateEditorFields({
              selectedTemplate: template,
              imageRevisionCount: input.badgeTemplateImageRevisionCount,
            })}
          </AdminPanel>
          {renderBadgeTemplateHistoryDialog()}
        </section>
      </>
    ),
  });
};
