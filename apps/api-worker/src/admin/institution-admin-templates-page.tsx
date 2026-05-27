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
  AdminTable,
} from "./components";
import { BadgeTemplateAdminTableRow } from "./badge-template-table-row-fragment";
import {
  buildInstitutionAdminShellPaths,
  renderInstitutionAdminPageHeader,
  renderInstitutionAdminShellPage,
} from "./institution-admin-shell";
import type { AppPage } from "../ui/render-page";

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

const addDisclosureControlMarkup = (
  <span class="ct-admin__add-disclosure-control">
    <span class="ct-admin__add-disclosure-control-open">Open form</span>
    <span class="ct-admin__add-disclosure-control-close">Hide form</span>
  </span>
);

const renderTemplateSelectOptions = (
  badgeTemplates: readonly BadgeTemplateRecord[],
): HonoElement => {
  return (
    <>
      {badgeTemplates.map((template, index) => (
        <option value={template.id} selected={index === 0}>
          {`${template.title} (${template.id})`}
        </option>
      ))}
    </>
  );
};

const renderTemplateCreatePanel = (input: {
  ruleBuilderPath: string;
  showcasePath: string;
}): HonoElement => {
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
      <div
        id="badge-template-create-next-actions"
        class="ct-admin__template-create-next-actions"
        hidden
        data-artwork-ready="false"
      >
        <p id="badge-template-create-next-copy">
          Add badge artwork next, then use this template in a rule.
        </p>
        <div class="ct-admin__template-create-next-action-row">
          <AdminButton
            type="button"
            variant="secondary"
            className="ct-admin__template-create-artwork-action"
            dataAttributes={{ "data-template-create-artwork-template-id": "" }}
          >
            Add artwork
          </AdminButton>
          <AdminButtonLink
            href={input.ruleBuilderPath}
            variant="secondary"
            className="ct-admin__template-create-rule-action"
            dataAttributes={{ "data-template-create-rule-link": "" }}
          >
            Use in a rule
          </AdminButtonLink>
          <AdminButtonLink
            href={input.showcasePath}
            variant="ghost"
            className="ct-admin__template-create-public-action"
            target="_blank"
            rel="noopener noreferrer"
            dataAttributes={{ "data-template-create-public-link": "" }}
          >
            View public page
          </AdminButtonLink>
        </div>
      </div>
    </details>
  );
};

const renderTemplateEditorPanel = (input: { templateSelectOptions: HonoElement }): HonoElement => {
  return (
    <details id="template-edit-panel" class="ct-admin__panel ct-admin__add-disclosure" hidden>
      <summary class="ct-admin__add-disclosure-summary">
        <span>
          <strong>Edit Badge Template</strong>
          <small>
            Update details, artwork, criteria, public links, and activity for the selected template.
          </small>
        </span>
        {addDisclosureControlMarkup}
      </summary>
      {/* Identity-only form: inputs and submit button bind by id via the HTML `form` attribute. */}
      <form
        id="badge-template-edit-form"
        class="ct-admin__template-editor-identity-form"
        hidden
      ></form>
      <div class="ct-admin__template-editor-body">
        <section class="ct-admin__template-editor-section" id="template-editor-details">
          <header class="ct-admin__template-editor-section-header">
            <h3>Details</h3>
            <p>Name and description shown on issued badge records.</p>
          </header>
          <div class="ct-admin__template-editor-fields">
            <AdminField label="Badge template">
              <select form="badge-template-edit-form" name="badgeTemplateId" required>
                {input.templateSelectOptions}
              </select>
            </AdminField>
            <AdminField label="Badge name">
              <input
                form="badge-template-edit-form"
                name="title"
                type="text"
                required
                maxlength={200}
              />
            </AdminField>
            <details class="ct-admin__template-editor-advanced">
              <summary>Advanced URL settings</summary>
              <AdminField label="URL key">
                <input
                  form="badge-template-edit-form"
                  name="slug"
                  type="text"
                  required
                  maxlength={120}
                />
              </AdminField>
            </details>
            <AdminField label="Description">
              <textarea
                form="badge-template-edit-form"
                class="ct-admin__template-editor-prose-textarea"
                name="description"
                rows={3}
                maxlength={2000}
              ></textarea>
            </AdminField>
          </div>
        </section>
        <section
          class="ct-admin__template-editor-section ct-admin__template-editor-section--artwork"
          id="template-editor-artwork"
        >
          <header class="ct-admin__template-editor-section-header">
            <h3>Artwork</h3>
            <p>Upload an image or generate one with AI before using the template in rules.</p>
          </header>
          <div class="ct-admin__template-editor-subgroup">
            <h4 class="ct-admin__template-editor-subgroup-title">Upload an image</h4>
            <AdminForm
              id="badge-template-image-upload-form"
              className="ct-admin__form ct-admin__template-editor-subform"
            >
              <input type="hidden" name="badgeTemplateId" value="" />
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
          <hr class="ct-admin__template-editor-divider" aria-hidden="true" />
          <div class="ct-admin__template-editor-subgroup">
            <h4 class="ct-admin__template-editor-subgroup-title">Or generate with AI</h4>
            <AdminForm
              id="badge-template-image-generation-form"
              className="ct-admin__form ct-admin__template-editor-subform"
            >
              <input type="hidden" name="badgeTemplateId" value="" />
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
                  <input name="accentColor" type="text" placeholder="Sakai blue" maxlength={80} />
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
              <img id="badge-template-image-generation-preview-img" alt="Generated badge draft" />
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
        </section>
        <section class="ct-admin__template-editor-section" id="template-editor-criteria">
          <header class="ct-admin__template-editor-section-header">
            <h3>Criteria</h3>
            <p>Where public viewers confirm what the badge represents.</p>
          </header>
          <div class="ct-admin__template-editor-fields">
            <AdminField label="Criteria page URL">
              <input
                form="badge-template-edit-form"
                name="criteriaUri"
                type="url"
                maxlength={2048}
              />
            </AdminField>
            <a
              id="badge-template-editor-criteria-link"
              class="ct-admin__text-action"
              href="#"
              target="_blank"
              rel="noopener noreferrer"
            >
              View public criteria page ↗
            </a>
          </div>
        </section>
        <section class="ct-admin__template-editor-section" id="template-editor-visibility">
          <header class="ct-admin__template-editor-section-header">
            <h3>Visibility</h3>
            <p>Preview the public badge page for this template.</p>
          </header>
          <a
            id="badge-template-editor-public-link"
            class="ct-admin__text-action"
            href="#"
            target="_blank"
            rel="noopener noreferrer"
          >
            View public badge page ↗
          </a>
        </section>
        <section class="ct-admin__template-editor-section" id="template-editor-activity">
          <header class="ct-admin__template-editor-section-header">
            <h3>Activity</h3>
            <p id="badge-template-editor-activity-summary">Select a template to review activity.</p>
          </header>
          <a
            href="#"
            class="ct-admin__text-action"
            id="badge-template-editor-history-link"
            data-template-history-template-id=""
            data-template-history-template-title=""
            data-template-history-image-revision-count="0"
          >
            View full history
          </a>
        </section>
        <div class="ct-admin__template-editor-submit">
          <AdminButton form="badge-template-edit-form" type="submit">
            Save details
          </AdminButton>
        </div>
        <AdminStatus id="badge-template-edit-status"></AdminStatus>
      </div>
    </details>
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

const renderBadgeTemplatesTable = (input: {
  badgeTemplates: readonly BadgeTemplateRecord[];
  badgeTemplatesPage: InstitutionAdminBadgeTemplatesPageOptions;
  badgeTemplateImageRevisionCountsById: Readonly<Record<string, number>>;
  rulesTemplatesPath: string;
  tenantId: string;
}): HonoElement => {
  const templateHistoryHref = (badgeTemplateId: string): string => {
    const query = new URLSearchParams();

    if (input.badgeTemplatesPage.searchQuery.length > 0) {
      query.set("q", input.badgeTemplatesPage.searchQuery);
    }

    if (input.badgeTemplatesPage.includeArchived) {
      query.set("includeArchived", "1");
    }

    if (input.badgeTemplatesPage.returnToRuleBuilder) {
      query.set("returnTo", "rule-builder");
    }

    query.set("badgeTemplateId", badgeTemplateId);
    query.set("history", "1");

    return `${input.rulesTemplatesPath}?${query.toString()}`;
  };
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
            historyHref={templateHistoryHref(template.id)}
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
  const templateSelectOptions = renderTemplateSelectOptions(input.badgeTemplates);
  const badgeTemplateRecords = input.badgeTemplates.map((template) => ({
    id: template.id,
    slug: template.slug,
    title: template.title,
    description: template.description,
    criteriaUri: template.criteriaUri,
    imageUri: template.imageUri,
    isArchived: template.isArchived,
    updatedAt: template.updatedAt,
  }));

  return renderInstitutionAdminShellPage({
    tenant: input.tenant,
    userId: input.userId,
    ...(input.userEmail === undefined ? {} : { userEmail: input.userEmail }),
    membershipRole: input.membershipRole,
    view: "rulesTemplates",
    title: `Badge Templates · Rules · Institution Admin · ${input.tenant.displayName}`,
    assets: ["institutionAdminCss", "institutionAdminShellJs", "institutionAdminBadgeTemplateJs"],
    ...(input.switchOrganizationPath === undefined
      ? {}
      : { switchOrganizationPath: input.switchOrganizationPath }),
    contextJson: {
      tenantAdminPath: paths.tenantAdminPath,
      badgeTemplateApiPathPrefix: `/v1/tenants/${encodeURIComponent(input.tenant.id)}/badge-templates`,
      badgeTemplateAdminTableRowPathPrefix: paths.rulesTemplatesPath,
      ruleBuilderPath: paths.ruleBuilderPath,
      showcasePath: paths.showcasePath,
      badgeTemplateRecords,
      badgeTemplatesReturnToRuleBuilder: input.badgeTemplatesPage.returnToRuleBuilder,
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
          {renderTemplateCreatePanel({
            ruleBuilderPath: paths.ruleBuilderPath,
            showcasePath: paths.showcasePath,
          })}
          {renderTemplateEditorPanel({ templateSelectOptions })}
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
