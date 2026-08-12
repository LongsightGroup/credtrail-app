/** Server-rendered badge template editor artwork UI. */
import type { BadgeTemplateRecord } from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import type { BadgeTemplateArtworkReadiness } from "../badges/badge-achievement-snapshot";
import { adminStatusPillClass } from "./admin-status-pill-class";
import { AdminButton, AdminField, AdminForm, AdminStatus } from "./components";
import { CtInput, CtSelect } from "../ui/forms";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

export const badgeTemplateEditorReadyState = (
  template: BadgeTemplateRecord,
  artworkReadiness: BadgeTemplateArtworkReadiness,
): { label: string; tone: string } => {
  if (template.isArchived) {
    return { label: "Archived", tone: "revoked" };
  }

  if (artworkReadiness === "missing_artwork") {
    return { label: "Needs image", tone: "warning" };
  }

  if (artworkReadiness === "unmanaged_artwork") {
    return { label: "Needs managed image", tone: "warning" };
  }

  if (artworkReadiness === "invalid_artwork") {
    return { label: "Image needs replacement", tone: "warning" };
  }

  if (artworkReadiness === "storage_unavailable") {
    return { label: "Image check unavailable", tone: "warning" };
  }

  return { label: "Ready for rules", tone: "active" };
};

export const BadgeTemplateEditorPreviewFrame = ({
  template,
}: {
  template: BadgeTemplateRecord;
}): HonoElement => {
  return (
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
  );
};

export const BadgeTemplateEditorReadyStatus = ({
  template,
  artworkReadiness,
}: {
  template: BadgeTemplateRecord;
  artworkReadiness: BadgeTemplateArtworkReadiness;
}): HonoElement => {
  const ready = badgeTemplateEditorReadyState(template, artworkReadiness);

  return (
    <span id="badge-template-editor-ready-status" class={adminStatusPillClass(ready.tone)}>
      {ready.label}
    </span>
  );
};

export const BadgeTemplateEditorCurrentArtwork = ({
  template,
  artworkReadiness,
}: {
  template: BadgeTemplateRecord;
  artworkReadiness: BadgeTemplateArtworkReadiness;
}): HonoElement => {
  const hasManagedArtwork = artworkReadiness === "ready";
  const artworkPillTone = hasManagedArtwork ? "active" : "warning";
  const artworkStatusLabel = (() => {
    switch (artworkReadiness) {
      case "ready":
        return "Approved image";
      case "missing_artwork":
        return "Image required";
      case "unmanaged_artwork":
        return "Managed image required";
      case "invalid_artwork":
        return "Replace image";
      case "storage_unavailable":
        return "Check unavailable";
    }
  })();
  const artworkDetail = (() => {
    switch (artworkReadiness) {
      case "ready":
        return "Approved artwork is set. This template is ready for rules.";
      case "missing_artwork":
        return "Upload approved artwork in CredTrail before using this template in rules.";
      case "unmanaged_artwork":
        return "Replace this image with artwork uploaded or generated in CredTrail before using the template in rules.";
      case "invalid_artwork":
        return "The stored image cannot be verified. Replace it before using this template in rules.";
      case "storage_unavailable":
        return "CredTrail cannot check the stored image right now. Try again before replacing it.";
    }
  })();

  return (
    <div
      class="ct-admin__template-editor-current-artwork"
      id="badge-template-editor-current-artwork"
    >
      <div id="badge-template-editor-current-artwork-media">
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
      </div>
      <div>
        <div class="ct-admin__template-editor-artwork-status-row">
          <strong>Current artwork</strong>
          <span
            id="badge-template-editor-current-artwork-status"
            class={adminStatusPillClass(artworkPillTone)}
          >
            {artworkStatusLabel}
          </span>
        </div>
        <p id="badge-template-editor-current-artwork-detail">{artworkDetail}</p>
      </div>
    </div>
  );
};

export const BadgeTemplateEditorArtworkActionsCopy = ({
  artworkReadiness,
  hasArtworkReference,
}: {
  artworkReadiness: BadgeTemplateArtworkReadiness;
  hasArtworkReference: boolean;
}): HonoElement => {
  const hasManagedArtwork = artworkReadiness === "ready";

  return (
    <>
      <strong id="badge-template-editor-artwork-actions-title">
        {hasManagedArtwork || hasArtworkReference ? "Replace artwork" : "Add artwork"}
      </strong>
      <small id="badge-template-editor-artwork-actions-detail">
        {!hasManagedArtwork
          ? "Upload an approved image or generate a draft to review."
          : "Upload a new image to replace the current artwork."}
      </small>
    </>
  );
};

export const BadgeTemplateEditorArtworkActions = ({
  template,
  artworkReadiness,
  imageUploadPath,
  imageApplyPath,
}: {
  template: BadgeTemplateRecord;
  artworkReadiness: BadgeTemplateArtworkReadiness;
  imageUploadPath: string;
  imageApplyPath: string;
}): HonoElement => {
  const hasManagedArtwork = artworkReadiness === "ready";

  return (
    <details
      id="badge-template-editor-artwork-actions"
      class="ct-admin__template-editor-artwork-actions"
      open={!hasManagedArtwork}
    >
      <summary class="ct-admin__template-editor-artwork-actions-summary">
        <span>
          <BadgeTemplateEditorArtworkActionsCopy
            artworkReadiness={artworkReadiness}
            hasArtworkReference={template.imageUri !== null}
          />
        </span>
        <span class="ct-admin__template-editor-artwork-actions-control">
          <span class="ct-admin__template-editor-artwork-actions-open">Open options</span>
          <span class="ct-admin__template-editor-artwork-actions-close">Hide options</span>
        </span>
      </summary>
      <div class="ct-admin__template-editor-artwork-action-grid">
        <section class="ct-admin__template-editor-artwork-option">
          <div class="ct-admin__template-editor-subgroup">
            <h4 class="ct-admin__template-editor-subgroup-title">Upload approved image</h4>
            <AdminForm
              id="badge-template-image-upload-form"
              action={imageUploadPath}
              method="post"
              encType="multipart/form-data"
              className="ct-admin__form ct-admin__template-editor-subform"
            >
              <CtInput type="hidden" name="badgeTemplateId" value={template.id} />
              <div class="ct-admin__template-editor-fields ct-admin__template-editor-fields--upload">
                <AdminField label="Image file">
                  <CtInput
                    name="file"
                    type="file"
                    required
                    accept="image/png,image/jpeg,image/webp"
                  />
                </AdminField>
                <AdminButton type="submit">Upload approved image</AdminButton>
              </div>
            </AdminForm>
            <AdminStatus id="badge-template-image-upload-status"></AdminStatus>
          </div>
        </section>
        <section class="ct-admin__template-editor-artwork-option">
          <div class="ct-admin__template-editor-subgroup">
            <h4 class="ct-admin__template-editor-subgroup-title">Generate a draft</h4>
            <AdminForm
              id="badge-template-image-generation-form"
              className="ct-admin__form ct-admin__template-editor-subform"
            >
              <CtInput type="hidden" name="badgeTemplateId" value={template.id} />
              <div class="ct-admin__template-editor-fields ct-admin__template-editor-fields--generation">
                <AdminField label="Style">
                  <CtSelect name="stylePreset" required>
                    <option value="institutional">Institutional</option>
                    <option value="technical">Technical</option>
                    <option value="academic">Academic</option>
                    <option value="open_source">Open source</option>
                    <option value="minimal">Minimal</option>
                  </CtSelect>
                </AdminField>
                <AdminField label="Accent">
                  <CtInput name="accentColor" type="text" placeholder="Sakai blue" maxlength={80} />
                </AdminField>
                <AdminField
                  label="Prompt notes"
                  className="ct-admin__template-editor-generation-prompt"
                >
                  <CtInput
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
            <AdminForm
              id="badge-template-image-generation-apply-form"
              action={imageApplyPath}
              method="post"
              className="ct-admin__form"
              hidden
            >
              <CtInput
                type="hidden"
                name="generationId"
                id="badge-template-image-generation-apply-generation-id"
                value=""
              />
            </AdminForm>
            <div
              id="badge-template-image-generation-preview"
              class="ct-admin__image-generation-preview"
              hidden
            >
              <img id="badge-template-image-generation-preview-img" alt="Generated badge draft" />
              <div class="ct-admin__image-generation-actions">
                <AdminButton
                  id="badge-template-image-generation-apply"
                  form="badge-template-image-generation-apply-form"
                  type="submit"
                  variant="secondary"
                >
                  Use this draft
                </AdminButton>
                <button
                  type="button"
                  id="badge-template-image-generation-open"
                  class="ct-admin__text-action"
                  hidden
                  aria-label="Open generated badge draft at full size"
                >
                  Open full size
                </button>
              </div>
            </div>
          </div>
        </section>
      </div>
    </details>
  );
};
