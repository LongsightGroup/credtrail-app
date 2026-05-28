import { INSTITUTION_ADMIN_BADGE_TEMPLATE_EDITOR_EDIT_JS } from "./institution-admin-badge-template-editor-edit-js";
import { INSTITUTION_ADMIN_BADGE_TEMPLATE_EDITOR_HISTORY_JS } from "./institution-admin-badge-template-editor-history-js";
import { INSTITUTION_ADMIN_BADGE_TEMPLATE_EDITOR_RECORDS_JS } from "./institution-admin-badge-template-editor-records-js";
import { INSTITUTION_ADMIN_BADGE_TEMPLATE_HISTORY_CORE_JS } from "./institution-admin-badge-template-history-core-js";
import { INSTITUTION_ADMIN_BADGE_TEMPLATE_IMAGE_HELPERS_JS } from "./institution-admin-badge-template-image-helpers-js";
import { INSTITUTION_ADMIN_BADGE_TEMPLATE_IMAGE_WORKFLOW_JS } from "./institution-admin-badge-template-image-workflow-js";
import { INSTITUTION_ADMIN_BADGE_TEMPLATE_SHARED_BOOTSTRAP_JS } from "./institution-admin-badge-template-shared-bootstrap-js";

export const INSTITUTION_ADMIN_BADGE_TEMPLATE_EDITOR_JS = [
  INSTITUTION_ADMIN_BADGE_TEMPLATE_SHARED_BOOTSTRAP_JS,
  INSTITUTION_ADMIN_BADGE_TEMPLATE_EDITOR_RECORDS_JS,
  INSTITUTION_ADMIN_BADGE_TEMPLATE_HISTORY_CORE_JS,
  INSTITUTION_ADMIN_BADGE_TEMPLATE_IMAGE_HELPERS_JS,
  INSTITUTION_ADMIN_BADGE_TEMPLATE_IMAGE_WORKFLOW_JS,
  INSTITUTION_ADMIN_BADGE_TEMPLATE_EDITOR_EDIT_JS,
  INSTITUTION_ADMIN_BADGE_TEMPLATE_EDITOR_HISTORY_JS,
  `
  const initInstitutionAdminBadgeTemplateEditorPage = () => {};

  if (document.getElementById('badge-template-edit-form')) {
    initInstitutionAdminBadgeTemplateEditorPage();
  }
})();
`,
].join("\n");
