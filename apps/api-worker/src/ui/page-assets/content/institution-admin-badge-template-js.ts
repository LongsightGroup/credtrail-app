import { INSTITUTION_ADMIN_BADGE_TEMPLATE_BOOTSTRAP_JS } from "./institution-admin-badge-template-bootstrap-js";
import { INSTITUTION_ADMIN_BADGE_TEMPLATE_CREATE_EDIT_JS } from "./institution-admin-badge-template-create-edit-js";
import { INSTITUTION_ADMIN_BADGE_TEMPLATE_HISTORY_JS } from "./institution-admin-badge-template-history-js";
import { INSTITUTION_ADMIN_BADGE_TEMPLATE_IMAGE_HELPERS_JS } from "./institution-admin-badge-template-image-helpers-js";
import { INSTITUTION_ADMIN_BADGE_TEMPLATE_IMAGE_WORKFLOW_JS } from "./institution-admin-badge-template-image-workflow-js";
import { INSTITUTION_ADMIN_BADGE_TEMPLATE_RECORDS_JS } from "./institution-admin-badge-template-records-js";

export const INSTITUTION_ADMIN_BADGE_TEMPLATE_JS = [
  INSTITUTION_ADMIN_BADGE_TEMPLATE_BOOTSTRAP_JS,
  INSTITUTION_ADMIN_BADGE_TEMPLATE_IMAGE_HELPERS_JS,
  INSTITUTION_ADMIN_BADGE_TEMPLATE_RECORDS_JS,
  INSTITUTION_ADMIN_BADGE_TEMPLATE_HISTORY_JS,
  INSTITUTION_ADMIN_BADGE_TEMPLATE_IMAGE_WORKFLOW_JS,
  INSTITUTION_ADMIN_BADGE_TEMPLATE_CREATE_EDIT_JS,
].join("\n");
