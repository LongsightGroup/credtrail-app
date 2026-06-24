import { ADMIN_STATUS_PILL_CLASS_HELPER_JS } from "../../../admin/admin-status-pill-class";
import { INSTITUTION_ADMIN_RULE_BUILDER_BOOTSTRAP_JS } from "./institution-admin-rule-builder-bootstrap-js";
import { INSTITUTION_ADMIN_RULE_BUILDER_CONDITION_FIELD_RENDERERS_JS } from "./institution-admin-rule-builder-condition-field-renderers-js";
import { INSTITUTION_ADMIN_RULE_BUILDER_CONDITION_FIELDS_JS } from "./institution-admin-rule-builder-condition-fields-js";
import { INSTITUTION_ADMIN_RULE_BUILDER_CONDITION_MODEL_JS } from "./institution-admin-rule-builder-condition-model-js";
import { INSTITUTION_ADMIN_RULE_BUILDER_DRAFTS_JS } from "./institution-admin-rule-builder-drafts-js";
import { LMS_GRADEBOOK_PICKER_PRIMITIVES_JS } from "./lms-gradebook-picker-primitives-js";
import { INSTITUTION_ADMIN_RULE_BUILDER_LMS_PICKER_JS } from "./institution-admin-rule-builder-lms-picker-js";
import { INSTITUTION_ADMIN_RULE_BUILDER_SETUP_JS } from "./institution-admin-rule-builder-setup-js";
import { INSTITUTION_ADMIN_RULE_BUILDER_STEPS_JS } from "./institution-admin-rule-builder-steps-js";
import { INSTITUTION_ADMIN_RULE_BUILDER_SUBMIT_JS } from "./institution-admin-rule-builder-submit-js";
import { INSTITUTION_ADMIN_RULE_BUILDER_SUMMARY_JS } from "./institution-admin-rule-builder-summary-js";

export const INSTITUTION_ADMIN_RULE_BUILDER_JS = [
  INSTITUTION_ADMIN_RULE_BUILDER_BOOTSTRAP_JS,
  ADMIN_STATUS_PILL_CLASS_HELPER_JS,
  INSTITUTION_ADMIN_RULE_BUILDER_SETUP_JS,
  INSTITUTION_ADMIN_RULE_BUILDER_STEPS_JS,
  INSTITUTION_ADMIN_RULE_BUILDER_CONDITION_FIELDS_JS,
  INSTITUTION_ADMIN_RULE_BUILDER_CONDITION_FIELD_RENDERERS_JS,
  LMS_GRADEBOOK_PICKER_PRIMITIVES_JS,
  INSTITUTION_ADMIN_RULE_BUILDER_LMS_PICKER_JS,
  INSTITUTION_ADMIN_RULE_BUILDER_CONDITION_MODEL_JS,
  INSTITUTION_ADMIN_RULE_BUILDER_SUMMARY_JS,
  INSTITUTION_ADMIN_RULE_BUILDER_DRAFTS_JS,
  INSTITUTION_ADMIN_RULE_BUILDER_SUBMIT_JS,
].join("\n");
