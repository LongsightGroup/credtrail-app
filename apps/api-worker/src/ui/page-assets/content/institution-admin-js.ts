import { INSTITUTION_ADMIN_BOOTSTRAP_JS } from "./institution-admin-bootstrap-js";
import { INSTITUTION_ADMIN_GOVERNANCE_TOOLS_JS } from "./institution-admin-governance-tools-js";
import { INSTITUTION_ADMIN_ISSUE_AUTH_JS } from "./institution-admin-issue-auth-js";
import { INSTITUTION_ADMIN_MEMBERSHIP_JS } from "./institution-admin-membership-js";
import { INSTITUTION_ADMIN_REPORTING_JS } from "./institution-admin-reporting-js";
import { INSTITUTION_ADMIN_RULE_OPERATIONS_JS } from "./institution-admin-rule-operations-js";

export const INSTITUTION_ADMIN_JS = [
  INSTITUTION_ADMIN_BOOTSTRAP_JS,
  INSTITUTION_ADMIN_RULE_OPERATIONS_JS,
  INSTITUTION_ADMIN_ISSUE_AUTH_JS,
  INSTITUTION_ADMIN_MEMBERSHIP_JS,
  INSTITUTION_ADMIN_GOVERNANCE_TOOLS_JS,
  INSTITUTION_ADMIN_REPORTING_JS,
].join("\n");
