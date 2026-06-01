import { INSTITUTION_ADMIN_ACCESS_JS } from "./institution-admin-access-js";
import { INSTITUTION_ADMIN_BOOTSTRAP_JS } from "./institution-admin-bootstrap-js";
import { INSTITUTION_ADMIN_GOVERNANCE_TOOLS_JS } from "./institution-admin-governance-tools-js";
import { INSTITUTION_ADMIN_REPORTING_JS } from "./institution-admin-reporting-js";
import { INSTITUTION_ADMIN_RULE_OPERATIONS_JS } from "./institution-admin-rule-operations-js";
import { INSTITUTION_ADMIN_SIDEBAR_JS } from "./institution-admin-sidebar-js";

export const INSTITUTION_ADMIN_JS = [
  INSTITUTION_ADMIN_BOOTSTRAP_JS,
  INSTITUTION_ADMIN_RULE_OPERATIONS_JS,
  INSTITUTION_ADMIN_ACCESS_JS,
  INSTITUTION_ADMIN_GOVERNANCE_TOOLS_JS,
  INSTITUTION_ADMIN_SIDEBAR_JS,
  INSTITUTION_ADMIN_REPORTING_JS,
].join("\n");
