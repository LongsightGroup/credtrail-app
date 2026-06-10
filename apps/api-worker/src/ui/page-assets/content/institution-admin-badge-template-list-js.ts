import { INSTITUTION_ADMIN_BADGE_TEMPLATE_HISTORY_CORE_JS } from "./institution-admin-badge-template-history-core-js";
import { INSTITUTION_ADMIN_BADGE_TEMPLATE_IMAGE_FALLBACK_JS } from "./institution-admin-badge-template-image-fallback-js";
import { INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_HISTORY_JS } from "./institution-admin-badge-template-list-history-js";
import { INSTITUTION_ADMIN_BADGE_TEMPLATE_SHARED_BOOTSTRAP_JS } from "./institution-admin-badge-template-shared-bootstrap-js";

export const INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_JS = [
  INSTITUTION_ADMIN_BADGE_TEMPLATE_SHARED_BOOTSTRAP_JS,
  INSTITUTION_ADMIN_BADGE_TEMPLATE_HISTORY_CORE_JS,
  INSTITUTION_ADMIN_BADGE_TEMPLATE_IMAGE_FALLBACK_JS,
  INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_HISTORY_JS,
  `
})();
`,
].join("\n");
