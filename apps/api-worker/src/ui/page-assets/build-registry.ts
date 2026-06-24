import { AUTH_LOGIN_CSS } from "./content/auth-login-css";
import { AUTH_LOGIN_JS } from "./content/auth-login-js";
import { DESIGN_SYSTEM_CSS } from "./content/design-system-css";
import { EXECUTIVE_DASHBOARD_CSS } from "./content/executive-dashboard-css";
import { FONT_ASSET_SOURCES } from "./content/font-assets";
import { FOUNDATION_CSS } from "./content/foundation-css";
import { INSTITUTION_ADMIN_ACCESS_JS } from "./content/institution-admin-access-js";
import { INSTITUTION_ADMIN_BADGE_TEMPLATE_EDITOR_JS } from "./content/institution-admin-badge-template-editor-js";
import { INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_JS } from "./content/institution-admin-badge-template-list-js";
import { INSTITUTION_ADMIN_CSS } from "./content/institution-admin-css";
import { INSTITUTION_ADMIN_ISSUED_BADGES_JS } from "./content/institution-admin-issued-badges-js";
import { INSTITUTION_ADMIN_JS } from "./content/institution-admin-js";
import { INSTITUTION_ADMIN_RULE_BUILDER_JS } from "./content/institution-admin-rule-builder-js";
import { INSTITUTION_ADMIN_SHELL_JS } from "./content/institution-admin-shell-js";
import { INSTITUTION_ADMIN_TEMPLATE_EDITOR_CSS } from "./content/institution-admin-template-editor-css";
import { LEARNER_DASHBOARD_CSS } from "./content/learner-dashboard-css";
import { LEARNER_RECORD_CSS } from "./content/learner-record-css";
import { LTI_COURSE_SUMMARY_JS } from "./content/lti-course-summary-js";
import { LTI_DEEP_LINK_SETUP_JS } from "./content/lti-deep-link-setup-js";
import { LTI_PAGES_CSS } from "./content/lti-pages-css";
import { LTI_POST_MESSAGE_STORAGE_JS } from "./content/lti-post-message-storage-js";
import { PUBLIC_BADGE_CSS } from "./content/public-badge-css";
import { PUBLIC_BADGE_JS } from "./content/public-badge-js";

export type PageAssetBuildKind = "style" | "script";

export interface PageAssetBuildSource {
  readonly kind: PageAssetBuildKind;
  readonly stem: string;
  readonly body: string;
}

export const PAGE_ASSET_BUILD_SOURCES = {
  foundationCss: { kind: "style", stem: "foundation", body: FOUNDATION_CSS },
  authLoginCss: { kind: "style", stem: "auth-login", body: AUTH_LOGIN_CSS },
  authLoginJs: { kind: "script", stem: "auth-login", body: AUTH_LOGIN_JS },
  executiveDashboardCss: {
    kind: "style",
    stem: "executive-dashboard",
    body: EXECUTIVE_DASHBOARD_CSS,
  },
  designSystemCss: { kind: "style", stem: "design-system", body: DESIGN_SYSTEM_CSS },
  institutionAdminCss: {
    kind: "style",
    stem: "institution-admin",
    body: INSTITUTION_ADMIN_CSS,
  },
  institutionAdminJs: { kind: "script", stem: "institution-admin", body: INSTITUTION_ADMIN_JS },
  institutionAdminShellJs: {
    kind: "script",
    stem: "institution-admin-shell",
    body: INSTITUTION_ADMIN_SHELL_JS,
  },
  institutionAdminAccessJs: {
    kind: "script",
    stem: "institution-admin-access",
    body: INSTITUTION_ADMIN_ACCESS_JS,
  },
  institutionAdminTemplateEditorCss: {
    kind: "style",
    stem: "institution-admin-template-editor",
    body: INSTITUTION_ADMIN_TEMPLATE_EDITOR_CSS,
  },
  institutionAdminBadgeTemplateListJs: {
    kind: "script",
    stem: "institution-admin-badge-template-list",
    body: INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_JS,
  },
  institutionAdminBadgeTemplateEditorJs: {
    kind: "script",
    stem: "institution-admin-badge-template-editor",
    body: INSTITUTION_ADMIN_BADGE_TEMPLATE_EDITOR_JS,
  },
  institutionAdminIssuedBadgesJs: {
    kind: "script",
    stem: "institution-admin-issued-badges",
    body: INSTITUTION_ADMIN_ISSUED_BADGES_JS,
  },
  institutionAdminRuleBuilderJs: {
    kind: "script",
    stem: "institution-admin-rule-builder",
    body: INSTITUTION_ADMIN_RULE_BUILDER_JS,
  },
  learnerRecordCss: { kind: "style", stem: "learner-record", body: LEARNER_RECORD_CSS },
  learnerDashboardCss: {
    kind: "style",
    stem: "learner-dashboard",
    body: LEARNER_DASHBOARD_CSS,
  },
  ltiPagesCss: { kind: "style", stem: "lti-pages", body: LTI_PAGES_CSS },
  ltiCourseSummaryJs: {
    kind: "script",
    stem: "lti-course-summary",
    body: LTI_COURSE_SUMMARY_JS,
  },
  ltiDeepLinkSetupJs: {
    kind: "script",
    stem: "lti-deep-link-setup",
    body: LTI_DEEP_LINK_SETUP_JS,
  },
  ltiPostMessageStorageJs: {
    kind: "script",
    stem: "lti-post-message-storage",
    body: LTI_POST_MESSAGE_STORAGE_JS,
  },
  publicBadgeCss: { kind: "style", stem: "public-badge", body: PUBLIC_BADGE_CSS },
  publicBadgeJs: { kind: "script", stem: "public-badge", body: PUBLIC_BADGE_JS },
} as const satisfies Record<string, PageAssetBuildSource>;

export { FONT_ASSET_SOURCES };
