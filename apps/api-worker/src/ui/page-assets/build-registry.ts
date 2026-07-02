import type { StylePageAssetSource } from "./assemble-style-asset";
import { AUTH_LOGIN_JS } from "./content/auth-login-js";
import { FONT_ASSET_SOURCES } from "./content/font-assets";
import { INSTITUTION_ADMIN_ACCESS_JS } from "./content/institution-admin-access-js";
import { INSTITUTION_ADMIN_BADGE_TEMPLATE_EDITOR_JS } from "./content/institution-admin-badge-template-editor-js";
import { INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_JS } from "./content/institution-admin-badge-template-list-js";
import { INSTITUTION_ADMIN_ISSUED_BADGES_JS } from "./content/institution-admin-issued-badges-js";
import { INSTITUTION_ADMIN_JS } from "./content/institution-admin-js";
import { INSTITUTION_ADMIN_RULE_BUILDER_JS } from "./content/institution-admin-rule-builder-js";
import { INSTITUTION_ADMIN_SHELL_JS } from "./content/institution-admin-shell-js";
import { LTI_COURSE_SUMMARY_JS } from "./content/lti-course-summary-js";
import { LTI_DEEP_LINK_SETUP_JS } from "./content/lti-deep-link-setup-js";
import { LTI_POST_MESSAGE_STORAGE_JS } from "./content/lti-post-message-storage-js";
import { PUBLIC_BADGE_JS } from "./content/public-badge-js";

export type { StylePageAssetMediaGroup, StylePageAssetSource } from "./assemble-style-asset";

export interface StylePageAssetBuildSource {
  readonly kind: "style";
  readonly stem: string;
  readonly sources: readonly StylePageAssetSource[];
}

export interface ScriptPageAssetBuildSource {
  readonly kind: "script";
  readonly stem: string;
  readonly body: string;
}

export type PageAssetBuildSource = StylePageAssetBuildSource | ScriptPageAssetBuildSource;

export const PAGE_ASSET_BUILD_SOURCES = {
  foundationCss: {
    kind: "style",
    stem: "foundation",
    sources: [
      "font-face.css",
      "generated/design-tokens.css",
      "actions.css",
      "forms.css",
      "foundation.css",
    ],
  },
  authLoginCss: { kind: "style", stem: "auth-login", sources: ["auth-login.css"] },
  authLoginJs: { kind: "script", stem: "auth-login", body: AUTH_LOGIN_JS },
  executiveDashboardCss: {
    kind: "style",
    stem: "executive-dashboard",
    sources: ["executive-dashboard.css"],
  },
  designSystemCss: { kind: "style", stem: "design-system", sources: ["design-system.css"] },
  institutionAdminCss: {
    kind: "style",
    stem: "institution-admin",
    sources: [
      "institution-admin-shell.css",
      "institution-admin-workspace.css",
      "institution-admin-reporting-visuals.css",
      "institution-admin-reporting-explore.css",
      "institution-admin-reporting-presentation.css",
      "institution-admin-reporting-focus.css",
      "institution-admin-layout.css",
      "institution-admin-forms.css",
      "institution-admin-rule-builder-steps.css",
      "institution-admin-rule-builder-controls.css",
      "institution-admin-rule-builder-canvas.css",
      "institution-admin-rule-builder-conditions.css",
      "institution-admin-buttons.css",
      "institution-admin-status.css",
      "institution-admin-tables.css",
      {
        media: "(max-width: 780px)",
        sourcePaths: [
          "institution-admin-forms-responsive.css",
          "institution-admin-rule-builder-responsive.css",
          "institution-admin-buttons-responsive.css",
          "institution-admin-tables-responsive.css",
        ],
      },
      {
        media: "(pointer: coarse)",
        sourcePaths: [
          "institution-admin-shell-coarse-pointer.css",
          "institution-admin-buttons-coarse-pointer.css",
        ],
      },
      "institution-admin-breakpoints.css",
    ],
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
    sources: ["institution-admin-template-editor.css"],
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
  learnerRecordCss: { kind: "style", stem: "learner-record", sources: ["learner-record.css"] },
  learnerDashboardCss: {
    kind: "style",
    stem: "learner-dashboard",
    sources: ["learner-dashboard.css"],
  },
  ltiPagesCss: { kind: "style", stem: "lti-pages", sources: ["lti-pages.css"] },
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
  publicBadgeCss: {
    kind: "style",
    stem: "public-badge",
    sources: [
      "public-badge-detail.css",
      "public-badge-wall.css",
      "public-badge-criteria-registry.css",
    ],
  },
  publicBadgeJs: { kind: "script", stem: "public-badge", body: PUBLIC_BADGE_JS },
} as const satisfies Record<string, PageAssetBuildSource>;

export { FONT_ASSET_SOURCES };
