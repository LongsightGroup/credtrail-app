import type { StylePageAssetSource } from "./assemble-style-asset";
import {
  ADMIN_STATUS_PILL_CLASS_SCRIPT_SOURCE,
  type ScriptPageAssetSource,
} from "./script-asset-fragments";

export type { StylePageAssetMediaGroup, StylePageAssetSource } from "./assemble-style-asset";

export interface StylePageAssetBuildSource {
  readonly kind: "style";
  readonly stem: string;
  readonly sources: readonly StylePageAssetSource[];
}

export interface ScriptPageAssetBuildSource {
  readonly kind: "script";
  readonly stem: string;
  readonly sources: readonly ScriptPageAssetSource[];
}

export type PageAssetBuildSource = StylePageAssetBuildSource | ScriptPageAssetBuildSource;

export const FONT_ASSET_SOURCE_PATHS = ["fonts/newsreader-latin.woff2"] as const;

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
  authLoginJs: {
    kind: "script",
    stem: "auth-login",
    sources: ["auth-login.js"],
  },
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
  institutionAdminJs: {
    kind: "script",
    stem: "institution-admin",
    sources: [
      "admin-browser-primitives.js",
      "institution-admin-bootstrap.js",
      "institution-admin-rule-operations.js",
      "institution-admin-shell-behavior.js",
      "institution-admin-access.js",
      "institution-admin-governance-tools.js",
      "institution-admin-sidebar.js",
      "institution-admin-reporting.js",
    ],
  },
  institutionAdminShellJs: {
    kind: "script",
    stem: "institution-admin-shell",
    sources: ["institution-admin-sidebar.js", "institution-admin-shell-behavior.js"],
  },
  institutionAdminAccessJs: {
    kind: "script",
    stem: "institution-admin-access",
    sources: ["institution-admin-access.js"],
  },
  institutionAdminTemplateEditorCss: {
    kind: "style",
    stem: "institution-admin-template-editor",
    sources: ["institution-admin-template-editor.css"],
  },
  institutionAdminBadgeTemplateListJs: {
    kind: "script",
    stem: "institution-admin-badge-template-list",
    sources: [
      "admin-browser-primitives.js",
      "institution-admin-badge-template-shared-bootstrap.js",
      "institution-admin-badge-template-history-core.js",
      "institution-admin-badge-template-image-fallback.js",
      "institution-admin-badge-template-list-history.js",
    ],
  },
  institutionAdminBadgeTemplateEditorJs: {
    kind: "script",
    stem: "institution-admin-badge-template-editor",
    sources: [
      "admin-browser-primitives.js",
      "institution-admin-badge-template-shared-bootstrap.js",
      "institution-admin-badge-template-editor-records.js",
      "institution-admin-badge-template-history-core.js",
      "institution-admin-badge-template-image-helpers.js",
      "institution-admin-badge-template-image-workflow.js",
      "institution-admin-badge-template-trusted-repeatable.js",
    ],
  },
  institutionAdminIssuedBadgesJs: {
    kind: "script",
    stem: "institution-admin-issued-badges",
    sources: ["admin-browser-primitives.js", "institution-admin-issued-badges.js"],
  },
  institutionAdminRuleVersionJs: {
    kind: "script",
    stem: "institution-admin-rule-version",
    sources: ["institution-admin-rule-version.js"],
  },
  institutionAdminRuleVersionCss: {
    kind: "style",
    stem: "institution-admin-rule-version",
    sources: ["rule-definition-summary.css", "institution-admin-rule-version.css"],
  },
  institutionAdminRuleApprovalReviewJs: {
    kind: "script",
    stem: "institution-admin-rule-approval-review",
    sources: ["institution-admin-rule-approval-review.js"],
  },
  institutionAdminRuleApprovalReviewCss: {
    kind: "style",
    stem: "institution-admin-rule-approval-review",
    sources: ["institution-admin-rule-approval-review.css"],
  },
  assertionEvidenceCss: {
    kind: "style",
    stem: "assertion-evidence",
    sources: ["assertion-evidence.css"],
  },
  assertionEvidenceJs: {
    kind: "script",
    stem: "assertion-evidence",
    sources: ["assertion-evidence.js"],
  },
  institutionAdminRuleBuilderJs: {
    kind: "script",
    stem: "institution-admin-rule-builder",
    sources: [
      "admin-browser-primitives.js",
      "institution-admin-rule-builder-authoring.js",
      "institution-admin-rule-builder-bootstrap.js",
      ADMIN_STATUS_PILL_CLASS_SCRIPT_SOURCE,
      "institution-admin-rule-builder-setup.js",
      "institution-admin-rule-builder-template-picker.js",
      "institution-admin-rule-builder-steps.js",
      "institution-admin-rule-builder-course-labels.js",
      "institution-admin-rule-builder-condition-fields.js",
      "institution-admin-rule-builder-condition-field-renderers.js",
      "lms-picker-payload-parsers.js",
      "lms-gradebook-picker-primitives.js",
      "institution-admin-rule-builder-lms-picker.js",
      "institution-admin-rule-builder-condition-model.js",
      "institution-admin-rule-builder-example-test.js",
      "institution-admin-rule-builder-summary.js",
      "institution-admin-rule-builder-learner-picker.js",
      "institution-admin-rule-builder-presets.js",
      "institution-admin-rule-builder-drafts.js",
      "institution-admin-rule-builder-submit.js",
    ],
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
    sources: ["lti-course-summary.js"],
  },
  ltiDeepLinkSetupJs: {
    kind: "script",
    stem: "lti-deep-link-setup",
    sources: [
      "lms-picker-payload-parsers.js",
      "lms-gradebook-picker-primitives.js",
      "lti-deep-link-setup.js",
    ],
  },
  ltiPostMessageStorageJs: {
    kind: "script",
    stem: "lti-post-message-storage",
    sources: ["lti-post-message-storage.js"],
  },
  publicBadgeCss: {
    kind: "style",
    stem: "public-badge",
    sources: [
      "public-badge-detail.css",
      "public-badge-wall.css",
      "rule-definition-summary.css",
      "public-badge-criteria-registry.css",
    ],
  },
  publicBadgeJs: {
    kind: "script",
    stem: "public-badge",
    sources: ["public-badge.js"],
  },
} as const satisfies Record<string, PageAssetBuildSource>;
