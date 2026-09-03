import type {
  BadgeIssuanceRuleRecord,
  BadgeIssuanceRuleVersionRecord,
  BadgeIssuanceRuleVersionSnapshot,
  TenantOrgUnitRecord,
} from "@credtrail/db";
import type { BadgeIssuanceRuleDefinition } from "@credtrail/validation";
import type { HtmlEscapedString } from "hono/utils/html";
import {
  createRuleDefinitionSummaryMarkup,
  type BadgeRuleSummaryLmsReferenceMarkupInput,
} from "../badges/badge-rule-definition-summary";
import {
  badgeRuleVersionDisplayFields,
  badgeRuleVersionStateLabel,
} from "../badges/badge-rule-presentation";
import { formatIsoTimestamp } from "../utils/display-format";
import { buildBadgeRuleVersionLmsReferenceLabelsPath } from "./access-admin-helpers";
import { AdminPanel, AdminStatusPill } from "./components";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

const versionTimestampRows = (
  version: BadgeIssuanceRuleVersionRecord,
  submittedByEmail: string | undefined,
): readonly { readonly label: string; readonly value: string }[] => {
  const rows: Array<{ readonly label: string; readonly value: string }> = [
    { label: "Created", value: formatIsoTimestamp(version.createdAt) },
  ];

  if (version.submittedAt !== null) {
    rows.push({ label: "Submitted", value: formatIsoTimestamp(version.submittedAt) });

    if (submittedByEmail !== undefined) {
      rows.push({ label: "Submitted by", value: submittedByEmail });
    }
  }

  if (version.approvedAt !== null) {
    rows.push({ label: "Approved", value: formatIsoTimestamp(version.approvedAt) });
  }

  if (version.activatedAt !== null) {
    rows.push({ label: "Activated", value: formatIsoTimestamp(version.activatedAt) });
  }

  if (version.effectiveStartsAt !== null) {
    rows.push({ label: "Effective from", value: formatIsoTimestamp(version.effectiveStartsAt) });
  }

  if (version.expiresAt !== null) {
    rows.push({ label: "Ends", value: formatIsoTimestamp(version.expiresAt) });
  }

  return rows;
};

const badgeArtwork = (snapshot: BadgeIssuanceRuleVersionSnapshot): HonoElement => {
  if (snapshot.badgeTemplateImageUri === null) {
    return (
      <span class="ct-admin__rule-version-artwork-placeholder" aria-hidden="true">
        {snapshot.badgeTemplateTitle.slice(0, 1).toUpperCase()}
      </span>
    );
  }

  return (
    <img
      class="ct-admin__rule-version-artwork"
      src={snapshot.badgeTemplateImageUri}
      alt=""
      width="96"
      height="96"
    />
  );
};

const badgeRuleVersionLifecycleSummary = (input: {
  readonly rule: BadgeIssuanceRuleRecord;
  readonly version: BadgeIssuanceRuleVersionRecord;
}): string => {
  if (input.rule.activeVersionId === input.version.id) {
    return "CredTrail currently uses this version for new awards. Awards already issued keep this version permanently.";
  }

  switch (input.version.status) {
    case "approved":
      return "This version is approved, but it will not issue badges until an administrator activates it.";
    case "pending_approval":
      return "This version is awaiting approval. Approval makes it eligible for activation; it does not replace the active version.";
    case "draft":
      return "This draft is read-only here and cannot issue badges until it is submitted, approved, and activated.";
    case "rejected":
      return "This submission was rejected and cannot issue badges. Editing it creates a new draft version.";
    case "suspended":
      return "Issuance from this version is suspended. Awards already issued from it remain unchanged.";
    case "expired":
      return "This version has expired and no longer issues badges. Awards already issued from it remain unchanged.";
    case "deprecated":
      return "This is a previous read-only version. Awards issued from it remain unchanged.";
    case "active":
      return "This active version is an immutable issuance record. Awards already issued from it remain unchanged.";
  }
};

const adminLmsReferenceMarkup = (input: BadgeRuleSummaryLmsReferenceMarkupInput): HonoElement => {
  const label = input.reference.kind === "assignment" ? "Assignment" : input.label;
  const content = (
    <>
      <span data-rule-lms-label="">{label}</span>{" "}
      <span class="ct-rule-summary__muted">ID: {input.rawId}</span>
    </>
  );

  if (input.reference.kind === "course") {
    return (
      <span data-rule-lms-reference="course" data-course-id={input.reference.courseId}>
        {content}
      </span>
    );
  }

  return (
    <span
      data-rule-lms-reference="assignment"
      data-course-id={input.reference.courseId}
      data-assignment-id={input.reference.assignmentId}
    >
      {content}
    </span>
  );
};

/** Renders the shared, read-only record for one governed badge-rule version. */
export const BadgeRuleVersionOverview = (input: {
  readonly tenantId: string;
  readonly rule: BadgeIssuanceRuleRecord;
  readonly version: BadgeIssuanceRuleVersionRecord;
  readonly latestVersion: BadgeIssuanceRuleVersionRecord;
  readonly definition: BadgeIssuanceRuleDefinition;
  readonly orgUnit: TenantOrgUnitRecord | null;
  readonly submittedByEmail?: string | undefined;
  readonly showLifecycleSummary?: boolean | undefined;
}): HonoElement => {
  const ruleSummaryMarkup = createRuleDefinitionSummaryMarkup(formatIsoTimestamp, {
    renderLmsReference: adminLmsReferenceMarkup,
  });
  const timestampRows = versionTimestampRows(input.version, input.submittedByEmail);
  const displayFields = badgeRuleVersionDisplayFields(input.version);
  const lmsLabelsUrl =
    input.version.snapshot.lmsConnectionId === null
      ? null
      : buildBadgeRuleVersionLmsReferenceLabelsPath(
          input.tenantId,
          input.rule.id,
          input.version.id,
        );

  return (
    <AdminPanel
      className="ct-admin__rule-version-record"
      {...(lmsLabelsUrl === null
        ? {}
        : {
            dataAttributes: {
              "data-rule-lms-labels": "",
              "data-lms-labels-url": lmsLabelsUrl,
            },
          })}
    >
      <div class="ct-admin__rule-version-identity">
        <div class="ct-admin__rule-version-artwork-frame">
          {badgeArtwork(input.version.snapshot)}
        </div>
        <div class="ct-admin__rule-version-identity-copy">
          <div class="ct-admin__rule-version-state">
            <AdminStatusPill tone={input.version.status}>
              {badgeRuleVersionStateLabel({
                rule: input.rule,
                version: input.version,
                latestVersion: input.latestVersion,
              })}
            </AdminStatusPill>
            <span>Version {String(input.version.versionNumber)}</span>
          </div>
          <h2>{displayFields.badgeTitle}</h2>
          <p class="ct-admin__rule-version-change-summary">
            <strong>Version note:</strong>{" "}
            {input.version.changeSummary ?? "No change summary was provided for this version."}
          </p>
          <p>{input.version.snapshot.description ?? "No rule description was provided."}</p>
          {input.showLifecycleSummary === false ? null : (
            <p class="ct-admin__rule-version-lifecycle-summary">
              {badgeRuleVersionLifecycleSummary(input)}
            </p>
          )}
        </div>
      </div>

      <div class="ct-admin__rule-version-metadata-groups">
        <section>
          <h3>Applies to</h3>
          <dl class="ct-admin__rule-version-metadata">
            <div>
              <dt>LMS</dt>
              <dd>{displayFields.lmsProviderLabel}</dd>
            </div>
            <div>
              <dt>Organization scope</dt>
              <dd>
                {input.orgUnit === null
                  ? input.version.snapshot.orgUnitId
                  : `${input.orgUnit.displayName} (${input.orgUnit.unitType})`}
              </dd>
            </div>
          </dl>
        </section>
        <section>
          <h3>Timeline</h3>
          <dl class="ct-admin__rule-version-metadata">
            {timestampRows.map((row) => (
              <div>
                <dt>{row.label}</dt>
                <dd>{row.value}</dd>
              </div>
            ))}
          </dl>
        </section>
      </div>

      <div class="ct-admin__rule-version-definition">
        <h3>What this version requires</h3>
        {ruleSummaryMarkup(input.definition)}
        {lmsLabelsUrl === null ? null : (
          <p
            class="ct-admin__rule-version-label-status"
            data-rule-lms-label-status=""
            role="status"
            hidden
          >
            Course and assignment names could not be loaded. The saved LMS IDs remain visible.
          </p>
        )}
      </div>

      <details class="ct-admin__rule-version-technical-details">
        <summary>Technical details</summary>
        <dl class="ct-admin__rule-version-support-metadata">
          <div>
            <dt>Rule ID</dt>
            <dd>{input.rule.id}</dd>
          </div>
          <div>
            <dt>Version ID</dt>
            <dd>{input.version.id}</dd>
          </div>
        </dl>
      </details>
    </AdminPanel>
  );
};
