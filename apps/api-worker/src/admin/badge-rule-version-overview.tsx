import type {
  BadgeIssuanceRuleRecord,
  BadgeIssuanceRuleVersionRecord,
  BadgeIssuanceRuleVersionSnapshot,
} from "@credtrail/db";
import type { BadgeIssuanceRuleDefinition } from "@credtrail/validation";
import type { HtmlEscapedString } from "hono/utils/html";
import {
  createRuleDefinitionSummaryMarkup,
  type BadgeRuleSummaryLmsReferenceMarkupInput,
} from "../badges/badge-rule-definition-summary";
import { formatIsoTimestamp } from "../utils/display-format";
import { buildBadgeRuleVersionLmsReferenceLabelsPath } from "./access-admin-helpers";
import { badgeRuleLmsProviderLabel, badgeRuleVersionStateLabel } from "./badge-rule-presentation";
import { AdminPanel, AdminStatusPill } from "./components";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

const versionTimestampRows = (
  version: BadgeIssuanceRuleVersionRecord,
): readonly { readonly label: string; readonly value: string }[] => {
  const rows: Array<{ readonly label: string; readonly value: string }> = [
    { label: "Created", value: formatIsoTimestamp(version.createdAt) },
  ];

  if (version.submittedAt !== null) {
    rows.push({ label: "Submitted", value: formatIsoTimestamp(version.submittedAt) });
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
}): HonoElement => {
  const ruleSummaryMarkup = createRuleDefinitionSummaryMarkup(formatIsoTimestamp, {
    renderLmsReference: adminLmsReferenceMarkup,
  });
  const timestampRows = versionTimestampRows(input.version);
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
          <h2>{input.version.snapshot.badgeTemplateTitle}</h2>
          <p>{input.version.snapshot.description ?? "No rule description was provided."}</p>
        </div>
      </div>

      <dl class="ct-admin__rule-version-metadata">
        {timestampRows.map((row) => (
          <div>
            <dt>{row.label}</dt>
            <dd>{row.value}</dd>
          </div>
        ))}
        <div>
          <dt>LMS</dt>
          <dd>{badgeRuleLmsProviderLabel(input.version.snapshot.lmsProviderKind)}</dd>
        </div>
      </dl>

      <div class="ct-admin__rule-version-definition">
        <h3>What this version requires</h3>
        {ruleSummaryMarkup(input.definition)}
        {lmsLabelsUrl === null ? null : (
          <p
            class="ct-admin__rule-version-label-status"
            data-rule-lms-label-status=""
            role="status"
          >
            Loading course and assignment names…
          </p>
        )}
      </div>

      <div class="ct-admin__rule-version-change-summary">
        <h3>Change summary</h3>
        <p>{input.version.changeSummary ?? "No change summary was provided for this version."}</p>
      </div>

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
    </AdminPanel>
  );
};
