import type { TenantMembershipRole, TenantRecord } from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import {
  AdminActions,
  AdminButton,
  AdminButtonLink,
  AdminMeta,
  AdminStatusPill,
} from "../components";
import { renderInstitutionAdminShellPage } from "../institution-admin-shell";
import type { AssertionEvidencePresentation } from "../../badges/assertion-evidence-presentation";
import { formatIsoTimestamp } from "../../utils/display-format";
import type { AppPage } from "../../ui/render-page";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

export interface AssertionEvidencePageInput {
  evidence: AssertionEvidencePresentation;
  returnHref: string;
  evidenceApiPath: string;
}

const DetailList = (input: { rows: readonly { label: string; value: string }[] }): HonoElement => {
  if (input.rows.length === 0) {
    return <p class="assertion-evidence__empty">No details are available.</p>;
  }

  return (
    <dl class="assertion-evidence__detail-list">
      {input.rows.map((row) => (
        <div class="assertion-evidence__detail-row">
          <dt>{row.label}</dt>
          <dd>{row.value}</dd>
        </div>
      ))}
    </dl>
  );
};

const TimelineList = (input: {
  entries: AssertionEvidencePresentation["changesAfterIssuance"];
}): HonoElement => {
  if (input.entries.length === 0) {
    return <p class="assertion-evidence__empty">No changes have been recorded after issuance.</p>;
  }

  return (
    <ol class="assertion-evidence__timeline">
      {input.entries.map((entry) => (
        <li class="assertion-evidence__timeline-item">
          <div class="assertion-evidence__timeline-head">
            <strong>{entry.summary}</strong>
            <span>{formatIsoTimestamp(entry.occurredAt)} UTC</span>
          </div>
          <p>{entry.actorLabel}</p>
          {entry.detail.length > 0 ? (
            <p class="assertion-evidence__timeline-detail">{entry.detail}</p>
          ) : null}
        </li>
      ))}
    </ol>
  );
};

const renderAssertionEvidenceBody = (input: AssertionEvidencePageInput): HonoElement => {
  const { evidence } = input;

  const summaryRows = [
    { label: "Badge", value: evidence.summary.badgeTitle },
    { label: "Recipient", value: evidence.summary.recipientIdentity },
    { label: "Issued", value: `${formatIsoTimestamp(evidence.summary.issuedAt)} UTC` },
    { label: "Current state", value: evidence.summary.lifecycleState },
    ...(evidence.summary.publicId === null
      ? []
      : [{ label: "Public credential ID", value: evidence.summary.publicId }]),
    ...(evidence.summary.attributedOrgUnitName === null
      ? []
      : [{ label: "Attributed org unit", value: evidence.summary.attributedOrgUnitName }]),
  ];

  const issuanceRows = [
    { label: "How issued", value: evidence.issuance.sourceLabel },
    ...(evidence.issuance.issuerLabel === null
      ? []
      : [{ label: "Issued by", value: evidence.issuance.issuerLabel }]),
  ];

  const ruleRows =
    evidence.rule === null
      ? []
      : [
          { label: "Rule", value: evidence.rule.ruleName },
          { label: "Version", value: String(evidence.rule.versionNumber) },
          { label: "Version status", value: evidence.rule.versionStatus },
          ...(evidence.rule.submittedAt === null
            ? []
            : [
                {
                  label: "Submitted",
                  value: `${formatIsoTimestamp(evidence.rule.submittedAt)} UTC`,
                },
              ]),
          ...(evidence.rule.approvedAt === null
            ? []
            : [
                {
                  label: "Approved",
                  value: `${formatIsoTimestamp(evidence.rule.approvedAt)} UTC`,
                },
              ]),
          ...(evidence.rule.activatedAt === null
            ? []
            : [
                {
                  label: "Activated",
                  value: `${formatIsoTimestamp(evidence.rule.activatedAt)} UTC`,
                },
              ]),
          ...(evidence.rule.changeSummary === null
            ? []
            : [{ label: "Change summary", value: evidence.rule.changeSummary }]),
        ];

  return (
    <main class="assertion-evidence">
      <header class="assertion-evidence__header">
        <p class="assertion-evidence__eyebrow">Credential evidence report</p>
        <h1>{evidence.summary.badgeTitle}</h1>
        <p class="assertion-evidence__lede">
          Issued to {evidence.summary.recipientIdentity} on{" "}
          {formatIsoTimestamp(evidence.summary.issuedAt)} UTC.
        </p>
        <div class="assertion-evidence__status-row">
          <AdminStatusPill tone={evidence.summary.lifecycleState}>
            {evidence.summary.lifecycleState}
          </AdminStatusPill>
          <AdminMeta>Generated {formatIsoTimestamp(evidence.generatedAt)} UTC</AdminMeta>
        </div>
        <AdminActions className="assertion-evidence__screen-actions">
          <AdminButtonLink href={input.returnHref} variant="secondary">
            Back to badge records
          </AdminButtonLink>
          <AdminButton type="button" variant="secondary" id="assertion-evidence-print">
            Print report
          </AdminButton>
          <AdminButton
            type="button"
            variant="secondary"
            id="assertion-evidence-download-json"
            data-evidence-api-path={input.evidenceApiPath}
          >
            Download JSON
          </AdminButton>
        </AdminActions>
      </header>

      <section class="assertion-evidence__section">
        <h2>Credential summary</h2>
        <DetailList rows={summaryRows} />
      </section>

      <section class="assertion-evidence__section">
        <h2>How this badge was issued</h2>
        <DetailList rows={issuanceRows} />
      </section>

      {evidence.rule === null ? null : (
        <section class="assertion-evidence__section">
          <h2>Rule and version</h2>
          <DetailList rows={ruleRows} />
        </section>
      )}

      {evidence.approvalEntries.length === 0 ? null : (
        <section class="assertion-evidence__section">
          <h2>Rule approval</h2>
          <ol class="assertion-evidence__timeline">
            {evidence.approvalEntries.map((entry) => (
              <li class="assertion-evidence__timeline-item">
                <div class="assertion-evidence__timeline-head">
                  <strong>{entry.actionLabel}</strong>
                  <span>{formatIsoTimestamp(entry.occurredAt)} UTC</span>
                </div>
                <p>
                  {entry.actorLabel}
                  {entry.actorRole === null ? "" : ` · ${entry.actorRole}`}
                </p>
                {entry.comment === null ? null : (
                  <p class="assertion-evidence__timeline-detail">{entry.comment}</p>
                )}
              </li>
            ))}
          </ol>
        </section>
      )}

      {evidence.factsSummary.length === 0 && evidence.evaluationOutcomes.length === 0 ? null : (
        <section class="assertion-evidence__section">
          <h2>Facts and evaluation</h2>
          {evidence.factsSummary.length > 0 ? (
            <ul class="assertion-evidence__facts-summary">
              {evidence.factsSummary.map((item) => (
                <li>{item}</li>
              ))}
            </ul>
          ) : null}
          {evidence.evaluationOutcomes.length > 0 ? (
            <ol class="assertion-evidence__evaluation-outcomes">
              {evidence.evaluationOutcomes.map((outcome) => (
                <li data-outcome={outcome.outcome}>{outcome.detail}</li>
              ))}
            </ol>
          ) : null}
        </section>
      )}

      {evidence.review === null ? null : (
        <section class="assertion-evidence__section">
          <h2>Manual review</h2>
          <DetailList
            rows={[
              { label: "Decision", value: evidence.review.decision },
              { label: "Reviewer", value: evidence.review.reviewerLabel },
              {
                label: "Reviewed",
                value: `${formatIsoTimestamp(evidence.review.reviewedAt)} UTC`,
              },
              ...(evidence.review.comment === null
                ? []
                : [{ label: "Comment", value: evidence.review.comment }]),
            ]}
          />
        </section>
      )}

      <section class="assertion-evidence__section">
        <h2>Changes after issuance</h2>
        <TimelineList entries={evidence.changesAfterIssuance} />
      </section>

      <footer class="assertion-evidence__support">
        <h2>Support details</h2>
        <DetailList rows={evidence.supportDetails} />
      </footer>
    </main>
  );
};

export const institutionAdminAssertionEvidencePage = (input: {
  tenant: TenantRecord;
  userId: string;
  userEmail?: string | undefined;
  membershipRole: TenantMembershipRole;
  switchOrganizationPath?: string | undefined;
  evidencePage: AssertionEvidencePageInput;
}): AppPage => {
  const { evidence } = input.evidencePage;

  return renderInstitutionAdminShellPage({
    tenant: input.tenant,
    userId: input.userId,
    ...(input.userEmail === undefined ? {} : { userEmail: input.userEmail }),
    membershipRole: input.membershipRole,
    view: "operationsIssuedBadges",
    title: `Credential evidence · ${evidence.summary.badgeTitle} · ${input.tenant.displayName}`,
    assets: ["institutionAdminCss", "assertionEvidenceCss", "assertionEvidenceJs"],
    contextJson: {},
    ...(input.switchOrganizationPath === undefined
      ? {}
      : { switchOrganizationPath: input.switchOrganizationPath }),
    children: renderAssertionEvidenceBody(input.evidencePage),
  });
};
