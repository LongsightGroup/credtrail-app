import type { HtmlEscapedString } from "hono/utils/html";
import type { LearnerRecordImportRowReport } from "../../learner-record/learner-record-import";
import { formatIsoTimestamp } from "../../utils/display-format";
import {
  AdminActions,
  AdminButton,
  AdminButtonLink,
  AdminCtaLink,
  AdminField,
  AdminForm,
  AdminMetricCard,
  AdminPanel,
  AdminStatus,
  AdminTable,
} from "../components";
import { CtFieldHint, CtInput, CtSelect } from "../../ui/forms";
import type {
  InstitutionAdminLearnerRecordImportWorkflow,
  InstitutionAdminLearnerRecordReview,
} from "./page-types";
import { formatReportingCount } from "./reporting-helpers";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

interface RenderInstitutionAdminLearnerRecordSectionsInput {
  tenantDisplayName: string;
  operationsLearnerRecordsPath: string;
  operationsLearnerRecordImportsPath: string;
  learnerRecordReview: InstitutionAdminLearnerRecordReview;
  learnerRecordImportWorkflow: InstitutionAdminLearnerRecordImportWorkflow;
}

interface InstitutionAdminLearnerRecordSections {
  learnerRecordReviewPanelMarkup: HonoElement;
  renderLearnerRecordReviewSections: () => HonoElement;
  learnerRecordImportPanelMarkup: HonoElement;
  learnerRecordImportFeedbackMarkup: HonoElement | null;
  learnerRecordImportSubmissionMarkup: HonoElement;
  learnerRecordImportProgressMarkup: HonoElement;
}

const formatLearnerRecordReviewDetailValue = (label: string, value: string): string => {
  if (label === "Issued" || label === "Revised" || label === "Revoked") {
    return `${formatIsoTimestamp(value)} UTC`;
  }

  return value;
};

export const renderInstitutionAdminLearnerRecordSections = (
  input: RenderInstitutionAdminLearnerRecordSectionsInput,
): InstitutionAdminLearnerRecordSections => {
  const {
    tenantDisplayName,
    operationsLearnerRecordsPath,
    operationsLearnerRecordImportsPath,
    learnerRecordReview,
    learnerRecordImportWorkflow,
  } = input;

  const renderLearnerRecordReviewItem = (
    item: NonNullable<
      InstitutionAdminLearnerRecordReview["presentation"]
    >["sections"][number]["items"][number],
  ): HonoElement => {
    const descriptionMarkup = item.description === null ? null : <p>{item.description}</p>;
    const detailsMarkup =
      item.details.length === 0 ? (
        <p class="ct-admin__meta">No additional record details are attached to this item.</p>
      ) : (
        <dl class="ct-stack">
          {item.details.map((row) => (
            <div>
              <dt class="ct-admin__meta">{row.label}</dt>
              <dd>{row.value}</dd>
            </div>
          ))}
        </dl>
      );
    const provenanceMarkup = (
      <dl class="ct-stack">
        {item.provenanceDetails.map((row) => (
          <div>
            <dt class="ct-admin__meta">{row.label}</dt>
            <dd>{formatLearnerRecordReviewDetailValue(row.label, row.value)}</dd>
          </div>
        ))}
      </dl>
    );
    const evidenceMarkup =
      item.evidenceLinks.length === 0 ? null : (
        <div class="ct-stack">
          <p class="ct-admin__meta">Evidence</p>
          <ul class="ct-stack">
            {item.evidenceLinks.map((href) => (
              <li>
                <a href={href} target="_blank" rel="noopener noreferrer">
                  {href}
                </a>
              </li>
            ))}
          </ul>
        </div>
      );
    const publicBadgeMarkup =
      item.publicBadgePath === null ? null : (
        <AdminCtaLink href={item.publicBadgePath}>Open public badge</AdminCtaLink>
      );

    return (
      <AdminMetricCard stack>
        <div class="ct-stack">
          <p class="ct-admin__meta">{item.recordTypeLabel}</p>
          <h3>{item.title}</h3>
          {descriptionMarkup}
          <p class="ct-admin__meta">
            {item.trustLabel} · {item.statusLabel}
          </p>
          <p class="ct-admin__meta">{item.provenanceSummary}</p>
        </div>
        <div class="ct-stack">
          <section class="ct-stack">
            <h4>Record details</h4>
            {detailsMarkup}
          </section>
          <section class="ct-stack">
            <h4>Provenance</h4>
            {provenanceMarkup}
          </section>
          {evidenceMarkup}
        </div>
        {publicBadgeMarkup}
      </AdminMetricCard>
    );
  };

  const renderLearnerRecordReviewSections = (): HonoElement => {
    if (learnerRecordReview.lookupState === "idle") {
      return <></>;
    }

    if (learnerRecordReview.lookupState === "unresolved") {
      return (
        <AdminPanel>
          <h2>No learner record found</h2>
          <AdminStatus tone="warning">
            No learner record matched that LMS learner ID or email address. Check the value and try
            again.
          </AdminStatus>
        </AdminPanel>
      );
    }

    if (learnerRecordReview.lookupState === "ambiguous") {
      return (
        <AdminPanel>
          <h2>More than one learner matched</h2>
          <AdminStatus tone="warning">
            That value belongs to more than one learner. Use an email address to open the right
            record.
          </AdminStatus>
        </AdminPanel>
      );
    }

    const presentation = learnerRecordReview.presentation;

    if (presentation === null || learnerRecordReview.learnerProfile === null) {
      return <></>;
    }

    const exportLinksMarkup = (
      <AdminPanel>
        <h2>Export and standards mapping</h2>
        <p>
          These links point to the real Phase 27 runtime endpoints for the selected learner. They do
          not imply transcript exchange or full CLR conformance.
        </p>
        <AdminActions>
          {learnerRecordReview.exportPath === null ? null : (
            <AdminCtaLink href={learnerRecordReview.exportPath}>
              Download native portable export
            </AdminCtaLink>
          )}
          {learnerRecordReview.standardsMappingPath === null ? null : (
            <AdminCtaLink href={learnerRecordReview.standardsMappingPath}>
              Open standards mapping
            </AdminCtaLink>
          )}
        </AdminActions>
      </AdminPanel>
    );

    return (
      <section class="ct-stack">
        <AdminPanel>
          <h2>Learner overview</h2>
          <p>
            Reviewing{" "}
            <strong>
              {learnerRecordReview.learnerProfile.displayName ??
                learnerRecordReview.learnerProfile.id}
            </strong>
            .
          </p>
          <p class="ct-admin__meta">Learner profile ID: {learnerRecordReview.learnerProfile.id}</p>
          <p class="ct-admin__meta">Subject ID: {learnerRecordReview.learnerProfile.subjectId}</p>
          <section class="ct-admin__metric-grid">
            <AdminMetricCard>
              <p class="ct-admin__meta">Total items</p>
              <p class="ct-admin__metric-value">{presentation.summary.total}</p>
            </AdminMetricCard>
            <AdminMetricCard>
              <p class="ct-admin__meta">Issuer verified</p>
              <p class="ct-admin__metric-value">{presentation.summary.issuerVerified}</p>
            </AdminMetricCard>
            <AdminMetricCard>
              <p class="ct-admin__meta">Learner supplemental</p>
              <p class="ct-admin__metric-value">{presentation.summary.supplemental}</p>
            </AdminMetricCard>
            <AdminMetricCard>
              <p class="ct-admin__meta">Historical</p>
              <p class="ct-admin__metric-value">{presentation.summary.historical}</p>
            </AdminMetricCard>
          </section>
        </AdminPanel>
        {exportLinksMarkup}
        {presentation.sections.map((section) => (
          <AdminPanel>
            <h2>{section.title}</h2>
            <p>{section.description}</p>
            <p class="ct-admin__meta">{section.itemCountLabel}</p>
            <section class="ct-admin__metric-grid">
              {section.items.map((item) => renderLearnerRecordReviewItem(item))}
            </section>
          </AdminPanel>
        ))}
      </section>
    );
  };

  const learnerRecordReviewPanelMarkup = (
    <AdminPanel>
      <h2>Learner record review</h2>
      <p>
        Open a learner’s unified record using the learner ID shown in the LMS or their email
        address.
      </p>
      <AdminForm method="get" action={operationsLearnerRecordsPath}>
        <AdminField label="LMS learner ID or email">
          <CtInput
            name="learner"
            type="text"
            value={learnerRecordReview.lookup.learner ?? ""}
            required
            maxlength={320}
            describedBy="learner-record-lookup-hint"
          />
          <CtFieldHint id="learner-record-lookup-hint">
            Use the learner ID from the LMS course roster or the learner’s institution email.
          </CtFieldHint>
        </AdminField>
        <AdminActions>
          <AdminButton type="submit">Load learner record</AdminButton>
          <AdminButtonLink href={operationsLearnerRecordsPath} variant="secondary">
            Clear lookup
          </AdminButtonLink>
        </AdminActions>
      </AdminForm>
    </AdminPanel>
  );

  const renderLearnerRecordImportRowReport = (
    report: LearnerRecordImportRowReport,
  ): HonoElement => {
    const preview = report.preview;
    const contextSummary =
      preview === null
        ? "No preview"
        : [
            preview.smartContext.orgUnitLabel === null
              ? "No org-unit default"
              : `Org unit: ${preview.smartContext.orgUnitLabel}`,
            preview.smartContext.badgeTemplateLabel === null
              ? "No badge-template default"
              : `Badge template: ${preview.smartContext.badgeTemplateLabel}`,
            preview.smartContext.pathwayLabel === null
              ? "No pathway hint"
              : `Pathway hint: ${preview.smartContext.pathwayLabel}`,
          ].join(" · ");
    const notes = [...report.errors, ...report.warnings];

    return (
      <tr>
        <td>{report.rowNumber}</td>
        <td>
          <span class="ct-admin__status-pill">{report.status}</span>
        </td>
        <td>
          {preview === null
            ? "No import preview available"
            : `${preview.learner.email} · ${preview.record.title}`}
        </td>
        <td>
          {preview === null ? "Unavailable" : `${preview.trustLevel} · ${preview.issuerName}`}
        </td>
        <td>{contextSummary}</td>
        <td>{notes.length === 0 ? "Ready to apply." : notes.join(" ")}</td>
      </tr>
    );
  };

  const learnerRecordImportFeedbackMarkup =
    learnerRecordImportWorkflow.feedback === null ? null : (
      <AdminPanel
        dataAttributes={{
          "data-learner-record-import-feedback": learnerRecordImportWorkflow.feedback.tone,
        }}
      >
        <h2>{learnerRecordImportWorkflow.feedback.title}</h2>
        <p>{learnerRecordImportWorkflow.feedback.detail}</p>
      </AdminPanel>
    );

  const learnerRecordImportSubmissionMarkup =
    learnerRecordImportWorkflow.submission === null ? (
      <AdminPanel dataAttributes={{ "data-learner-record-import-state": "idle" }}>
        <h2>No batch loaded yet</h2>
        <p>
          Upload a CSV to preview trust classification, inferred org-unit or badge-template context,
          and any pathway hints before you queue the batch.
        </p>
      </AdminPanel>
    ) : (
      <AdminPanel
        dataAttributes={{
          "data-learner-record-import-state": learnerRecordImportWorkflow.submission.mode,
        }}
      >
        <h2>
          {learnerRecordImportWorkflow.submission.mode === "apply"
            ? "Queued batch"
            : "Preview batch"}
        </h2>
        <p>
          {learnerRecordImportWorkflow.submission.fileName} · batch{" "}
          {learnerRecordImportWorkflow.submission.batchId}
        </p>
        <section class="ct-admin__metric-grid">
          <AdminMetricCard>
            <p class="ct-admin__meta">Total rows</p>
            <p class="ct-admin__metric-value">
              {formatReportingCount(learnerRecordImportWorkflow.submission.totalRows)}
            </p>
          </AdminMetricCard>
          <AdminMetricCard>
            <p class="ct-admin__meta">Valid rows</p>
            <p class="ct-admin__metric-value">
              {formatReportingCount(learnerRecordImportWorkflow.submission.validRows)}
            </p>
          </AdminMetricCard>
          <AdminMetricCard>
            <p class="ct-admin__meta">Invalid rows</p>
            <p class="ct-admin__metric-value">
              {formatReportingCount(learnerRecordImportWorkflow.submission.invalidRows)}
            </p>
          </AdminMetricCard>
          <AdminMetricCard>
            <p class="ct-admin__meta">Queued rows</p>
            <p class="ct-admin__metric-value">
              {formatReportingCount(learnerRecordImportWorkflow.submission.queuedRows)}
            </p>
          </AdminMetricCard>
        </section>
        {learnerRecordImportWorkflow.submission.queueForm === null ? (
          learnerRecordImportWorkflow.submission.mode === "preview" ? (
            <p class="ct-admin__hint">No valid rows are ready to queue from this preview.</p>
          ) : null
        ) : (
          <AdminForm
            method="post"
            action={learnerRecordImportWorkflow.applyPath}
            className="ct-admin__form ct-admin__review-action-form"
          >
            <CtInput
              type="hidden"
              name="batchId"
              value={learnerRecordImportWorkflow.submission.queueForm.batchId}
            />
            <AdminActions>
              <AdminButton type="submit">Queue reviewed import</AdminButton>
            </AdminActions>
          </AdminForm>
        )}
        <AdminTable
          headers={["Row", "Status", "Learner and record", "Trust", "Smart defaults", "Notes"]}
          wrapperClassName="ct-admin__table-shell"
        >
          {learnerRecordImportWorkflow.submission.rows.map((report) =>
            renderLearnerRecordImportRowReport(report),
          )}
        </AdminTable>
      </AdminPanel>
    );

  const learnerRecordImportProgressMarkup = (
    <AdminPanel>
      <h2>Current import progress</h2>
      <p>
        These batch states come from the real learner-record import queue. Failed rows can be
        retried without replaying the whole upload.
      </p>
      <section class="ct-admin__metric-grid">
        <AdminMetricCard>
          <p class="ct-admin__meta">Batches</p>
          <p class="ct-admin__metric-value">
            {formatReportingCount(learnerRecordImportWorkflow.progress.totals.batches)}
          </p>
        </AdminMetricCard>
        <AdminMetricCard>
          <p class="ct-admin__meta">Pending rows</p>
          <p class="ct-admin__metric-value">
            {formatReportingCount(learnerRecordImportWorkflow.progress.totals.pendingRows)}
          </p>
        </AdminMetricCard>
        <AdminMetricCard>
          <p class="ct-admin__meta">Completed rows</p>
          <p class="ct-admin__metric-value">
            {formatReportingCount(learnerRecordImportWorkflow.progress.totals.completedRows)}
          </p>
        </AdminMetricCard>
        <AdminMetricCard>
          <p class="ct-admin__meta">Failed rows</p>
          <p class="ct-admin__metric-value">
            {formatReportingCount(learnerRecordImportWorkflow.progress.totals.failedRows)}
          </p>
        </AdminMetricCard>
      </section>
      {learnerRecordImportWorkflow.progress.batches.length === 0 ? (
        <p class="ct-admin__hint">
          No learner-record import batches have been queued for this tenant yet.
        </p>
      ) : (
        <section class="ct-admin__metric-grid">
          {learnerRecordImportWorkflow.progress.batches.map((batch) => {
            const retryMarkup =
              batch.failedRows === 0 ? null : (
                <AdminForm
                  method="post"
                  action={`${operationsLearnerRecordImportsPath}/${encodeURIComponent(batch.batchId)}/retry`}
                  className="ct-stack"
                >
                  <AdminButton type="submit">Retry failed rows</AdminButton>
                </AdminForm>
              );

            return (
              <AdminMetricCard
                stack
                dataAttributes={{ "data-learner-record-import-batch": batch.batchId }}
              >
                <div class="ct-stack">
                  <p class="ct-admin__meta">{batch.fileName ?? "CSV import"}</p>
                  <h3>{batch.batchId}</h3>
                  <p class="ct-admin__meta">
                    Pending {formatReportingCount(batch.pendingRows)} · Processing{" "}
                    {formatReportingCount(batch.processingRows)} · Completed{" "}
                    {formatReportingCount(batch.completedRows)} · Failed{" "}
                    {formatReportingCount(batch.failedRows)}
                  </p>
                  <p class="ct-admin__meta">Updated {formatIsoTimestamp(batch.lastUpdatedAt)}</p>
                  {batch.latestError === null ? null : (
                    <AdminStatus tone="warning">{batch.latestError}</AdminStatus>
                  )}
                </div>
                {retryMarkup}
              </AdminMetricCard>
            );
          })}
        </section>
      )}
    </AdminPanel>
  );

  const learnerRecordImportPanelMarkup = (
    <AdminPanel>
      <h2>Learner record import</h2>
      <p>
        Upload one CSV, choose the default trust classification once, and let CredTrail infer
        matching org-unit and badge-template context when current organization data supports it.
        Pathway labels stay explicit imported metadata.
      </p>
      <AdminActions>
        <AdminCtaLink href={learnerRecordImportWorkflow.templatePath}>
          Download CSV template
        </AdminCtaLink>
      </AdminActions>
      <AdminForm
        method="post"
        encType="multipart/form-data"
        action={learnerRecordImportWorkflow.previewPath}
        className="ct-admin__form ct-stack"
      >
        <AdminField label="Batch default trust level">
          <CtSelect name="defaultTrustLevel">
            <option
              value="issuer_verified"
              selected={
                learnerRecordImportWorkflow.defaults.defaultTrustLevel === "issuer_verified"
              }
            >
              issuer verified
            </option>
            <option
              value="learner_supplemental"
              selected={
                learnerRecordImportWorkflow.defaults.defaultTrustLevel === "learner_supplemental"
              }
            >
              learner supplemental
            </option>
          </CtSelect>
        </AdminField>
        <AdminField label="Default issuer name">
          <CtInput
            name="defaultIssuerName"
            type="text"
            value={learnerRecordImportWorkflow.defaults.defaultIssuerName}
            placeholder={tenantDisplayName}
          />
        </AdminField>
        <AdminField label="CSV file">
          <CtInput name="file" type="file" accept=".csv,text/csv" />
        </AdminField>
        <p class="ct-admin__hint">
          Defaults come from the current org-unit structure and badge-template ownership.
        </p>
        <AdminActions>
          <AdminButton type="submit">Preview import</AdminButton>
        </AdminActions>
      </AdminForm>
    </AdminPanel>
  );

  return {
    learnerRecordReviewPanelMarkup,
    renderLearnerRecordReviewSections,
    learnerRecordImportPanelMarkup,
    learnerRecordImportFeedbackMarkup,
    learnerRecordImportSubmissionMarkup,
    learnerRecordImportProgressMarkup,
  };
};
