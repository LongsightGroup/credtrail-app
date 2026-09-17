import type { HtmlEscapedString } from "hono/utils/html";
import { learnerRecordImportState } from "../../learner-record/learner-record-import-progress";
import { formatIsoTimestamp } from "../../utils/display-format";
import {
  AdminActions,
  AdminButton,
  AdminButtonLink,
  AdminField,
  AdminForm,
  AdminPanel,
  AdminTable,
} from "../components";
import { CtInput, CtSelect } from "../../ui/forms";
import type { InstitutionAdminLearnerRecordImportWorkflow } from "./page-types";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;
/** Renders the upload, reviewed preview, and list-first import history. */
export const renderLearnerRecordImportSections = (input: {
  tenantDisplayName: string;
  operationsLearnerRecordsPath: string;
  operationsLearnerRecordImportsPath: string;
  learnerRecordImportWorkflow: InstitutionAdminLearnerRecordImportWorkflow;
}): {
  learnerRecordImportPanelMarkup: HonoElement;
  learnerRecordImportFeedbackMarkup: HonoElement | null;
  learnerRecordImportSubmissionMarkup: HonoElement | null;
  learnerRecordImportProgressMarkup: HonoElement;
} => {
  const { learnerRecordImportWorkflow: workflow, operationsLearnerRecordImportsPath: path } = input;
  const submission = workflow.submission;
  const imported = workflow.importedLearners;
  const active = workflow.progress.totals.pendingRows + workflow.progress.totals.processingRows > 0;
  return {
    learnerRecordImportPanelMarkup: (
      <section class="ct-stack">
        <header class="ct-action-group">
          <h2>Import history</h2>
          <AdminButtonLink href={`${path}?upload=1#learner-import-upload`}>
            Import learner records
          </AdminButtonLink>
        </header>
        {workflow.showUpload ? (
          <AdminPanel id="learner-import-upload">
            <h3>Import learner records</h3>
            <p>
              Upload a CSV and review its rows before importing. This adds learner records; it does
              not issue badges.
            </p>
            <AdminButtonLink href={workflow.templatePath} variant="quiet">
              Download CSV template
            </AdminButtonLink>
            <AdminForm
              method="post"
              encType="multipart/form-data"
              action={workflow.previewPath}
              className="ct-admin__form ct-admin__setup-form ct-stack"
            >
              <AdminField label="Default record trust">
                <CtSelect name="defaultTrustLevel">
                  <option
                    value="issuer_verified"
                    selected={workflow.defaults.defaultTrustLevel === "issuer_verified"}
                  >
                    Issuer verified
                  </option>
                  <option
                    value="learner_supplemental"
                    selected={workflow.defaults.defaultTrustLevel === "learner_supplemental"}
                  >
                    Learner supplemental
                  </option>
                </CtSelect>
              </AdminField>
              <AdminField label="Default issuer name">
                <CtInput
                  name="defaultIssuerName"
                  type="text"
                  value={workflow.defaults.defaultIssuerName}
                  placeholder={input.tenantDisplayName}
                />
              </AdminField>
              <AdminField label="CSV file">
                <CtInput name="file" type="file" accept=".csv,text/csv" required />
              </AdminField>
              <AdminActions>
                <AdminButton type="submit">Preview import</AdminButton>
                <AdminButtonLink href={path} variant="quiet">
                  Cancel
                </AdminButtonLink>
              </AdminActions>
            </AdminForm>
          </AdminPanel>
        ) : null}
      </section>
    ),
    learnerRecordImportFeedbackMarkup: workflow.feedback ? (
      <AdminPanel
        dataAttributes={{ "data-learner-record-import-feedback": workflow.feedback.tone }}
      >
        <h2>{workflow.feedback.title}</h2>
        <p role="status">{workflow.feedback.detail}</p>
      </AdminPanel>
    ) : null,
    learnerRecordImportSubmissionMarkup: submission ? (
      <AdminPanel dataAttributes={{ "data-learner-record-import-state": submission.mode }}>
        <h2>{submission.mode === "apply" ? "Queued batch" : "Preview batch"}</h2>
        <p>
          <strong>{submission.fileName}</strong> · {submission.totalRows} rows
        </p>
        <p>
          {submission.validRows} valid rows · {submission.invalidRows} invalid rows
          {submission.mode === "apply" ? ` · ${submission.queuedRows} queued` : ""}
        </p>
        {submission.mode === "preview" ? (
          <p>
            Import {submission.validRows} valid {submission.validRows === 1 ? "row" : "rows"};{" "}
            {submission.invalidRows} invalid{" "}
            {submission.invalidRows === 1 ? "row will" : "rows will"} be skipped. Importing adds
            learner records and does not issue badges. Review warnings before continuing.
          </p>
        ) : (
          <p>The valid rows are queued for background processing. Follow their progress below.</p>
        )}
        {submission.queueForm ? (
          <AdminForm method="post" action={workflow.applyPath}>
            <CtInput type="hidden" name="batchId" value={submission.queueForm.batchId} />
            <AdminButton type="submit">
              Import {submission.validRows} valid {submission.validRows === 1 ? "row" : "rows"}
            </AdminButton>
          </AdminForm>
        ) : submission.mode === "preview" ? (
          <p>No valid rows are ready to import. Correct the CSV and preview it again.</p>
        ) : null}
        <AdminActions>
          <label hidden data-import-attention-control="true">
            <input type="checkbox" data-import-attention="true" /> Show rows needing attention
          </label>
          <AdminButtonLink
            href={`${path}/${encodeURIComponent(submission.batchId)}/errors.csv`}
            variant="secondary"
          >
            Download error report
          </AdminButtonLink>
          <AdminButtonLink href={`${path}?upload=1#learner-import-upload`} variant="quiet">
            Upload corrected CSV
          </AdminButtonLink>
        </AdminActions>
        <p>
          Rows needing attention include invalid rows and valid rows with warnings. Error reports
          are available for 24 hours after preview.
        </p>
        <p id="import-preview-filter-status" role="status"></p>
        <AdminTable headers={["Row", "Status", "Learner and record", "Trust and issuer", "Notes"]}>
          {submission.rows.map((report) => (
            <tr
              data-import-preview-row="true"
              data-needs-attention={String(
                report.status === "invalid" || report.warnings.length > 0,
              )}
            >
              <td>{report.rowNumber}</td>
              <td>{report.status === "valid" ? "Valid" : "Invalid"}</td>
              <td>
                {report.preview
                  ? `${report.preview.learner.email} · ${report.preview.record.title}`
                  : "Correct this row to preview its record"}
              </td>
              <td>
                {report.preview
                  ? `${report.preview.trustLevel === "issuer_verified" ? "Issuer verified" : "Learner supplemental"} · ${report.preview.issuerName}`
                  : "Unavailable"}
              </td>
              <td>
                {[...report.errors, ...report.warnings].length ? (
                  <ul>
                    {[...report.errors, ...report.warnings].map((note) => (
                      <li>{note}</li>
                    ))}
                  </ul>
                ) : (
                  "Ready to import"
                )}
                {report.preview?.smartContext.orgUnitLabel ? (
                  <p>Org unit: {report.preview.smartContext.orgUnitLabel}</p>
                ) : null}
                {report.preview?.smartContext.badgeTemplateLabel ? (
                  <p>Badge context: {report.preview.smartContext.badgeTemplateLabel}</p>
                ) : null}
                {report.preview?.smartContext.pathwayLabel ? (
                  <p>Pathway hint: {report.preview.smartContext.pathwayLabel}</p>
                ) : null}
              </td>
            </tr>
          ))}
        </AdminTable>
        <details>
          <summary>Batch reference</summary>
          <p>{submission.batchId}</p>
        </details>
      </AdminPanel>
    ) : null,
    learnerRecordImportProgressMarkup: (
      <>
        {imported ? (
          <AdminPanel id="imported-learners">
            <h2>Imported learners</h2>
            <p>Only successfully saved records from this batch appear here.</p>
            <AdminTable headers={["Learner", "Imported records", "Actions"]}>
              {imported.rows.length ? (
                imported.rows.map((learner) => (
                  <tr>
                    <td>
                      {learner.displayName ?? learner.email ?? "Learner"}
                      {learner.displayName && learner.email ? <p>{learner.email}</p> : null}
                    </td>
                    <td>{learner.records}</td>
                    <td>
                      {learner.email ? (
                        <AdminButtonLink
                          href={`${input.operationsLearnerRecordsPath}?${new URLSearchParams({ learner: learner.email })}`}
                        >
                          View learner record
                        </AdminButtonLink>
                      ) : (
                        "Learner email unavailable"
                      )}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colspan={3}>
                    No imported learners on this page yet. Check the batch progress below.
                  </td>
                </tr>
              )}
            </AdminTable>
            <AdminActions>
              {imported.next ? (
                <AdminButtonLink
                  href={`${path}?${new URLSearchParams({ batch: imported.batchId, after: imported.next })}#imported-learners`}
                >
                  More learners
                </AdminButtonLink>
              ) : null}
              {imported.after ? (
                <AdminButtonLink
                  href={`${path}?${new URLSearchParams({ batch: imported.batchId })}#imported-learners`}
                >
                  First learners
                </AdminButtonLink>
              ) : null}
              <AdminButtonLink href={path} variant="quiet">
                Close
              </AdminButtonLink>
            </AdminActions>
          </AdminPanel>
        ) : null}
        <section
          id="learner-import-progress"
          class="ct-admin__panel ct-stack"
          data-import-active={String(active)}
          data-progress-url={path}
          aria-label="Import history"
        >
          <h2>Current import progress</h2>
          <p>The 20 most recently updated batches. Counts include every row in each batch.</p>
          <p>
            Queued batches wait for processing. Completed rows are saved learner records. Failed
            rows can be retried without importing successful rows again.
          </p>
          <p role="status" data-import-refresh-status="true">
            {active
              ? "Progress refreshes automatically while work remains. You can leave this page; importing continues."
              : "No imports in this list are waiting or processing."}
          </p>
          <AdminActions>
            <AdminButtonLink
              href={path}
              variant="quiet"
              dataAttributes={{ "data-refresh-imports": "true" }}
            >
              Refresh progress
            </AdminButtonLink>
          </AdminActions>
          <AdminTable headers={["File", "Status", "Progress", "Updated (UTC)", "Actions"]}>
            {workflow.progress.batches.length ? (
              workflow.progress.batches.map((batch) => (
                <tr data-learner-record-import-batch={batch.batchId}>
                  <td>
                    <strong>{batch.fileName ?? "CSV import"}</strong>
                    <details>
                      <summary>Batch reference</summary>
                      {batch.batchId}
                    </details>
                  </td>
                  <td>{learnerRecordImportState(batch)}</td>
                  <td>
                    {batch.completedRows} of {batch.totalRows} completed
                    <br />
                    {batch.pendingRows} queued · {batch.processingRows} processing ·{" "}
                    {batch.failedRows} failed
                  </td>
                  <td>
                    <time datetime={batch.lastUpdatedAt}>
                      {formatIsoTimestamp(batch.lastUpdatedAt)} UTC
                    </time>
                  </td>
                  <td>
                    <AdminActions>
                      {batch.completedRows > 0 ? (
                        <AdminButtonLink
                          href={`${path}?${new URLSearchParams({ batch: batch.batchId })}#imported-learners`}
                          variant="secondary"
                        >
                          View imported learners
                        </AdminButtonLink>
                      ) : null}
                      {batch.failedRows > 0 ? (
                        <AdminForm
                          method="post"
                          action={`${path}/${encodeURIComponent(batch.batchId)}/retry`}
                        >
                          <AdminButton type="submit" variant="secondary">
                            Retry failed rows
                          </AdminButton>
                        </AdminForm>
                      ) : null}
                    </AdminActions>
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colspan={5}>
                  No imports yet. Choose Import learner records to preview your first CSV.
                </td>
              </tr>
            )}
          </AdminTable>
        </section>
      </>
    ),
  };
};
