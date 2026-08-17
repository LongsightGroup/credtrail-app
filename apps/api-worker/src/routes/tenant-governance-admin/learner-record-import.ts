import {
  createLearnerRecordImportPreview,
  listImportLearnerRecordBatchQueueMessages,
  type LearnerRecordTrustLevel,
  type TenantMembershipRole,
} from "@credtrail/db";
import { parseLearnerRecordImportBatchDefaults } from "@credtrail/validation";
import { institutionAdminLearnerRecordImportsPage } from "../../admin/institution-admin/page";
import type { AppContext } from "../../app/types";
import type { ResolveDatabase } from "../../app/route-deps";
import { prepareLearnerRecordImportSubmission } from "../../learner-record/learner-record-import-preparation";
import { summarizeLearnerRecordImportProgress } from "../../learner-record/learner-record-import-progress";
import { queueReviewedLearnerRecordImportPreview } from "../../learner-record/learner-record-import-queue";
import { renderAppPage } from "../../ui/render-page";
import type { InstitutionAdminPageData } from "../institution-admin-page-data-loader";
import type { TenantGovernanceAdminPageDataLoaders } from "./page-data";

const LEARNER_RECORD_IMPORT_PREVIEW_TTL_HOURS = 24;

const addHoursToIso = (fromIso: string, hours: number): string => {
  const fromMs = Date.parse(fromIso);
  if (!Number.isFinite(fromMs)) {
    throw new Error("Invalid ISO timestamp");
  }
  return new Date(fromMs + hours * 60 * 60 * 1000).toISOString();
};

const getOptionalFormValue = (formData: FormData, name: string): string | undefined => {
  const value = formData.get(name);
  if (typeof value !== "string") {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed.length === 0 ? undefined : trimmed;
};

export const createTenantGovernanceLearnerRecordImportAdmin = (input: {
  resolveDatabase: ResolveDatabase;
  loadInstitutionAdminPageData: TenantGovernanceAdminPageDataLoaders["loadInstitutionAdminPageData"];
}) => {
  const { resolveDatabase, loadInstitutionAdminPageData } = input;

  const loadLearnerRecordImportPageData = async (input: {
    c: AppContext;
    tenantId: string;
    sessionUserId: string;
    membershipRole: TenantMembershipRole;
    workflow?: Pick<
      NonNullable<InstitutionAdminPageData["learnerRecordImportWorkflow"]>,
      "defaults" | "submission" | "feedback"
    >;
  }): Promise<InstitutionAdminPageData | Response> => {
    const pageData = await loadInstitutionAdminPageData(
      input.c,
      input.tenantId,
      input.sessionUserId,
      input.membershipRole,
    );

    if (pageData instanceof Response) {
      return pageData;
    }

    const progress = summarizeLearnerRecordImportProgress(
      await listImportLearnerRecordBatchQueueMessages(resolveDatabase(input.c.env), {
        tenantId: input.tenantId,
        limit: 100,
      }),
    );

    return {
      ...pageData,
      learnerRecordImportWorkflow: {
        templatePath: `/v1/tenants/${encodeURIComponent(input.tenantId)}/learner-record-imports/template.csv`,
        previewPath: `/tenants/${encodeURIComponent(input.tenantId)}/admin/operations/learner-record-imports/preview`,
        applyPath: `/tenants/${encodeURIComponent(input.tenantId)}/admin/operations/learner-record-imports/apply`,
        defaults: input.workflow?.defaults ?? {
          defaultTrustLevel: "issuer_verified" as LearnerRecordTrustLevel,
          defaultIssuerName: "",
        },
        submission: input.workflow?.submission ?? null,
        feedback: input.workflow?.feedback ?? null,
        progress,
      },
    };
  };

  const renderLearnerRecordImportWorkspace = async (
    c: AppContext,
    tenantId: string,
    sessionUserId: string,
    membershipRole: TenantMembershipRole,
    workflow?: Pick<
      NonNullable<InstitutionAdminPageData["learnerRecordImportWorkflow"]>,
      "defaults" | "submission" | "feedback"
    >,
  ): Promise<Response> => {
    const pageData = await loadLearnerRecordImportPageData({
      c,
      tenantId,
      sessionUserId,
      membershipRole,
      ...(workflow === undefined ? {} : { workflow }),
    });

    if (pageData instanceof Response) {
      return pageData;
    }

    c.header("Cache-Control", "no-store");
    return renderAppPage(c, institutionAdminLearnerRecordImportsPage(pageData));
  };

  const handleLearnerRecordImportUpload = async (input: {
    c: AppContext;
    tenantId: string;
    sessionUserId: string;
    membershipRole: TenantMembershipRole;
    mode: "preview" | "apply";
  }): Promise<Response> => {
    const contentType = input.c.req.header("content-type")?.toLowerCase() ?? "";

    if (
      !contentType.includes("multipart/form-data") &&
      !contentType.includes("application/x-www-form-urlencoded")
    ) {
      return renderLearnerRecordImportWorkspace(
        input.c,
        input.tenantId,
        input.sessionUserId,
        input.membershipRole,
        {
          defaults: {
            defaultTrustLevel: "issuer_verified",
            defaultIssuerName: "",
          },
          submission: null,
          feedback: {
            tone: "warning",
            title: "Upload requires CSV form data",
            detail: 'Use multipart form upload with a file field named "file".',
          },
        },
      );
    }

    const formData = await input.c.req.formData();
    const db = resolveDatabase(input.c.env);

    if (input.mode === "apply") {
      const batchId = getOptionalFormValue(formData, "batchId") ?? "";
      const nowIso = new Date().toISOString();

      if (batchId.length === 0) {
        return renderLearnerRecordImportWorkspace(
          input.c,
          input.tenantId,
          input.sessionUserId,
          input.membershipRole,
          {
            defaults: {
              defaultTrustLevel: "issuer_verified",
              defaultIssuerName: "",
            },
            submission: null,
            feedback: {
              tone: "warning",
              title: "Preview is required before queueing",
              detail: "Preview the CSV first, then use the queue action shown under the preview.",
            },
          },
        );
      }

      let queueResult: Awaited<ReturnType<typeof queueReviewedLearnerRecordImportPreview>>;

      try {
        queueResult = await queueReviewedLearnerRecordImportPreview(db, {
          tenantId: input.tenantId,
          batchId,
          queuedAt: nowIso,
        });
      } catch {
        return renderLearnerRecordImportWorkspace(
          input.c,
          input.tenantId,
          input.sessionUserId,
          input.membershipRole,
          {
            defaults: {
              defaultTrustLevel: "issuer_verified",
              defaultIssuerName: "",
            },
            submission: null,
            feedback: {
              tone: "warning",
              title: "Reviewed preview could not be queued",
              detail:
                "Check import progress before trying again. If this batch does not appear, preview the CSV again.",
            },
          },
        );
      }

      if (queueResult.status === "missing") {
        return renderLearnerRecordImportWorkspace(
          input.c,
          input.tenantId,
          input.sessionUserId,
          input.membershipRole,
          {
            defaults: {
              defaultTrustLevel: "issuer_verified",
              defaultIssuerName: "",
            },
            submission: null,
            feedback: {
              tone: "warning",
              title: "Reviewed preview is no longer available",
              detail: "Preview the CSV again, then use the queue action shown under the preview.",
            },
          },
        );
      }

      if (queueResult.status === "invalid_preview") {
        const defaults = queueResult.defaults ?? {
          defaultTrustLevel: "issuer_verified" as const,
        };
        const defaultIssuerName = defaults.defaultIssuerName ?? "";
        return renderLearnerRecordImportWorkspace(
          input.c,
          input.tenantId,
          input.sessionUserId,
          input.membershipRole,
          {
            defaults: {
              defaultTrustLevel: defaults.defaultTrustLevel,
              defaultIssuerName,
            },
            submission: null,
            feedback: {
              tone: "warning",
              title: "Reviewed preview could not be queued",
              detail: "Preview the CSV again so CredTrail can rebuild the reviewed queue payload.",
            },
          },
        );
      }

      const defaultIssuerName = queueResult.defaults.defaultIssuerName ?? "";

      if (queueResult.status === "already_queued") {
        return renderLearnerRecordImportWorkspace(
          input.c,
          input.tenantId,
          input.sessionUserId,
          input.membershipRole,
          {
            defaults: {
              defaultTrustLevel: queueResult.defaults.defaultTrustLevel,
              defaultIssuerName,
            },
            submission: null,
            feedback: {
              tone: "warning",
              title: "Reviewed preview was already queued",
              detail: "Open the import progress table below to review the queued batch.",
            },
          },
        );
      }

      const reports = queueResult.reports;
      const validRows = reports.filter((report) => report.status === "valid").length;
      const invalidRows = reports.length - validRows;

      return renderLearnerRecordImportWorkspace(
        input.c,
        input.tenantId,
        input.sessionUserId,
        input.membershipRole,
        {
          defaults: {
            defaultTrustLevel: queueResult.defaults.defaultTrustLevel,
            defaultIssuerName,
          },
          submission: {
            mode: "apply",
            batchId: queueResult.preview.batchId,
            fileName: queueResult.preview.fileName,
            totalRows: reports.length,
            validRows,
            invalidRows,
            queuedRows: queueResult.queuedRows,
            rows: reports,
            queueForm: null,
          },
          feedback: {
            tone: "success",
            title: "Learner-record import batch queued",
            detail: `Queued ${String(queueResult.queuedRows)} valid rows from ${queueResult.preview.fileName}. Invalid rows were kept out of the queue.`,
          },
        },
      );
    }

    if (!contentType.includes("multipart/form-data")) {
      return renderLearnerRecordImportWorkspace(
        input.c,
        input.tenantId,
        input.sessionUserId,
        input.membershipRole,
        {
          defaults: {
            defaultTrustLevel: "issuer_verified",
            defaultIssuerName: "",
          },
          submission: null,
          feedback: {
            tone: "warning",
            title: "Upload requires CSV form data",
            detail: 'Use multipart form upload with a file field named "file".',
          },
        },
      );
    }

    const upload = formData.get("file");
    const defaultIssuerName = getOptionalFormValue(formData, "defaultIssuerName") ?? "";
    let defaults;

    try {
      defaults = parseLearnerRecordImportBatchDefaults({
        defaultTrustLevel: getOptionalFormValue(formData, "defaultTrustLevel"),
        ...(defaultIssuerName.length === 0 ? {} : { defaultIssuerName }),
      });
    } catch {
      return renderLearnerRecordImportWorkspace(
        input.c,
        input.tenantId,
        input.sessionUserId,
        input.membershipRole,
        {
          defaults: {
            defaultTrustLevel: "issuer_verified",
            defaultIssuerName,
          },
          submission: null,
          feedback: {
            tone: "warning",
            title: "Import defaults are invalid",
            detail: "Choose a valid batch trust default before previewing or queueing the import.",
          },
        },
      );
    }

    let fileContent: string;
    let fileName: string;

    if (upload instanceof File && upload.size > 0) {
      fileContent = await upload.text();
      fileName = upload.name;
    } else {
      return renderLearnerRecordImportWorkspace(
        input.c,
        input.tenantId,
        input.sessionUserId,
        input.membershipRole,
        {
          defaults: {
            defaultTrustLevel: defaults.defaultTrustLevel,
            defaultIssuerName,
          },
          submission: null,
          feedback: {
            tone: "warning",
            title: "CSV file is required",
            detail: 'Attach a CSV file in the "file" field to preview learner-record imports.',
          },
        },
      );
    }

    if (fileContent.trim().length === 0) {
      return renderLearnerRecordImportWorkspace(
        input.c,
        input.tenantId,
        input.sessionUserId,
        input.membershipRole,
        {
          defaults: {
            defaultTrustLevel: defaults.defaultTrustLevel,
            defaultIssuerName,
          },
          submission: null,
          feedback: {
            tone: "warning",
            title: "Uploaded CSV is empty",
            detail: "Add at least one learner-record row before previewing or queueing the batch.",
          },
        },
      );
    }

    let prepared;
    const requestedAt = new Date().toISOString();

    try {
      prepared = await prepareLearnerRecordImportSubmission(db, {
        tenantId: input.tenantId,
        fileName,
        content: fileContent,
        defaults,
        requestedAt,
        requestedByUserId: input.sessionUserId,
      });
    } catch (error: unknown) {
      return renderLearnerRecordImportWorkspace(
        input.c,
        input.tenantId,
        input.sessionUserId,
        input.membershipRole,
        {
          defaults: {
            defaultTrustLevel: defaults.defaultTrustLevel,
            defaultIssuerName,
          },
          submission: null,
          feedback: {
            tone: "warning",
            title: "Import file could not be prepared",
            detail:
              error instanceof Error
                ? error.message
                : "CredTrail could not parse this learner-record CSV.",
          },
        },
      );
    }

    const validRows = prepared.reports.filter((report) => report.status === "valid").length;
    const invalidRows = prepared.reports.length - validRows;

    if (validRows > 0) {
      await createLearnerRecordImportPreview(db, {
        tenantId: input.tenantId,
        batchId: prepared.batchId,
        fileName: prepared.fileName,
        format: prepared.format,
        defaultsJson: JSON.stringify(prepared.defaults),
        reportsJson: JSON.stringify(prepared.reports),
        queuePayloadsJson: JSON.stringify(prepared.queuePayloads),
        createdByUserId: input.sessionUserId,
        createdAt: requestedAt,
        expiresAt: addHoursToIso(requestedAt, LEARNER_RECORD_IMPORT_PREVIEW_TTL_HOURS),
      });
    }

    return renderLearnerRecordImportWorkspace(
      input.c,
      input.tenantId,
      input.sessionUserId,
      input.membershipRole,
      {
        defaults: {
          defaultTrustLevel: defaults.defaultTrustLevel,
          defaultIssuerName,
        },
        submission: {
          mode: "preview",
          batchId: prepared.batchId,
          fileName: prepared.fileName,
          totalRows: prepared.reports.length,
          validRows,
          invalidRows,
          queuedRows: 0,
          rows: prepared.reports,
          queueForm: validRows > 0 ? { batchId: prepared.batchId } : null,
        },
        feedback: {
          tone: "warning",
          title: "Learner-record import preview ready",
          detail:
            "Review trust classification, smart defaults, and warnings below before queueing the import.",
        },
      },
    );
  };

  return {
    loadLearnerRecordImportPageData,
    renderLearnerRecordImportWorkspace,
    handleLearnerRecordImportUpload,
  };
};
