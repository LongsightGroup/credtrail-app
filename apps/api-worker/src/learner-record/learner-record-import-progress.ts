import type {
  ImportLearnerRecordBatchQueueMessageRecord,
  LearnerRecordTrustLevel,
} from "@credtrail/db";

/** Progress summary for one learner-record import batch. */
export interface LearnerRecordImportBatchProgressSummary {
  readonly batchId: string;
  readonly fileName: string | null;
  readonly format: string | null;
  readonly totalRows: number;
  readonly pendingRows: number;
  readonly processingRows: number;
  readonly completedRows: number;
  readonly failedRows: number;
  readonly retryableRows: number;
  readonly failedRowNumbers: readonly number[];
  readonly latestError: string | null;
  readonly defaultTrustLevel: LearnerRecordTrustLevel | null;
  readonly firstQueuedAt: string;
  readonly lastUpdatedAt: string;
}

type MutableBatchProgressSummary = {
  -readonly [Key in keyof LearnerRecordImportBatchProgressSummary]: Key extends "failedRowNumbers"
    ? number[]
    : LearnerRecordImportBatchProgressSummary[Key];
};

/** Aggregate and per-batch learner-record import progress. */
export interface LearnerRecordImportProgress {
  readonly totals: {
    readonly messages: number;
    readonly batches: number;
    readonly pendingRows: number;
    readonly processingRows: number;
    readonly completedRows: number;
    readonly failedRows: number;
  };
  readonly batches: readonly LearnerRecordImportBatchProgressSummary[];
}

/** Summarizes row-level queue messages into batch progress for the admin workspace. */
export const summarizeLearnerRecordImportProgress = (
  messages: readonly ImportLearnerRecordBatchQueueMessageRecord[],
): LearnerRecordImportProgress => {
  const summaries = new Map<string, MutableBatchProgressSummary>();

  for (const message of messages) {
    const existing = summaries.get(message.batchId);
    const summary = existing ?? {
      batchId: message.batchId,
      fileName: message.fileName,
      format: message.format,
      totalRows: 0,
      pendingRows: 0,
      processingRows: 0,
      completedRows: 0,
      failedRows: 0,
      retryableRows: 0,
      failedRowNumbers: [],
      latestError: null,
      defaultTrustLevel: message.defaultTrustLevel,
      firstQueuedAt: message.createdAt,
      lastUpdatedAt: message.updatedAt,
    };

    summary.totalRows += 1;

    if (message.createdAt < summary.firstQueuedAt) {
      summary.firstQueuedAt = message.createdAt;
    }

    if (message.updatedAt > summary.lastUpdatedAt) {
      summary.lastUpdatedAt = message.updatedAt;
    }

    if (summary.fileName === null && message.fileName !== null) {
      summary.fileName = message.fileName;
    }

    if (summary.format === null && message.format !== null) {
      summary.format = message.format;
    }

    if (summary.defaultTrustLevel === null && message.defaultTrustLevel !== null) {
      summary.defaultTrustLevel = message.defaultTrustLevel;
    }

    if (message.lastError !== null && message.lastError.trim().length > 0) {
      summary.latestError = message.lastError;
    }

    if (message.status === "pending") {
      summary.pendingRows += 1;
    } else if (message.status === "processing") {
      summary.processingRows += 1;
    } else if (message.status === "completed") {
      summary.completedRows += 1;
    } else {
      summary.failedRows += 1;
      summary.retryableRows += 1;

      if (message.rowNumber !== null) {
        summary.failedRowNumbers.push(message.rowNumber);
      }
    }

    if (existing === undefined) {
      summaries.set(message.batchId, summary);
    }
  }

  const batches = Array.from(summaries.values())
    .map((summary) => {
      summary.failedRowNumbers.sort((left, right) => left - right);
      return {
        ...summary,
        failedRowNumbers: summary.failedRowNumbers.slice(0, 50),
      };
    })
    .sort((left, right) => right.lastUpdatedAt.localeCompare(left.lastUpdatedAt));

  return {
    totals: batches.reduce(
      (accumulator, batch) => {
        accumulator.messages += batch.totalRows;
        accumulator.pendingRows += batch.pendingRows;
        accumulator.processingRows += batch.processingRows;
        accumulator.completedRows += batch.completedRows;
        accumulator.failedRows += batch.failedRows;
        return accumulator;
      },
      {
        messages: 0,
        batches: batches.length,
        pendingRows: 0,
        processingRows: 0,
        completedRows: 0,
        failedRows: 0,
      },
    ),
    batches,
  };
};
