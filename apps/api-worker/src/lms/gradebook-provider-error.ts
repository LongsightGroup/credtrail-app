import type { GradebookProviderKind, GradebookRequestOptions } from "./gradebook-types";

export type GradebookProviderOperation =
  | "connection"
  | "course_search"
  | "gradebook_read"
  | "learner_search";

export type GradebookProviderErrorReason =
  | "invalid_response"
  | "permission_denied"
  | "request_cancelled"
  | "request_failed"
  | "unauthorized";

interface GradebookProviderErrorInput {
  readonly providerKind: GradebookProviderKind;
  readonly operation: GradebookProviderOperation;
  readonly reason: GradebookProviderErrorReason;
  readonly statusCode: number | null;
  readonly message: string;
  readonly cause?: unknown;
}

/** A classified, telemetry-safe failure returned by an LMS adapter boundary. */
export class GradebookProviderError extends Error {
  public readonly _tag = "GradebookProviderError" as const;
  public readonly providerKind: GradebookProviderKind;
  public readonly operation: GradebookProviderOperation;
  public readonly reason: GradebookProviderErrorReason;
  public readonly statusCode: number | null;

  public constructor(input: GradebookProviderErrorInput) {
    super(input.message, input.cause === undefined ? undefined : { cause: input.cause });
    this.name = "GradebookProviderError";
    this.providerKind = input.providerKind;
    this.operation = input.operation;
    this.reason = input.reason;
    this.statusCode = input.statusCode;
  }
}

/** Classifies an LMS HTTP status without exposing response bodies or credentials. */
export const gradebookProviderHttpError = (input: {
  readonly providerKind: GradebookProviderKind;
  readonly operation: GradebookProviderOperation;
  readonly statusCode: number;
}): GradebookProviderError => {
  const reason =
    input.statusCode === 401
      ? "unauthorized"
      : input.statusCode === 403
        ? "permission_denied"
        : "request_failed";

  return new GradebookProviderError({
    ...input,
    reason,
    message: `${input.providerKind} ${input.operation} request failed (${String(input.statusCode)})`,
  });
};

/** Classifies a thrown LMS transport failure without exposing request data. */
export const gradebookProviderRequestError = (input: {
  readonly providerKind: GradebookProviderKind;
  readonly operation: GradebookProviderOperation;
  readonly cause: unknown;
  readonly options?: GradebookRequestOptions;
}): GradebookProviderError => {
  const requestCancelled = input.options?.signal?.aborted === true;

  return new GradebookProviderError({
    providerKind: input.providerKind,
    operation: input.operation,
    reason: requestCancelled ? "request_cancelled" : "request_failed",
    statusCode: null,
    message: requestCancelled
      ? `${input.providerKind} ${input.operation} request was cancelled`
      : `${input.providerKind} ${input.operation} request failed`,
    cause: input.cause,
  });
};

/** Returns whether an LMS adapter failure represents caller cancellation or a deadline. */
export const isGradebookProviderRequestCancelled = (
  cause: unknown,
  options: GradebookRequestOptions = {},
): boolean => {
  return (
    options.signal?.aborted === true ||
    (cause instanceof GradebookProviderError && cause.reason === "request_cancelled")
  );
};
