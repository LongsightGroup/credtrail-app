import type { GradebookRequestOptions } from "./gradebook-types";

/** Maximum wall-clock time for an LMS operation started by an HTTP request. */
export const DEFAULT_GRADEBOOK_REQUEST_TIMEOUT_MS = 15_000;

/** Combines caller cancellation with one bounded LMS operation deadline. */
export const gradebookRequestOptionsWithDeadline = (
  options: GradebookRequestOptions = {},
  timeoutMs = DEFAULT_GRADEBOOK_REQUEST_TIMEOUT_MS,
): GradebookRequestOptions => {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
    throw new Error("LMS request timeout must be a positive integer");
  }

  const deadline = AbortSignal.timeout(timeoutMs);

  return {
    signal: options.signal === undefined ? deadline : AbortSignal.any([options.signal, deadline]),
  };
};
