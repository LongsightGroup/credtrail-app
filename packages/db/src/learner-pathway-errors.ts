/** Stable workflow failures that an HTTP adapter may safely present to an administrator. */
export type LearnerPathwayCommandErrorCode = "invalid" | "not_found" | "conflict" | "not_ready";

/** Expected learner-pathway command failure with a machine-readable error code. */
export class LearnerPathwayCommandError extends Error {
  public readonly _tag = "LearnerPathwayCommandError";

  public constructor(
    public readonly code: LearnerPathwayCommandErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "LearnerPathwayCommandError";
  }
}

/** Narrows an unknown failure to an expected learner-pathway command failure. */
export const isLearnerPathwayCommandError = (
  cause: unknown,
): cause is LearnerPathwayCommandError => {
  return cause instanceof LearnerPathwayCommandError;
};
