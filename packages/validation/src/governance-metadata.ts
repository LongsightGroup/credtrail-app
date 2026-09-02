import { z } from "zod";
import { jsonObjectSchema, type JsonObject } from "./json.js";

export const ltiInstructorPlacementGovernanceSchema = z.object({
  enabled: z.boolean(),
});

const ltiInstructorPlacementPolicyRequestSchema = z.strictObject({
  enabled: z.boolean(),
});

export const governanceMetadataSchema = jsonObjectSchema.superRefine((value, ctx) => {
  const placement = value.ltiInstructorPlacement;

  if (placement === undefined) {
    return;
  }

  const parsedPlacement = ltiInstructorPlacementGovernanceSchema.safeParse(placement);

  if (!parsedPlacement.success) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["ltiInstructorPlacement"],
      message: "ltiInstructorPlacement must be an object with enabled: boolean",
    });
  }
});

export type GovernanceMetadata = JsonObject;
/** Parsed request to allow or prevent future instructor-created LMS placements. */
export type LtiInstructorPlacementPolicyRequest = z.infer<
  typeof ltiInstructorPlacementPolicyRequestSchema
>;

type SetLtiInstructorPlacementPolicyResult =
  | { readonly status: "updated"; readonly governanceMetadataJson: string }
  | { readonly status: "invalid_existing_metadata" };

/** Parses an LMS instructor-placement policy command at an external boundary. */
export const parseLtiInstructorPlacementPolicyRequest = (
  input: unknown,
): LtiInstructorPlacementPolicyRequest => {
  return ltiInstructorPlacementPolicyRequestSchema.parse(input);
};

export const parseGovernanceMetadataJson = (
  governanceMetadataJson: string | null,
): GovernanceMetadata | null => {
  if (governanceMetadataJson === null) {
    return null;
  }

  let parsed: unknown;

  try {
    parsed = JSON.parse(governanceMetadataJson) as unknown;
  } catch {
    return null;
  }

  const result = governanceMetadataSchema.safeParse(parsed);

  return result.success ? result.data : null;
};

export const isLtiInstructorPlacementEnabled = (governanceMetadataJson: string | null): boolean => {
  const metadata = parseGovernanceMetadataJson(governanceMetadataJson);

  if (metadata === null) {
    return false;
  }

  const placement = metadata.ltiInstructorPlacement;

  if (placement === undefined) {
    return false;
  }

  const parsedPlacement = ltiInstructorPlacementGovernanceSchema.safeParse(placement);

  return parsedPlacement.success && parsedPlacement.data.enabled === true;
};

/**
 * Sets the instructor-placement policy while preserving every other valid governance field.
 * Invalid stored metadata is reported instead of being overwritten.
 */
export const setLtiInstructorPlacementPolicy = (
  governanceMetadataJson: string | null,
  enabled: boolean,
): SetLtiInstructorPlacementPolicyResult => {
  const metadata =
    governanceMetadataJson === null ? {} : parseGovernanceMetadataJson(governanceMetadataJson);

  if (metadata === null) {
    return { status: "invalid_existing_metadata" };
  }

  return {
    status: "updated",
    governanceMetadataJson: JSON.stringify({
      ...metadata,
      ltiInstructorPlacement: { enabled },
    }),
  };
};
