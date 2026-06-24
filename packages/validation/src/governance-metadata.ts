import { z } from "zod";
import { jsonObjectSchema, type JsonObject } from "./json.js";

export const ltiInstructorPlacementGovernanceSchema = z.object({
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
