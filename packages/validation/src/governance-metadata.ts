import { jsonObjectSchema, type JsonObject } from "./json.js";

export const governanceMetadataSchema = jsonObjectSchema;

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
