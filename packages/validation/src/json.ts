import { z } from "zod";

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[];

export interface JsonObject {
  [key: string]: JsonValue;
}

export const isValidationParseError = (error: unknown): error is z.ZodError => {
  return error instanceof z.ZodError;
};

export const queueJobTypeSchema = z.enum([
  "issue_badge",
  "revoke_badge",
  "rebuild_verification_cache",
  "import_migration_batch",
  "import_learner_record_batch",
  "generate_badge_template_image",
]);

export const idempotencyKeySchema = z.string().min(1).max(128);

export const jsonValueSchema: z.ZodType<JsonValue> = z.lazy(
  () =>
    z.union([
      z.string(),
      z.number().finite(),
      z.boolean(),
      z.null(),
      z.array(jsonValueSchema),
      z.record(z.string(), jsonValueSchema),
    ]) as z.ZodType<JsonValue>,
);

export const jsonObjectSchema: z.ZodType<JsonObject> = z.record(
  z.string(),
  jsonValueSchema,
) as z.ZodType<JsonObject>;
