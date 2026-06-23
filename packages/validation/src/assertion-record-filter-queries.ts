import { z } from "zod";
import { assertionLifecycleStateSchema } from "./path-params.js";
import { resourceIdSchema } from "./primitives.js";

export const optionalBlankStringToUndefined = (input: unknown): unknown => {
  if (typeof input !== "string") {
    return input;
  }

  const trimmed = input.trim();
  return trimmed.length === 0 ? undefined : trimmed;
};

const assertionRecordDateSchema = z.iso.date();

export const tenantAssertionRecordFilterQueryShape = {
  issuedFrom: z.preprocess(optionalBlankStringToUndefined, assertionRecordDateSchema.optional()),
  issuedTo: z.preprocess(optionalBlankStringToUndefined, assertionRecordDateSchema.optional()),
  badgeTemplateId: z.preprocess(optionalBlankStringToUndefined, resourceIdSchema.optional()),
  orgUnitId: z.preprocess(optionalBlankStringToUndefined, resourceIdSchema.optional()),
  recipientQuery: z.preprocess(
    optionalBlankStringToUndefined,
    z.string().min(1).max(320).optional(),
  ),
  state: z.preprocess(optionalBlankStringToUndefined, assertionLifecycleStateSchema.optional()),
};

export const refineAssertionIssuedDateRange = (
  value: {
    issuedFrom?: string | undefined;
    issuedTo?: string | undefined;
  },
  ctx: z.RefinementCtx,
): void => {
  if (value.issuedFrom === undefined || value.issuedTo === undefined) {
    return;
  }

  if (value.issuedFrom > value.issuedTo) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["issuedTo"],
      message: "issuedTo must be on or after issuedFrom",
    });
  }
};

export const tenantAssertionRecordFilterQuerySchema = z
  .object(tenantAssertionRecordFilterQueryShape)
  .superRefine(refineAssertionIssuedDateRange);

export type TenantAssertionRecordFilterQuery = z.infer<
  typeof tenantAssertionRecordFilterQuerySchema
>;
