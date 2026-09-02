import { z } from "zod";

const placementAvailabilityIdentifierSchema = z.string().trim().min(1).max(255);

const selectedCoursesAvailabilitySchema = z
  .strictObject({
    scope: z.literal("selected_courses"),
    courseContextIds: z.array(placementAvailabilityIdentifierSchema).min(1).max(500),
  })
  .superRefine((value, context) => {
    if (new Set(value.courseContextIds).size !== value.courseContextIds.length) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["courseContextIds"],
        message: "Course context IDs must be unique",
      });
    }
  });

const orgUnitSubtreeAvailabilitySchema = z.strictObject({
  scope: z.literal("org_unit_subtree"),
  rootOrgUnitId: placementAvailabilityIdentifierSchema,
});

const tenantAvailabilitySchema = z.strictObject({
  scope: z.literal("tenant"),
});

/** Closed transport schema for replacing one rule's placement availability. */
export const replaceBadgeRulePlacementAvailabilityRequestSchema = z.discriminatedUnion("scope", [
  selectedCoursesAvailabilitySchema,
  orgUnitSubtreeAvailabilitySchema,
  tenantAvailabilitySchema,
]);

/** Parsed request for replacing one rule's placement availability. */
export type ReplaceBadgeRulePlacementAvailabilityRequest = z.infer<
  typeof replaceBadgeRulePlacementAvailabilityRequestSchema
>;

/** Parses an untrusted placement-availability replacement request. */
export const parseReplaceBadgeRulePlacementAvailabilityRequest = (
  input: unknown,
): ReplaceBadgeRulePlacementAvailabilityRequest => {
  return replaceBadgeRulePlacementAvailabilityRequestSchema.parse(input);
};
