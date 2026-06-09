import {
  listBadgeIssuanceRuleValueLists,
  type BadgeIssuanceRuleValueListRecord,
  type SqlDatabase,
} from "@credtrail/db";
import {
  parseBadgeIssuanceRuleDefinition,
  type BadgeIssuanceRuleDefinition,
} from "@credtrail/validation";

export const resolveRuleDefinition = (
  rawRuleJson: string,
): ReturnType<typeof parseBadgeIssuanceRuleDefinition> => {
  let parsed: unknown;

  try {
    parsed = JSON.parse(rawRuleJson) as unknown;
  } catch {
    throw new Error("Stored rule JSON is invalid");
  }

  return parseBadgeIssuanceRuleDefinition(parsed);
};

function collectRuleValueListReferences(
  condition: BadgeIssuanceRuleDefinition["conditions"],
  output: Set<string>,
): void {
  if ("all" in condition) {
    for (const child of condition.all) {
      collectRuleValueListReferences(child, output);
    }

    return;
  }

  if ("any" in condition) {
    for (const child of condition.any) {
      collectRuleValueListReferences(child, output);
    }

    return;
  }

  if ("not" in condition) {
    collectRuleValueListReferences(condition.not, output);
    return;
  }

  if ("courseListId" in condition && typeof condition.courseListId === "string") {
    output.add(condition.courseListId);
  }

  if ("badgeTemplateListId" in condition && typeof condition.badgeTemplateListId === "string") {
    output.add(condition.badgeTemplateListId);
  }
}

function valueListById(
  valueLists: readonly BadgeIssuanceRuleValueListRecord[],
): Map<string, BadgeIssuanceRuleValueListRecord> {
  return new Map(valueLists.map((valueList) => [valueList.id, valueList]));
}

function resolveCourseListCondition(
  condition:
    | Extract<BadgeIssuanceRuleDefinition["conditions"], { type: "grade_threshold" }>
    | Extract<BadgeIssuanceRuleDefinition["conditions"], { type: "course_completion" }>
    | Extract<BadgeIssuanceRuleDefinition["conditions"], { type: "program_completion" }>,
  valueLists: Map<string, BadgeIssuanceRuleValueListRecord>,
): BadgeIssuanceRuleDefinition["conditions"] {
  if (condition.courseListId === undefined) {
    return condition;
  }

  const valueList = valueLists.get(condition.courseListId);

  if (valueList === undefined) {
    throw new Error(`Rule value list ${condition.courseListId} was not found`);
  }

  if (valueList.kind !== "course_ids") {
    throw new Error(`Rule value list ${condition.courseListId} is not a course list`);
  }

  if (condition.type === "program_completion") {
    return {
      type: "program_completion",
      courseIds: valueList.values,
      ...(condition.minimumCompleted === undefined
        ? {}
        : { minimumCompleted: condition.minimumCompleted }),
    };
  }

  const expandedConditions = valueList.values.map((courseId) => {
    if (condition.type === "grade_threshold") {
      return {
        type: "grade_threshold" as const,
        courseId,
        ...(condition.scoreField === undefined ? {} : { scoreField: condition.scoreField }),
        ...(condition.minScore === undefined ? {} : { minScore: condition.minScore }),
        ...(condition.maxScore === undefined ? {} : { maxScore: condition.maxScore }),
      };
    }

    return {
      type: "course_completion" as const,
      courseId,
      minCompletionPercent: condition.minCompletionPercent,
    };
  });

  return {
    any: expandedConditions,
  };
}

function resolveBadgeTemplateListCondition(
  condition: Extract<BadgeIssuanceRuleDefinition["conditions"], { type: "prerequisite_badge" }>,
  valueLists: Map<string, BadgeIssuanceRuleValueListRecord>,
): BadgeIssuanceRuleDefinition["conditions"] {
  if (condition.badgeTemplateListId === undefined) {
    return condition;
  }

  const valueList = valueLists.get(condition.badgeTemplateListId);

  if (valueList === undefined) {
    throw new Error(`Rule value list ${condition.badgeTemplateListId} was not found`);
  }

  if (valueList.kind !== "badge_template_ids") {
    throw new Error(
      `Rule value list ${condition.badgeTemplateListId} is not a badge-template list`,
    );
  }

  return {
    any: valueList.values.map((badgeTemplateId) => ({
      type: "prerequisite_badge" as const,
      badgeTemplateId,
    })),
  };
}

function resolveRuleConditionValueLists(
  condition: BadgeIssuanceRuleDefinition["conditions"],
  valueLists: Map<string, BadgeIssuanceRuleValueListRecord>,
): BadgeIssuanceRuleDefinition["conditions"] {
  if ("all" in condition) {
    return {
      all: condition.all.map((child) => resolveRuleConditionValueLists(child, valueLists)),
    };
  }

  if ("any" in condition) {
    return {
      any: condition.any.map((child) => resolveRuleConditionValueLists(child, valueLists)),
    };
  }

  if ("not" in condition) {
    return {
      not: resolveRuleConditionValueLists(condition.not, valueLists),
    };
  }

  switch (condition.type) {
    case "grade_threshold":
    case "course_completion":
    case "program_completion":
      return resolveCourseListCondition(condition, valueLists);
    case "prerequisite_badge":
      return resolveBadgeTemplateListCondition(condition, valueLists);
    case "assignment_submission":
    case "survey_completion":
    case "time_window":
    case "custom_field":
      return condition;
  }
}

export async function resolveBadgeIssuanceRuleDefinitionValueLists(
  db: SqlDatabase,
  tenantId: string,
  definition: BadgeIssuanceRuleDefinition,
): Promise<BadgeIssuanceRuleDefinition> {
  const referencedValueListIds = new Set<string>();
  collectRuleValueListReferences(definition.conditions, referencedValueListIds);

  if (referencedValueListIds.size === 0) {
    return definition;
  }

  const valueLists = await listBadgeIssuanceRuleValueLists(db, {
    tenantId,
    includeArchived: false,
  });
  const selectedValueLists = valueLists.filter((valueList) =>
    referencedValueListIds.has(valueList.id),
  );
  const resolvedDefinition = {
    ...definition,
    conditions: resolveRuleConditionValueLists(
      definition.conditions,
      valueListById(selectedValueLists),
    ),
  };

  return parseBadgeIssuanceRuleDefinition(resolvedDefinition);
}
