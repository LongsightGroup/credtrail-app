const createRuleBuilderExampleTestController = ({
  scoreField,
  scoreInput,
  scoreHint,
  completionField,
  completionInput,
  completionHint,
  guidance,
  emptyMessage,
}) => {
  let scoreAdjustable = false;
  let completionAdjustable = false;

  const leafCondition = (condition) => {
    if (condition && typeof condition === "object" && "not" in condition) {
      return condition.not;
    }

    return condition;
  };

  const configuredNumber = (value) => {
    return typeof value === "number" && Number.isFinite(value) ? value : null;
  };

  const thresholdText = (condition) => {
    const minimum = configuredNumber(condition.minScore);
    const maximum = configuredNumber(condition.maxScore);
    const boundaries = [];

    if (minimum !== null) {
      boundaries.push("at least " + String(minimum) + "%");
    }

    if (maximum !== null) {
      boundaries.push("no more than " + String(maximum) + "%");
    }

    return boundaries.join(" and ");
  };

  const scoreRequirement = (condition) => {
    if (condition.type === "grade_threshold") {
      const scoreName = condition.scoreField === "current_score" ? "current score" : "final score";
      const threshold = thresholdText(condition);
      return threshold.length > 0 ? scoreName + " " + threshold : null;
    }

    if (condition.type === "assignment_submission") {
      const minimum = configuredNumber(condition.minScore);
      return minimum === null ? null : "gradebook item score of at least " + String(minimum) + "%";
    }

    return null;
  };

  const completionRequirement = (condition) => {
    if (condition.type === "course_completion") {
      const minimum = configuredNumber(condition.minCompletionPercent) ?? 100;
      return "at least " + String(minimum) + "% of gradebook items complete";
    }

    if (condition.type === "program_completion") {
      const courseCount = Array.isArray(condition.courseIds) ? condition.courseIds.length : 0;
      const minimum = configuredNumber(condition.minimumCompleted);
      const requiredCount = minimum ?? (courseCount > 0 ? courseCount : null);
      const courseRequirement =
        requiredCount === null
          ? "the configured course pathway complete"
          : courseCount > 0
            ? String(requiredCount) +
              " of " +
              String(courseCount) +
              " configured " +
              (courseCount === 1 ? "course" : "courses") +
              " complete"
            : String(requiredCount) +
              " configured " +
              (requiredCount === 1 ? "course" : "courses") +
              " complete";
      return courseRequirement + "; generated courses count as complete at 100%";
    }

    return null;
  };

  const setFieldVisibility = (field, input, visible) => {
    field.hidden = !visible;
    input.disabled = !visible;
    input.required = visible;
  };

  const requirementsHint = (requirements) => {
    if (requirements.size === 0) {
      return "";
    }

    return (
      "Configured requirement" +
      (requirements.size === 1 ? ": " : "s: ") +
      Array.from(requirements).join("; ") +
      "."
    );
  };

  const validPercent = (value) => {
    const normalized = value.trim();
    const parsed = Number(normalized);
    return normalized.length > 0 && Number.isFinite(parsed) && parsed >= 0 && parsed <= 100;
  };

  const validationMessage = ({ score, completion }) => {
    if (scoreAdjustable && !validPercent(score)) {
      return "Example score must be a number between 0 and 100.";
    }

    if (completionAdjustable && !validPercent(completion)) {
      return "Example completion must be a number between 0 and 100.";
    }

    return null;
  };

  const sync = (conditions) => {
    const scoreRequirements = new Set();
    const completionRequirements = new Set();

    conditions.forEach((condition) => {
      const leaf = leafCondition(condition);

      if (leaf === null || typeof leaf !== "object") {
        return;
      }

      const score = scoreRequirement(leaf);
      const completion = completionRequirement(leaf);

      if (score !== null) {
        scoreRequirements.add(score);
      }

      if (completion !== null) {
        completionRequirements.add(completion);
      }
    });

    scoreAdjustable = scoreRequirements.size > 0;
    completionAdjustable = completionRequirements.size > 0;
    setFieldVisibility(scoreField, scoreInput, scoreAdjustable);
    setFieldVisibility(completionField, completionInput, completionAdjustable);

    scoreHint.textContent = requirementsHint(scoreRequirements);
    completionHint.textContent = requirementsHint(completionRequirements);

    const adjustableCount = Number(scoreAdjustable) + Number(completionAdjustable);
    guidance.textContent =
      adjustableCount === 0
        ? "No generated values need adjustment for this rule."
        : adjustableCount === 1
          ? "One generated value can affect this rule."
          : "Two generated values can affect this rule.";
    emptyMessage.hidden = adjustableCount > 0;
  };

  return {
    sync,
    validationMessage,
  };
};
