const ruleBuilderExampleTestControlDefinitions = {
  score: {
    key: "score",
    name: "testScore",
    invalidMessage: "Example score must be a number between 0 and 100.",
  },
  completion: {
    key: "completion",
    name: "testCompletionPercent",
    invalidMessage: "Example completion must be a number between 0 and 100.",
  },
};

const configuredExampleNumber = (value) => {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
};

const scoreThresholdText = (condition) => {
  const boundaries = [];
  const minimum = configuredExampleNumber(condition.minScore);
  const maximum = configuredExampleNumber(condition.maxScore);

  if (minimum !== null) {
    boundaries.push("at least " + String(minimum) + "%");
  }

  if (maximum !== null) {
    boundaries.push("no more than " + String(maximum) + "%");
  }

  return boundaries.join(" and ");
};

const programCompletionRequirement = (condition) => {
  const courseCount = Array.isArray(condition.courseIds) ? condition.courseIds.length : 0;
  const minimum = configuredExampleNumber(condition.minimumCompleted);
  const requiredCount = minimum ?? (courseCount > 0 ? courseCount : null);

  if (requiredCount === null) {
    return "the configured course pathway complete";
  }

  if (courseCount > 0) {
    return (
      String(requiredCount) +
      " of " +
      String(courseCount) +
      " configured " +
      (courseCount === 1 ? "course" : "courses") +
      " complete"
    );
  }

  return (
    String(requiredCount) +
    " configured " +
    (requiredCount === 1 ? "course" : "courses") +
    " complete"
  );
};

const exampleTestRequirement = (condition) => {
  const leaf = leafConditionFromCondition(condition);

  if (leaf === null || typeof leaf !== "object") {
    return null;
  }

  if (leaf.type === "grade_threshold") {
    const threshold = scoreThresholdText(leaf);

    if (threshold.length === 0) {
      return null;
    }

    return {
      key: "score",
      text: (leaf.scoreField === "current_score" ? "current score " : "final score ") + threshold,
    };
  }

  if (leaf.type === "assignment_submission") {
    const minimum = configuredExampleNumber(leaf.minScore);
    return minimum === null
      ? null
      : {
          key: "score",
          text: "gradebook item score of at least " + String(minimum) + "%",
        };
  }

  if (leaf.type === "course_completion") {
    const minimum = configuredExampleNumber(leaf.minCompletionPercent) ?? 100;
    return {
      key: "completion",
      text: "at least " + String(minimum) + "% of gradebook items complete",
    };
  }

  if (leaf.type === "program_completion") {
    return {
      key: "completion",
      text: programCompletionRequirement(leaf) +
        "; generated courses count as complete at 100%",
    };
  }

  return null;
};

const exampleTestRequirements = (conditions) => {
  const requirements = {
    score: new Set(),
    completion: new Set(),
  };

  for (const condition of conditions) {
    const requirement = exampleTestRequirement(condition);

    if (requirement !== null) {
      requirements[requirement.key].add(requirement.text);
    }
  }

  return requirements;
};

const formattedExampleRequirements = (requirements) => {
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

const readExampleTestControl = (root, definition) => {
  const field = root.querySelector(
    '[data-rule-builder-example-control="' + definition.key + '"]',
  );
  const input = field?.querySelector('[name="' + definition.name + '"]');
  const hint = field?.querySelector(".ct-field__hint");

  if (
    !(field instanceof HTMLElement) ||
    !(input instanceof HTMLInputElement) ||
    !(hint instanceof HTMLElement)
  ) {
    throw new Error("Generated-example " + definition.key + " control is missing.");
  }

  return {
    ...definition,
    field,
    hint,
    input,
  };
};

const createRuleBuilderExampleTestController = (root) => {
  if (!(root instanceof HTMLElement)) {
    throw new Error("Generated-example test fields are missing.");
  }

  const guidance = root.querySelector("[data-rule-builder-example-guidance]");

  if (!(guidance instanceof HTMLElement)) {
    throw new Error("Generated-example guidance is missing.");
  }

  const controls = {
    score: readExampleTestControl(root, ruleBuilderExampleTestControlDefinitions.score),
    completion: readExampleTestControl(root, ruleBuilderExampleTestControlDefinitions.completion),
  };
  const orderedControls = [controls.score, controls.completion];

  const clearValidation = (control) => {
    control.input.setCustomValidity("");
    control.input.removeAttribute("aria-invalid");
  };

  for (const control of orderedControls) {
    control.input.addEventListener("input", () => {
      clearValidation(control);
    });
  }

  const sync = (conditions) => {
    const requirements = exampleTestRequirements(conditions);
    let adjustableCount = 0;

    for (const control of orderedControls) {
      const controlRequirements = requirements[control.key];
      const isAdjustable = controlRequirements.size > 0;
      control.field.hidden = !isAdjustable;
      control.input.disabled = !isAdjustable;
      control.input.required = isAdjustable;
      control.hint.textContent = formattedExampleRequirements(controlRequirements);
      clearValidation(control);

      if (isAdjustable) {
        adjustableCount += 1;
      }
    }

    guidance.textContent =
      adjustableCount === 0
        ? "This rule's example facts come from its configured requirements. There are no values to adjust; run the test or use advanced facts."
        : adjustableCount === 1
          ? "One generated value can affect this rule."
          : "Two generated values can affect this rule.";
  };

  const validate = () => {
    for (const control of orderedControls) {
      clearValidation(control);

      if (control.input.disabled || control.input.checkValidity()) {
        continue;
      }

      control.input.setCustomValidity(control.invalidMessage);
      control.input.setAttribute("aria-invalid", "true");
      control.input.focus();
      return control.invalidMessage;
    }

    return null;
  };

  return { sync, validate };
};

const ruleBuilderExampleTestController = createRuleBuilderExampleTestController(
  ruleBuilderExampleTestFields,
);
