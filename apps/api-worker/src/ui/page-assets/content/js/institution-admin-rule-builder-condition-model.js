const readConditionFromCard = (card, strict) => {
  const typeSelect = card.querySelector(".ct-admin__condition-type");
  const negate = readCheckboxFromCard(card, "negate");

  if (!(typeSelect instanceof HTMLSelectElement)) {
    throw new Error("Requirement row is missing a type selection.");
  }

  const conditionType = typeSelect.value;
  let condition = null;

  if (conditionType === "course_completion") {
    const courseId = readFieldFromCard(card, "courseId");
    const courseListId = readFieldFromCard(card, "courseListId");
    const minCompletionPercent = parseNumberInput(readFieldFromCard(card, "minCompletionPercent"));

    if (strict && courseId.length === 0 && courseListId.length === 0) {
      throw new Error("Course completion requirement needs a course ID or reusable course list.");
    }

    if (strict && courseId.length > 0 && courseListId.length > 0) {
      throw new Error(
        "Course completion requirement can use course ID or reusable course list, not both.",
      );
    }

    condition = {
      type: "course_completion",
      minCompletionPercent: minCompletionPercent ?? 100,
      ...(courseListId.length > 0
        ? { courseListId }
        : { courseId }),
    };
  } else if (conditionType === "grade_threshold") {
    const courseId = readFieldFromCard(card, "courseId");
    const courseListId = readFieldFromCard(card, "courseListId");
    const minScore = parseNumberInput(readFieldFromCard(card, "minScore"));
    const maxScore = parseNumberInput(readFieldFromCard(card, "maxScore"));

    if (strict && courseId.length === 0 && courseListId.length === 0) {
      throw new Error("Grade threshold requirement needs a course ID or reusable course list.");
    }

    if (strict && courseId.length > 0 && courseListId.length > 0) {
      throw new Error(
        "Grade threshold requirement can use course ID or reusable course list, not both.",
      );
    }

    if (strict && minScore === null && maxScore === null) {
      throw new Error("Grade threshold requires min score or max score.");
    }

    condition = {
      type: "grade_threshold",
      scoreField:
        readFieldFromCard(card, "scoreField") === "current_score" ? "current_score" : "final_score",
      ...(courseListId.length > 0
        ? { courseListId }
        : { courseId }),
    };

    if (minScore !== null) {
      condition.minScore = minScore;
    }

    if (maxScore !== null) {
      condition.maxScore = maxScore;
    }
  } else if (conditionType === "program_completion") {
    const courseIds = parseCsv(readFieldFromCard(card, "courseIds"));
    const courseListId = readFieldFromCard(card, "courseListId");
    const minimumCompleted = parseNumberInput(readFieldFromCard(card, "minimumCompleted"));

    if (strict && courseIds.length === 0 && courseListId.length === 0) {
      throw new Error(
        "Course pathway completion requires selected courses or a reusable course list.",
      );
    }

    if (strict && courseIds.length > 0 && courseListId.length > 0) {
      throw new Error(
        "Course pathway completion can use selected courses or a reusable course list, not both.",
      );
    }

    condition = {
      type: "program_completion",
      ...(courseListId.length > 0
        ? { courseListId }
        : { courseIds }),
    };

    if (minimumCompleted !== null) {
      condition.minimumCompleted = Math.trunc(minimumCompleted);
    }
  } else if (conditionType === "assignment_submission") {
    const courseId = readFieldFromCard(card, "courseId");
    const assignmentId = readFieldFromCard(card, "assignmentId");
    const minScore = parseNumberInput(readFieldFromCard(card, "minScore"));
    const workflowStates = parseCsv(readFieldFromCard(card, "workflowStates"));

    if (strict && courseId.length === 0) {
      throw new Error("Gradebook item requirement needs a course.");
    }

    if (strict && assignmentId.length === 0) {
      throw new Error("Gradebook item requirement needs a gradebook item.");
    }

    condition = {
      type: "assignment_submission",
      courseId,
      assignmentId,
      requireSubmitted: readCheckboxFromCard(card, "requireSubmitted"),
    };

    if (minScore !== null) {
      condition.minScore = minScore;
    }

    if (workflowStates.length > 0) {
      condition.workflowStates = workflowStates;
    }
  } else if (conditionType === "survey_completion") {
    const surveyId = readFieldFromCard(card, "surveyId");
    const source = readFieldFromCard(card, "source");

    if (strict && surveyId.length === 0) {
      throw new Error("Survey completion requirement needs a survey ID.");
    }

    condition = {
      type: "survey_completion",
      surveyId,
      requireCompleted: readCheckboxFromCard(card, "requireCompleted"),
    };

    if (source.length > 0) {
      condition.source = source;
    }
  } else if (conditionType === "time_window") {
    const notBeforeIso = toIsoTimestamp(readFieldFromCard(card, "notBefore"));
    const notAfterIso = toIsoTimestamp(readFieldFromCard(card, "notAfter"));

    if (notBeforeIso === null || notAfterIso === null) {
      throw new Error("Time window condition has an invalid timestamp.");
    }

    if (strict && notBeforeIso === undefined && notAfterIso === undefined) {
      throw new Error("Time window condition requires not before or not after.");
    }

    condition = {
      type: "time_window",
    };

    if (notBeforeIso !== undefined) {
      condition.notBefore = notBeforeIso;
    }

    if (notAfterIso !== undefined) {
      condition.notAfter = notAfterIso;
    }
  } else if (conditionType === "custom_field") {
    const fieldName = readFieldFromCard(card, "fieldName");
    const operator = readFieldFromCard(card, "operator");
    const expectedValueType = readFieldFromCard(card, "expectedValueType");
    const expectedValue = parseCustomExpectedValue(
      readFieldFromCard(card, "expectedValue"),
      expectedValueType,
    );

    if (strict && fieldName.length === 0) {
      throw new Error("Custom field requirement needs a field name.");
    }

    if (strict && expectedValue === null) {
      throw new Error("Custom field requirement needs a valid expected value.");
    }

    condition = {
      type: "custom_field",
      fieldName: fieldName.length > 0 ? fieldName : "fieldName",
      operator:
        operator === "not_equals" ||
        operator === "contains" ||
        operator === "greater_than_or_equal" ||
        operator === "less_than_or_equal"
          ? operator
          : "equals",
      expectedValue: expectedValue === null ? "VALUE" : expectedValue,
    };
  } else {
    const badgeTemplateId = readFieldFromCard(card, "badgeTemplateId");
    const badgeTemplateListId = readFieldFromCard(card, "badgeTemplateListId");

    if (strict && badgeTemplateId.length === 0 && badgeTemplateListId.length === 0) {
      throw new Error(
        "Prerequisite badge requirement needs a badge template ID or reusable badge list.",
      );
    }

    if (strict && badgeTemplateId.length > 0 && badgeTemplateListId.length > 0) {
      throw new Error(
        "Prerequisite badge requirement can use badge template ID or reusable badge list, not both.",
      );
    }

    condition = {
      type: "prerequisite_badge",
      ...(badgeTemplateListId.length > 0
        ? { badgeTemplateListId }
        : {
            badgeTemplateId:
              badgeTemplateId.length > 0 ? badgeTemplateId : "badge_template_required",
          }),
    };
  }

  return negate ? { not: condition } : condition;
};

const readDefinitionFromBuilder = (strict) => {
  const cards = getConditionCards();

  if (cards.length === 0) {
    throw new Error("Add at least one requirement before creating a draft.");
  }

  const conditions = cards.map((card) => readConditionFromCard(card, strict));
  const rootLogic = getRuleBuilderRootLogic();

  const definition = {
    conditions: rootLogic === "any" ? { any: conditions } : { all: conditions },
  };

  if (getCheckboxFieldValue("reviewOnMissingFacts")) {
    definition.options = {
      reviewOnMissingFacts: true,
    };
  }

  return definition;
};

const leafConditionFromCondition = (condition) => {
  if (condition && typeof condition === "object" && "not" in condition) {
    const nested = condition.not;
    return nested && typeof nested === "object" ? nested : condition;
  }

  return condition;
};

const conditionLabel = (condition) => {
  const leaf = leafConditionFromCondition(condition);
  const type = leaf && typeof leaf === "object" && typeof leaf.type === "string" ? leaf.type : "";
  return conditionTypeLabels[type] ?? "Requirement";
};

const conditionDetail = (condition) => {
  const leaf = leafConditionFromCondition(condition);

  if (leaf === null || typeof leaf !== "object") {
    return "Configure requirement details.";
  }

  if (leaf.type === "course_completion") {
    return (
      "At least " +
      String(leaf.minCompletionPercent ?? 100) +
      "% of gradebook items in " +
      (leaf.courseId ?? leaf.courseListId ?? "selected course") +
      " must be complete."
    );
  }

  if (leaf.type === "grade_threshold") {
    const parts = [];

    if (leaf.minScore !== undefined) {
      parts.push("min " + String(leaf.minScore));
    }

    if (leaf.maxScore !== undefined) {
      parts.push("max " + String(leaf.maxScore));
    }

    return (
      "Course " +
      (leaf.courseId ?? leaf.courseListId ?? "selected") +
      " score " +
      (parts.join(", ") || "threshold")
    );
  }

  if (leaf.type === "program_completion") {
    return "Complete " + String(leaf.minimumCompleted ?? "all") + " required courses.";
  }

  if (leaf.type === "assignment_submission") {
    return (
      "Gradebook item " +
      leaf.assignmentId +
      " in " +
      leaf.courseId +
      " must satisfy submission rules."
    );
  }

  if (leaf.type === "survey_completion") {
    return "Survey " + leaf.surveyId + " must be completed.";
  }

  if (leaf.type === "time_window") {
    return "Qualifying activity must fall inside the configured time window.";
  }

  if (leaf.type === "prerequisite_badge") {
    return (
      "Requires badge " + (leaf.badgeTemplateId ?? leaf.badgeTemplateListId ?? "selected") + "."
    );
  }

  if (leaf.type === "custom_field") {
    return (
      leaf.fieldName + " " + (leaf.operator ?? "equals") + " " + String(leaf.expectedValue) + "."
    );
  }

  return "Configure requirement details.";
};

const readConditionsForPreview = () => {
  return getConditionCards()
    .map((card) => {
      try {
        return readConditionFromCard(card, false);
      } catch {
        return null;
      }
    })
    .filter((condition) => condition !== null);
};

const selectedBadgeTemplateLabel = () => {
  const field = getRuleCreateField("badgeTemplateId");

  if (!(field instanceof HTMLSelectElement)) {
    return "selected badge";
  }

  const option = field.selectedOptions.item(0);
  return option === null ? "selected badge" : option.textContent?.trim() || "selected badge";
};

const createRuleFlowItem = (modifier, connector, kicker, title, detail) => {
  const item = document.createElement("li");
  item.className = "ct-admin__builder-flow-item ct-admin__builder-flow-item--" + modifier;

  if (connector.length > 0) {
    const connectorElement = document.createElement("span");
    connectorElement.className = "ct-admin__builder-flow-connector";
    connectorElement.textContent = connector;
    item.appendChild(connectorElement);
  }

  const node = document.createElement("div");
  node.className = "ct-admin__builder-flow-node";

  const kickerElement = document.createElement("span");
  kickerElement.className = "ct-admin__builder-flow-kicker";
  kickerElement.textContent = kicker;

  const titleElement = document.createElement("strong");
  titleElement.textContent = title;

  const detailElement = document.createElement("p");
  detailElement.textContent = detail;

  node.append(kickerElement, titleElement, detailElement);
  item.appendChild(node);

  return item;
};

const renderRuleFlowPreview = () => {
  if (
    !(ruleBuilderFlowList instanceof HTMLOListElement) ||
    !(ruleBuilderFlowEmpty instanceof HTMLElement)
  ) {
    return;
  }

  const conditions = readConditionsForPreview();
  const rootLogic = getRuleBuilderRootLogic();
  const connectorLabel = rootLogic === "any" ? "OR" : "AND";

  ruleBuilderFlowEmpty.hidden = conditions.length > 0;

  if (ruleBuilderFlowMode instanceof HTMLElement) {
    ruleBuilderFlowMode.textContent =
      conditions.length === 0
        ? "Waiting for requirements."
        : rootLogic === "any"
          ? "Any path can qualify."
          : "Learner must meet every requirement.";
  }

  if (conditions.length === 0) {
    ruleBuilderFlowList.replaceChildren();
    return;
  }

  const conditionItems = conditions.map((condition, index) => {
    const leaf = leafConditionFromCondition(condition);
    const type =
      leaf && typeof leaf === "object" && typeof leaf.type === "string" ? leaf.type : "unknown";
    const isNegated = condition && typeof condition === "object" && "not" in condition;
    return createRuleFlowItem(
      type,
      index === 0 ? "" : connectorLabel,
      "Requirement " + String(index + 1),
      (isNegated ? "Exclude: " : "") + conditionLabel(condition),
      conditionDetail(condition),
    );
  });
  const badgeLabel = selectedBadgeTemplateLabel();

  ruleBuilderFlowList.replaceChildren(
    ...conditionItems,
    createRuleFlowItem("issue", "THEN", "Outcome", "Issue badge draft", badgeLabel),
  );
};

const addSourceEntry = (entries, key, label, state, detail) => {
  if (!entries.has(key)) {
    entries.set(key, {
      label,
      state,
      details: [],
    });
  }

  const entry = entries.get(key);

  if (entry && !entry.details.includes(detail)) {
    entry.details.push(detail);
  }
};

const sourceEntriesForConditions = (conditions) => {
  const entries = new Map();
  const lmsLabel = getSelectedLmsProviderKind() || "selected LMS";

  conditions.forEach((condition) => {
    const leaf = leafConditionFromCondition(condition);

    if (leaf === null || typeof leaf !== "object") {
      return;
    }

    if (
      leaf.type === "course_completion" ||
      leaf.type === "grade_threshold" ||
      leaf.type === "program_completion"
    ) {
      addSourceEntry(
        entries,
        "lms-gradebook",
        lmsLabel + " gradebook connection",
        "Connected or sample",
        conditionDetail(condition),
      );
      return;
    }

    if (leaf.type === "assignment_submission") {
      addSourceEntry(
        entries,
        "lms-assignments",
        lmsLabel + " gradebook items",
        "Connected or sample",
        conditionDetail(condition),
      );
      return;
    }

    if (leaf.type === "survey_completion") {
      addSourceEntry(
        entries,
        "survey",
        leaf.source === "qualtrics" ? "Qualtrics surveys" : "Survey facts",
        "Sample or connector facts",
        conditionDetail(condition),
      );
      return;
    }

    if (leaf.type === "prerequisite_badge") {
      addSourceEntry(
        entries,
        "credtrail",
        "CredTrail issued badges",
        "Available",
        conditionDetail(condition),
      );
      return;
    }

    if (leaf.type === "custom_field") {
      addSourceEntry(
        entries,
        "custom",
        "Institutional fields",
        "Sample or import facts",
        conditionDetail(condition),
      );
      return;
    }

    if (leaf.type === "time_window") {
      addSourceEntry(entries, "clock", "System clock", "Available", conditionDetail(condition));
    }
  });

  return Array.from(entries.values());
};

const buildSampleFactsFromConditions = (conditions, learnerId) => {
  const courseId = getDefaultCourseId();
  const parsedScore = Number(getTextFieldValue("testScore"));
  const score =
    Number.isFinite(parsedScore) && parsedScore >= 0 && parsedScore <= 100
      ? parsedScore
      : 92;
  const parsedCompletionPercent = Number(getTextFieldValue("testCompletionPercent"));
  const completionPercent =
    Number.isFinite(parsedCompletionPercent) &&
    parsedCompletionPercent >= 0 &&
    parsedCompletionPercent <= 100
      ? parsedCompletionPercent
      : 100;
  const facts = {
    grades: [],
    completions: [],
    submissions: [],
    surveyCompletions: [],
    customFields: [],
    earnedBadgeTemplateIds: [],
  };

  conditions.forEach((condition) => {
    const leaf = leafConditionFromCondition(condition);

    if (leaf === null || typeof leaf !== "object") {
      return;
    }

    if (leaf.type === "grade_threshold") {
      facts.grades.push({
        courseId: leaf.courseId ?? courseId,
        learnerId,
        currentScore: score,
        finalScore: score,
      });
      return;
    }

    if (leaf.type === "course_completion" || leaf.type === "program_completion") {
      const courseIds = Array.isArray(leaf.courseIds)
        ? leaf.courseIds
        : [leaf.courseId ?? courseId];
      courseIds.forEach((entryCourseId) => {
        facts.completions.push({
          courseId: entryCourseId,
          learnerId,
          completed: completionPercent >= 100,
          completionPercent,
        });
      });
      return;
    }

    if (leaf.type === "assignment_submission") {
      facts.submissions.push({
        courseId: leaf.courseId,
        assignmentId: leaf.assignmentId,
        learnerId,
        score,
        workflowState: "submitted",
        submittedAt: new Date().toISOString(),
      });
      return;
    }

    if (leaf.type === "survey_completion") {
      facts.surveyCompletions.push({
        surveyId: leaf.surveyId,
        learnerId,
        ...(leaf.source === undefined ? {} : { source: leaf.source }),
        completed: true,
        completedAt: new Date().toISOString(),
      });
      return;
    }

    if (leaf.type === "custom_field") {
      facts.customFields.push({
        learnerId,
        fieldName: leaf.fieldName,
        value: leaf.expectedValue,
      });
      return;
    }

    if (leaf.type === "prerequisite_badge") {
      facts.earnedBadgeTemplateIds.push(leaf.badgeTemplateId ?? "badge_template_foundations");
    }
  });

  return facts;
};

const buildSampleFactsPreview = (conditions) => {
  const advancedFactsJson = getTextFieldValue("testFactsJson");

  if (advancedFactsJson.length > 0) {
    try {
      return JSON.stringify(JSON.parse(advancedFactsJson), null, 2);
    } catch {
      return "Advanced facts JSON is invalid.";
    }
  }

  return JSON.stringify(buildSampleFactsFromConditions(conditions, "example-learner"), null, 2);
};

const renderSourceReadiness = () => {
  if (!(ruleBuilderSourceList instanceof HTMLElement)) {
    return;
  }

  const conditions = readConditionsForPreview();
  const entries = sourceEntriesForConditions(conditions);

  if (entries.length === 0) {
    const row = document.createElement("div");
    const term = document.createElement("dt");
    const detail = document.createElement("dd");
    term.textContent = "No sources yet";
    detail.textContent = "Add requirements to see which facts CredTrail needs.";
    row.append(term, detail);
    ruleBuilderSourceList.replaceChildren(row);
    setCodeOutput(ruleBuilderSourceSample, "");
    return;
  }

  const rows = entries.map((entry) => {
    const row = document.createElement("div");
    const term = document.createElement("dt");
    const detail = document.createElement("dd");
    const state = document.createElement("span");
    const text = document.createElement("span");

    term.textContent = entry.label;
    state.className = "ct-admin__status-pill";
    state.textContent = entry.state;
    text.textContent = entry.details.join(" ");
    detail.append(state, text);
    row.append(term, detail);

    return row;
  });

  ruleBuilderSourceList.replaceChildren(...rows);
  setCodeOutput(ruleBuilderSourceSample, buildSampleFactsPreview(conditions));
};

const validateConditionCards = (updateRows) => {
  const errors = [];

  getConditionCards().forEach((card, index) => {
    try {
      readConditionFromCard(card, true);

      if (updateRows) {
        setConditionResultState(card, "idle", "Ready to test.");
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : "Requirement needs attention.";
      errors.push("Requirement " + String(index + 1) + ": " + message);

      if (updateRows) {
        setConditionResultState(card, "fail", message);
      }
    }
  });

  return errors;
};
