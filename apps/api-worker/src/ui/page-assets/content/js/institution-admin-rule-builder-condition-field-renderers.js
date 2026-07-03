const createConditionInput = (type, attributes) => {
  const input = document.createElement("input");
  input.type = type;

  Object.entries(attributes).forEach(([name, value]) => {
    if (value === true) {
      input.setAttribute(name, "");
      return;
    }

    if (value !== false && value !== null && value !== undefined) {
      input.setAttribute(name, String(value));
    }
  });

  return input;
};

const createConditionOption = (value, label, selected) => {
  const option = document.createElement("option");
  option.value = value;
  option.textContent = label;
  option.selected = selected;
  return option;
};

const createConditionSelect = (attributes, options) => {
  const select = document.createElement("select");

  Object.entries(attributes).forEach(([name, value]) => {
    if (value === true) {
      select.setAttribute(name, "");
      return;
    }

    if (value !== false && value !== null && value !== undefined) {
      select.setAttribute(name, String(value));
    }
  });

  select.append(...options);
  return select;
};

const createConditionField = (labelText, control, styled) => {
  const field = document.createElement("label");
  field.className = styled === false ? "" : "ct-field ct-admin__field ct-admin__condition-field";
  const fieldLabel = document.createElement("span");
  fieldLabel.className = "ct-field__label";
  fieldLabel.textContent = labelText;
  if (control.tagName === "INPUT" && control.type !== "checkbox" && control.type !== "radio") {
    control.classList.add("ct-input", "ct-field__control");
  }
  if (control.tagName === "SELECT") {
    control.classList.add("ct-select", "ct-field__control");
  }
  if (control.tagName === "TEXTAREA") {
    control.classList.add("ct-textarea", "ct-field__control");
  }
  field.append(fieldLabel, control);
  return field;
};

const createConditionCheckbox = (fieldName, labelText, checked) => {
  const field = document.createElement("label");
  const checkbox = createConditionInput("checkbox", { "data-field": fieldName });
  checkbox.className = "ct-checkbox-field__control";
  checkbox.checked = checked;
  const fieldLabel = document.createElement("span");
  fieldLabel.className = "ct-checkbox-field__label";
  fieldLabel.textContent = labelText;
  field.className = "ct-checkbox-field ct-admin__checkbox-row";
  field.append(checkbox, fieldLabel);
  return field;
};

const replaceConditionFields = (fieldsContainer, fields) => {
  fieldsContainer.replaceChildren(...fields);
};

const createCourseSearchField = (targetFieldName) => {
  return createConditionField(
    "Course search",
    createConditionInput("search", {
      "data-lms-course-query": targetFieldName,
      placeholder: "Search by title, code, or ID",
    }),
  );
};

const createCourseSelectField = (labelText, fieldName, selectedValue, multiple) => {
  const attributes = {
    "data-field": fieldName,
    "data-lms-course-select": true,
    multiple,
    required: multiple ? false : true,
    size: multiple ? "6" : null,
  };

  if (multiple) {
    attributes["data-selected-values"] = selectedValue;
  } else {
    attributes["data-selected-value"] = selectedValue;
  }

  return createConditionField(
    labelText,
    createConditionSelect(attributes, [createConditionOption("", "Loading courses...", false)]),
  );
};

const createListSelectField = (labelText, fieldName, kind, selectedValue, emptyLabel) => {
  const options = [
    createConditionOption("", emptyLabel, selectedValue.length === 0),
    ...ruleValueLists
      .filter((valueList) => valueList.kind === kind)
      .map((valueList) => {
        const label =
          typeof valueList.label === "string" && valueList.label.length > 0
            ? valueList.label
            : valueList.id;
        return createConditionOption(
          valueList.id,
          label +
            " · " +
            String(Array.isArray(valueList.values) ? valueList.values.length : 0) +
            " values",
          valueList.id === selectedValue,
        );
      }),
  ];

  return createConditionField(
    labelText,
    createConditionSelect({ "data-field": fieldName }, options),
    false,
  );
};

const renderCourseCompletionFields = (card, fieldsContainer, seed) => {
  const selectedCourseId = typeof seed.courseId === "string" ? seed.courseId : "";
  replaceConditionFields(fieldsContainer, [
    createCourseSearchField("courseId"),
    createCourseSelectField("LMS course", "courseId", selectedCourseId, false),
    createConditionField(
      "Gradebook completion at least %",
      createConditionInput("number", {
        "data-field": "minCompletionPercent",
        min: "0",
        max: "100",
        step: "0.01",
      }),
    ),
  ]);

  setFieldOnCard(
    card,
    "courseListId",
    typeof seed.courseListId === "string" ? seed.courseListId : "",
  );
  setFieldOnCard(
    card,
    "minCompletionPercent",
    typeof seed.minCompletionPercent === "number" ? String(seed.minCompletionPercent) : "100",
  );
  bindExclusiveFieldPair(card, "courseId", "courseListId");
  bindSearchableCourseSelect(card, "courseId");
  updateConditionPlainSummary(card);
};

const renderGradeThresholdFields = (card, fieldsContainer, seed) => {
  const selectedCourseId = typeof seed.courseId === "string" ? seed.courseId : "";
  replaceConditionFields(fieldsContainer, [
    createCourseSearchField("courseId"),
    createCourseSelectField("LMS course", "courseId", selectedCourseId, false),
    createConditionField(
      "Gradebook score field",
      createConditionSelect({ "data-field": "scoreField" }, [
        createConditionOption("final_score", "Final score", false),
        createConditionOption("current_score", "Current score", false),
      ]),
    ),
    createConditionField(
      "Minimum score (optional)",
      createConditionInput("number", {
        "data-field": "minScore",
        min: "0",
        max: "100",
        step: "0.01",
      }),
    ),
    createConditionField(
      "Maximum score (optional)",
      createConditionInput("number", {
        "data-field": "maxScore",
        min: "0",
        max: "100",
        step: "0.01",
      }),
    ),
  ]);

  setFieldOnCard(
    card,
    "courseListId",
    typeof seed.courseListId === "string" ? seed.courseListId : "",
  );
  setFieldOnCard(
    card,
    "scoreField",
    seed.scoreField === "current_score" ? "current_score" : "final_score",
  );
  setFieldOnCard(card, "minScore", typeof seed.minScore === "number" ? String(seed.minScore) : "");
  setFieldOnCard(card, "maxScore", typeof seed.maxScore === "number" ? String(seed.maxScore) : "");
  bindExclusiveFieldPair(card, "courseId", "courseListId");
  bindSearchableCourseSelect(card, "courseId");
  updateConditionPlainSummary(card);
};

const renderProgramCompletionFields = (card, fieldsContainer, seed) => {
  const selectedCourseIds = Array.isArray(seed.courseIds) ? seed.courseIds.join(",") : "";
  replaceConditionFields(fieldsContainer, [
    createCourseSearchField("courseIds"),
    createCourseSelectField("Courses", "courseIds", selectedCourseIds, true),
    createConditionField(
      "Minimum completed (optional)",
      createConditionInput("number", {
        "data-field": "minimumCompleted",
        min: "1",
        max: "200",
        step: "1",
      }),
    ),
  ]);

  setFieldOnCard(
    card,
    "courseListId",
    typeof seed.courseListId === "string" ? seed.courseListId : "",
  );
  setFieldOnCard(
    card,
    "minimumCompleted",
    typeof seed.minimumCompleted === "number" ? String(seed.minimumCompleted) : "",
  );
  bindExclusiveFieldPair(card, "courseIds", "courseListId");
  bindSearchableCourseSelect(card, "courseIds");
  updateConditionPlainSummary(card);
};

const renderAssignmentSubmissionFields = (card, fieldsContainer, seed) => {
  const selectedCourseId = typeof seed.courseId === "string" ? seed.courseId : "";
  const selectedAssignmentId = typeof seed.assignmentId === "string" ? seed.assignmentId : "";
  const selectedWorkflowStates = Array.isArray(seed.workflowStates)
    ? seed.workflowStates.join(",")
    : "";
  replaceConditionFields(fieldsContainer, [
    createCourseSearchField("courseId"),
    createCourseSelectField("Course", "courseId", selectedCourseId, false),
    createConditionField(
      "Gradebook item search",
      createConditionInput("search", {
        "data-lms-gradebook-item-query": true,
        placeholder: "Search by title or ID",
      }),
    ),
    createConditionField(
      "Gradebook item",
      createConditionSelect(
        {
          "data-field": "assignmentId",
          "data-lms-gradebook-item-select": true,
          "data-selected-value": selectedAssignmentId,
          required: true,
        },
        [createConditionOption("", "Select course first", false)],
      ),
    ),
    createConditionField(
      "Minimum score (optional)",
      createConditionInput("number", {
        "data-field": "minScore",
        min: "0",
        max: "100",
        step: "0.01",
      }),
    ),
    createConditionField(
      "Workflow states",
      createConditionSelect(
        {
          "data-field": "workflowStates",
          "data-lms-workflow-state-select": true,
          "data-selected-values": selectedWorkflowStates,
          multiple: true,
          size: "5",
        },
        [createConditionOption("", "Select gradebook item first", false)],
      ),
    ),
    createConditionCheckbox("requireSubmitted", "Gradebook item must be submitted", true),
  ]);

  setFieldOnCard(card, "minScore", typeof seed.minScore === "number" ? String(seed.minScore) : "");
  setCheckboxOnCard(
    card,
    "requireSubmitted",
    seed.requireSubmitted === undefined ? true : Boolean(seed.requireSubmitted),
  );
  bindSearchableCourseSelect(card, "courseId");
  bindSearchableGradebookItemSelect(card);
  updateConditionPlainSummary(card);
};

const renderSurveyCompletionFields = (card, fieldsContainer, seed) => {
  const surveyPlaceholder = getCoursePlaceholder() + "_EXIT_SURVEY";
  replaceConditionFields(fieldsContainer, [
    createConditionField(
      "Survey ID",
      createConditionInput("text", {
        "data-field": "surveyId",
        placeholder: surveyPlaceholder,
      }),
    ),
    createConditionField(
      "Source (optional)",
      createConditionInput("text", {
        "data-field": "source",
        placeholder: "qualtrics",
      }),
    ),
    createConditionCheckbox("requireCompleted", "Survey must be completed", true),
  ]);

  setFieldOnCard(card, "surveyId", typeof seed.surveyId === "string" ? seed.surveyId : "");
  setFieldOnCard(card, "source", typeof seed.source === "string" ? seed.source : "");
  setCheckboxOnCard(
    card,
    "requireCompleted",
    seed.requireCompleted === undefined ? true : Boolean(seed.requireCompleted),
  );
  updateConditionPlainSummary(card);
};

const renderTimeWindowFields = (card, fieldsContainer, seed) => {
  replaceConditionFields(fieldsContainer, [
    createConditionField(
      "Not before (optional)",
      createConditionInput("datetime-local", { "data-field": "notBefore" }),
      false,
    ),
    createConditionField(
      "Not after (optional)",
      createConditionInput("datetime-local", { "data-field": "notAfter" }),
      false,
    ),
  ]);

  setFieldOnCard(card, "notBefore", toDateTimeLocalInput(seed.notBefore));
  setFieldOnCard(card, "notAfter", toDateTimeLocalInput(seed.notAfter));
  updateConditionPlainSummary(card);
};

const renderCustomFieldFields = (card, fieldsContainer, seed) => {
  const valueType =
    typeof seed.expectedValue === "number"
      ? "number"
      : typeof seed.expectedValue === "boolean"
        ? "boolean"
        : "string";
  replaceConditionFields(fieldsContainer, [
    createConditionField(
      "Field name",
      createConditionInput("text", {
        "data-field": "fieldName",
        placeholder: "programStanding",
      }),
      false,
    ),
    createConditionField(
      "Operator",
      createConditionSelect({ "data-field": "operator" }, [
        createConditionOption("equals", "Equals", false),
        createConditionOption("not_equals", "Does not equal", false),
        createConditionOption("contains", "Contains", false),
        createConditionOption("greater_than_or_equal", "Greater than or equal", false),
        createConditionOption("less_than_or_equal", "Less than or equal", false),
      ]),
      false,
    ),
    createConditionField(
      "Value type",
      createConditionSelect({ "data-field": "expectedValueType" }, [
        createConditionOption("string", "Text", false),
        createConditionOption("number", "Number", false),
        createConditionOption("boolean", "True/false", false),
      ]),
      false,
    ),
    createConditionField(
      "Expected value",
      createConditionInput("text", {
        "data-field": "expectedValue",
        placeholder: "eligible",
      }),
      false,
    ),
  ]);

  setFieldOnCard(card, "fieldName", typeof seed.fieldName === "string" ? seed.fieldName : "");
  setFieldOnCard(card, "operator", typeof seed.operator === "string" ? seed.operator : "equals");
  setFieldOnCard(card, "expectedValueType", valueType);
  setFieldOnCard(
    card,
    "expectedValue",
    seed.expectedValue === undefined ? "" : String(seed.expectedValue),
  );
  updateConditionPlainSummary(card);
};

const renderPrerequisiteBadgeFields = (card, fieldsContainer, seed) => {
  replaceConditionFields(fieldsContainer, [
    createConditionField(
      "Required badge template ID",
      createConditionInput("text", {
        "data-field": "badgeTemplateId",
        placeholder: "badge_template_foundations",
      }),
      false,
    ),
    createListSelectField(
      "Reusable badge-template list",
      "badgeTemplateListId",
      "badge_template_ids",
      typeof seed.badgeTemplateListId === "string" ? seed.badgeTemplateListId : "",
      "Use single badge template",
    ),
  ]);
  setFieldOnCard(
    card,
    "badgeTemplateId",
    typeof seed.badgeTemplateId === "string" ? seed.badgeTemplateId : "",
  );
  setFieldOnCard(
    card,
    "badgeTemplateListId",
    typeof seed.badgeTemplateListId === "string" ? seed.badgeTemplateListId : "",
  );
  bindExclusiveFieldPair(card, "badgeTemplateId", "badgeTemplateListId");
  updateConditionPlainSummary(card);
};

const conditionFieldRenderers = {
  course_completion: renderCourseCompletionFields,
  grade_threshold: renderGradeThresholdFields,
  program_completion: renderProgramCompletionFields,
  assignment_submission: renderAssignmentSubmissionFields,
  survey_completion: renderSurveyCompletionFields,
  time_window: renderTimeWindowFields,
  custom_field: renderCustomFieldFields,
  prerequisite_badge: renderPrerequisiteBadgeFields,
};

const renderConditionFields = (card, seed) => {
  const typeSelect = card.querySelector(".ct-admin__condition-type");
  const fieldsContainer = card.querySelector(".ct-admin__condition-fields");

  if (!(typeSelect instanceof HTMLSelectElement) || !(fieldsContainer instanceof HTMLElement)) {
    return;
  }

  const conditionType = typeSelect.value;
  updateConditionCardClass(card, conditionType);
  const renderer = conditionFieldRenderers[conditionType] ?? renderPrerequisiteBadgeFields;

  renderer(card, fieldsContainer, seed);
};
