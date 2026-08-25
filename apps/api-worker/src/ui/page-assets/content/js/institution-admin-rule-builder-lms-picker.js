const setConditionLookupStatus = (card, selector, message, isError) => {
  if (!(card instanceof HTMLElement)) {
    return;
  }

  const status = card.querySelector(selector);

  if (!(status instanceof HTMLElement)) {
    return;
  }

  status.hidden = message.length === 0;
  status.dataset.tone = isError ? "error" : "info";
  status.textContent = message;
};

const setCourseLookupStatus = (card, select, message, isError) => {
  const fieldName = select.dataset.field ?? "";

  if (fieldName.length === 0) {
    return;
  }

  setConditionLookupStatus(card, '[data-lms-course-status="' + fieldName + '"]', message, isError);
};

const setGradebookLookupStatus = (card, message, isError) => {
  setConditionLookupStatus(card, "[data-lms-gradebook-status]", message, isError);
};

const courseLookupStatusMessage = (courseCount, hasMore, query) => {
  const normalizedQuery = query.trim();

  if (courseCount === 0) {
    return normalizedQuery.length === 0
      ? "No courses are available through this LMS connection."
      : "No courses match this search.";
  }

  if (!hasMore) {
    return "";
  }

  return normalizedQuery.length === 0
    ? "Showing " +
        String(courseCount) +
        " courses. Search by title, code, or ID to narrow the list."
    : "Showing " + String(courseCount) + " matches. Refine your search to narrow the list.";
};

const selectedCourseOptionSnapshots = (select, selectedValues, connectionId) => {
  const snapshotsByValue = new Map();

  Array.from(select.selectedOptions).forEach((option) => {
    if (option.value.length > 0) {
      snapshotsByValue.set(
        option.value,
        hasRuleBuilderCourseLabel(connectionId, option.value)
          ? ruleBuilderCourseLabelForId(connectionId, option.value)
          : (option.textContent ?? option.value),
      );
    }
  });

  selectedValues.forEach((value) => {
    if (!snapshotsByValue.has(value)) {
      snapshotsByValue.set(value, ruleBuilderCourseLabelForId(connectionId, value));
    }
  });

  return snapshotsByValue;
};

const courseSelectOptions = (input) => {
  const courseById = new Map(input.courses.map((course) => [course.courseId, course]));
  const selectedValues = [...new Set(input.selectedValues)];
  const selectedSet = new Set(selectedValues);
  const selectedOptions = selectedValues.map((courseId) => {
    const course = courseById.get(courseId);

    return {
      courseId,
      label:
        course === undefined
          ? hasRuleBuilderCourseLabel(input.connectionId, courseId)
            ? ruleBuilderCourseLabelForId(input.connectionId, courseId)
            : (input.selectedOptionSnapshots.get(courseId) ?? courseId)
          : ruleBuilderCourseLabel(course),
    };
  });
  const availableOptions = input.courses
    .filter((course) => !selectedSet.has(course.courseId))
    .map((course) => ({
      courseId: course.courseId,
      label: ruleBuilderCourseLabel(course),
    }));

  return [...selectedOptions, ...availableOptions];
};

const setCourseSelectOptions = (select, input) => {
  const options = courseSelectOptions(input);

  lmsSetSelectOptions(
    select,
    options,
    input.emptyLabel,
    input.selectedValues,
    (option) => option.label,
    (option) => option.courseId,
  );
};

const failCourseLookup = (card, select, message, selection) => {
  setCourseSelectOptions(select, {
    ...selection,
    courses: [],
    emptyLabel: "Courses unavailable",
  });
  const outcome = lmsFailSelectLookup(
    select,
    "Courses unavailable",
    "courses",
    message,
    "Unable to load LMS courses.",
  );
  setCourseLookupStatus(card, select, outcome.message, true);
  return outcome;
};

const coursesPathForConnection = (connectionId) => {
  if (connectionId.length === 0) {
    return "";
  }

  return lmsConnectionsApiPath + "/" + encodeURIComponent(connectionId) + "/courses";
};

const gradebookItemsPath = (courseId) => {
  const connectionId = getSelectedLmsConnectionId();

  if (connectionId.length === 0 || courseId.length === 0) {
    return "";
  }

  return (
    lmsConnectionsApiPath +
    "/" +
    encodeURIComponent(connectionId) +
    "/courses/" +
    encodeURIComponent(courseId) +
    "/gradebook-items"
  );
};

const workflowStatesPath = (courseId, assignmentId) => {
  const connectionId = getSelectedLmsConnectionId();

  if (connectionId.length === 0 || courseId.length === 0 || assignmentId.length === 0) {
    return "";
  }

  return (
    lmsConnectionsApiPath +
    "/" +
    encodeURIComponent(connectionId) +
    "/courses/" +
    encodeURIComponent(courseId) +
    "/gradebook-items/" +
    encodeURIComponent(assignmentId) +
    "/workflow-states"
  );
};

const restoreSelectedCourseLabels = async (input) => {
  const unresolvedCourseIds = [
    ...new Set(
      input.selectedValues.filter(
        (courseId) => !hasRuleBuilderCourseLabel(input.connectionId, courseId),
      ),
    ),
  ];

  if (unresolvedCourseIds.length === 0) {
    return { status: "complete", warningMessage: "" };
  }

  const result = await lmsFetchLatestJson(
    input.requestOwner,
    input.coursesPath + "/resolve",
    "Unable to restore saved course names.",
    {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ courseIds: unresolvedCourseIds }),
    },
  );

  if (result.status === "superseded") {
    return result;
  }

  if (getSelectedLmsConnectionId() !== input.connectionId) {
    return lmsLookupSuperseded();
  }

  if (result.status === "failed") {
    return {
      status: "complete",
      warningMessage: result.message + " Saved course IDs remain visible.",
    };
  }

  const resolvedCourses = lmsParseCourseResolutionPayload(result.payload);

  if (resolvedCourses === null) {
    return {
      status: "complete",
      warningMessage: "Unable to restore every saved course name. Saved course IDs remain visible.",
    };
  }

  rememberRuleBuilderCourseLabels(input.connectionId, resolvedCourses);
  const restoredCourseIds = new Set(resolvedCourses.map((course) => course.courseId));
  const hasMissingCourse = unresolvedCourseIds.some(
    (courseId) => !restoredCourseIds.has(courseId),
  );

  return {
    status: "complete",
    warningMessage: hasMissingCourse
      ? "Unable to restore every saved course name. Saved course IDs remain visible."
      : "",
  };
};

const hydrateCourseSelect = async (card, select, query) => {
  const connectionId = getSelectedLmsConnectionId();
  const path = coursesPathForConnection(connectionId);
  const url = lmsUrlWithSearchQuery(path, query);
  const selectedValues = lmsSelectedValuesForSelect(select);
  const selectedOptionSnapshots = selectedCourseOptionSnapshots(
    select,
    selectedValues,
    connectionId,
  );
  const selection = {
    connectionId,
    selectedValues,
    selectedOptionSnapshots,
  };

  if (path.length === 0) {
    lmsCancelRequest(card);
    setCourseLookupStatus(card, select, "", false);
    setCourseSelectOptions(select, {
      ...selection,
      courses: [],
      emptyLabel: "Select an LMS connection first",
    });
    select.disabled = true;
    return lmsLookupComplete();
  }

  setCourseLookupStatus(card, select, "", false);
  select.disabled = true;
  setCourseSelectOptions(select, {
    ...selection,
    courses: [],
    emptyLabel: "Loading courses...",
  });
  const result = await lmsFetchLatestJson(card, url, "Unable to load LMS courses.");

  if (result.status === "superseded") {
    return result;
  }

  if (result.status === "failed") {
    return failCourseLookup(card, select, result.message, selection);
  }

  const parsed = lmsParseCourseSearchPayload(result.payload);

  if (parsed === null) {
    return failCourseLookup(card, select, "Unable to load LMS courses.", selection);
  }

  const { courses, hasMore } = parsed;
  if (getSelectedLmsConnectionId() !== connectionId) {
    return lmsLookupSuperseded();
  }

  rememberRuleBuilderCourseLabels(connectionId, courses);
  const labelRestoration = await restoreSelectedCourseLabels({
    connectionId,
    coursesPath: path,
    requestOwner: card,
    selectedValues,
  });

  if (labelRestoration.status === "superseded") {
    return labelRestoration;
  }

  setCourseSelectOptions(select, {
    ...selection,
    courses,
    emptyLabel: courses.length === 0 ? "No matching courses" : "Select course",
  });
  select.disabled = false;
  setCourseLookupStatus(
    card,
    select,
    labelRestoration.warningMessage || courseLookupStatusMessage(courses.length, hasMore, query),
    labelRestoration.warningMessage.length > 0,
  );

  return lmsLookupComplete();
};

const hydrateWorkflowStateSelect = async (card) => {
  const courseId = readFieldFromCard(card, "courseId");
  const assignmentId = readFieldFromCard(card, "assignmentId");
  const stateSelect = card.querySelector("[data-lms-workflow-state-select]");

  setGradebookLookupStatus(card, "", false);

  const outcome = await lmsHydrateWorkflowStateSelect({
    stateSelect,
    workflowStatesUrl: workflowStatesPath(courseId, assignmentId),
    fallbackMessage: "Unable to load workflow states.",
  });

  if (outcome.status === "failed") {
    setGradebookLookupStatus(card, outcome.message, true);
  }

  return outcome;
};

const hydrateGradebookItemSelect = async (card, query) => {
  const courseId = readFieldFromCard(card, "courseId");
  const itemSelect = card.querySelector("[data-lms-gradebook-item-select]");
  const stateSelect = card.querySelector("[data-lms-workflow-state-select]");

  if (!(itemSelect instanceof HTMLSelectElement)) {
    return lmsLookupSuperseded();
  }

  const path = gradebookItemsPath(courseId);

  setGradebookLookupStatus(card, "", false);

  const outcome = await lmsHydrateGradebookItemWorkflowSelects({
    itemSelect,
    stateSelect,
    itemsUrl: path,
    query,
    itemFallbackMessage: "Unable to load gradebook items.",
    workflowFallbackMessage: "Unable to load workflow states.",
    workflowStatesUrlForAssignment: (assignmentId) => workflowStatesPath(courseId, assignmentId),
  });

  if (outcome.status === "failed") {
    setGradebookLookupStatus(card, outcome.message, true);
  }

  return outcome;
};

const bindSearchableCourseSelect = (card, fieldName) => {
  const courseSelect = card.querySelector(
    '[data-field="' + fieldName + '"][data-lms-course-select]',
  );
  const courseSearch = card.querySelector('[data-lms-course-query="' + fieldName + '"]');

  if (!(courseSelect instanceof HTMLSelectElement)) {
    return;
  }

  const refresh = lmsBindDebouncedSearch({
    searchInput: courseSearch,
    onInput: async () => {
      const courseOutcome = await hydrateCourseSelect(
        card,
        courseSelect,
        courseSearch instanceof HTMLInputElement ? courseSearch.value : "",
      );

      if (courseOutcome.status !== "complete") {
        return;
      }

      syncDefinitionJsonFromBuilder();
      if (fieldName === "courseId") {
        const itemOutcome = await hydrateGradebookItemSelect(card, "");

        if (itemOutcome.status === "complete") {
          syncDefinitionJsonFromBuilder();
        }
      }
    },
  });

  courseSelect.addEventListener("change", () => {
    courseSelect.dataset.selectedValue = courseSelect.value;
    courseSelect.dataset.selectedValues = Array.from(courseSelect.selectedOptions)
      .map((option) => option.value)
      .join(",");
    if (fieldName === "courseId") {
      lmsRunDetached(async () => {
        const outcome = await hydrateGradebookItemSelect(card, "");

        if (outcome.status === "complete") {
          syncDefinitionJsonFromBuilder();
        }
      });
    }
  });

  refresh();
};

const bindSearchableGradebookItemSelect = (card) => {
  const itemSelect = card.querySelector("[data-lms-gradebook-item-select]");
  const itemSearch = card.querySelector("[data-lms-gradebook-item-query]");

  if (!(itemSelect instanceof HTMLSelectElement)) {
    return;
  }

  lmsBindDebouncedSearch({
    searchInput: itemSearch,
    onInput: async () => {
      const outcome = await hydrateGradebookItemSelect(
        card,
        itemSearch instanceof HTMLInputElement ? itemSearch.value : "",
      );

      if (outcome.status === "complete") {
        syncDefinitionJsonFromBuilder();
      }
    },
  });

  itemSelect.addEventListener("change", () => {
    itemSelect.dataset.selectedValue = itemSelect.value;
    lmsRunDetached(async () => {
      const outcome = await hydrateWorkflowStateSelect(card);

      if (outcome.status === "complete") {
        syncDefinitionJsonFromBuilder();
      }
    });
  });
};
