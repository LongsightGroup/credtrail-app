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

const setCourseSelectOptions = (
  select,
  courses,
  emptyLabel,
  selectedValues,
  selectedOptionSnapshots,
  connectionId,
) => {
  lmsSetSelectOptions(
    select,
    courses,
    emptyLabel,
    selectedValues,
    ruleBuilderCourseLabel,
    (course) => course.courseId,
  );

  const availableValues = new Set(Array.from(select.options).map((option) => option.value));
  const firstCourseOption = select.options.item(1);

  selectedOptionSnapshots.forEach((snapshotLabel, value) => {
    if (availableValues.has(value)) {
      return;
    }

    const option = document.createElement("option");
    option.value = value;
    option.textContent = hasRuleBuilderCourseLabel(connectionId, value)
      ? ruleBuilderCourseLabelForId(connectionId, value)
      : snapshotLabel;
    option.selected = true;

    if (firstCourseOption === null) {
      select.append(option);
    } else {
      select.insertBefore(option, firstCourseOption);
    }
  });
};

const failCourseLookup = (
  card,
  select,
  message,
  selectedValues,
  selectedOptionSnapshots,
  connectionId,
) => {
  setCourseSelectOptions(
    select,
    [],
    "Courses unavailable",
    selectedValues,
    selectedOptionSnapshots,
    connectionId,
  );
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

  if (path.length === 0) {
    lmsCancelRequest(card);
    setCourseLookupStatus(card, select, "", false);
    setCourseSelectOptions(
      select,
      [],
      "Select an LMS connection first",
      selectedValues,
      selectedOptionSnapshots,
      connectionId,
    );
    select.disabled = true;
    return lmsLookupComplete();
  }

  setCourseLookupStatus(card, select, "", false);
  select.disabled = true;
  setCourseSelectOptions(
    select,
    [],
    "Loading courses...",
    selectedValues,
    selectedOptionSnapshots,
    connectionId,
  );
  const result = await lmsFetchLatestJson(card, url, "Unable to load LMS courses.");

  if (result.status === "superseded") {
    return result;
  }

  if (result.status === "failed") {
    return failCourseLookup(
      card,
      select,
      result.message,
      selectedValues,
      selectedOptionSnapshots,
      connectionId,
    );
  }

  const parsed = lmsParseCourseSearchPayload(result.payload);

  if (parsed === null) {
    return failCourseLookup(
      card,
      select,
      "Unable to load LMS courses.",
      selectedValues,
      selectedOptionSnapshots,
      connectionId,
    );
  }

  const { courses, hasMore } = parsed;
  if (getSelectedLmsConnectionId() !== connectionId) {
    return lmsLookupSuperseded();
  }

  rememberRuleBuilderCourseLabels(connectionId, courses);
  setCourseSelectOptions(
    select,
    courses,
    courses.length === 0 ? "No matching courses" : "Select course",
    selectedValues,
    selectedOptionSnapshots,
    connectionId,
  );

  const unresolvedCourseIds = [
    ...new Set(
      selectedValues.filter((courseId) => !hasRuleBuilderCourseLabel(connectionId, courseId)),
    ),
  ];

  if (unresolvedCourseIds.length > 0) {
    const resolutionResult = await lmsFetchLatestJson(
      card,
      path + "/resolve",
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

    if (resolutionResult.status === "superseded") {
      return resolutionResult;
    }

    if (getSelectedLmsConnectionId() !== connectionId) {
      return lmsLookupSuperseded();
    }

    const resolvedCourses =
      resolutionResult.status === "complete"
        ? lmsParseCourseResolutionPayload(resolutionResult.payload)
        : null;

    if (resolvedCourses !== null) {
      rememberRuleBuilderCourseLabels(connectionId, resolvedCourses);
      setCourseSelectOptions(
        select,
        courses,
        courses.length === 0 ? "No matching courses" : "Select course",
        selectedValues,
        selectedOptionSnapshots,
        connectionId,
      );
    }

    const restoredCourseIds = new Set(
      resolvedCourses === null ? [] : resolvedCourses.map((course) => course.courseId),
    );
    const hasMissingCourse = unresolvedCourseIds.some(
      (courseId) => !restoredCourseIds.has(courseId),
    );

    if (resolutionResult.status === "failed" || resolvedCourses === null || hasMissingCourse) {
      select.disabled = false;
      setCourseLookupStatus(
        card,
        select,
        (resolutionResult.status === "failed"
          ? resolutionResult.message
          : "Unable to restore every saved course name.") + " Saved course IDs remain visible.",
        true,
      );
      return lmsLookupComplete();
    }
  }

  select.disabled = false;
  setCourseLookupStatus(
    card,
    select,
    courseLookupStatusMessage(courses.length, hasMore, query),
    false,
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
