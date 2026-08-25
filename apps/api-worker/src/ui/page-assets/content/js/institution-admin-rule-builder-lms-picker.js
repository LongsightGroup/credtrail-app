const lmsCourseLabel = (course) => {
  if (!course || typeof course !== "object") {
    return "Untitled course";
  }

  const title =
    typeof course.title === "string" && course.title.length > 0 ? course.title : "Untitled course";
  const courseCode =
    typeof course.courseCode === "string" && course.courseCode.length > 0 ? course.courseCode : "";
  const courseId = typeof course.courseId === "string" ? course.courseId : "";
  return (
    title +
    (courseCode.length > 0 ? " · " + courseCode : "") +
    (courseId.length > 0 ? " (" + courseId + ")" : "")
  );
};

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

  setConditionLookupStatus(
    card,
    '[data-lms-course-status="' + fieldName + '"]',
    message,
    isError,
  );
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
    : "Showing " +
        String(courseCount) +
        " matches. Refine your search to narrow the list.";
};

const selectedCourseOptionSnapshots = (select, selectedValues) => {
  const snapshotsByValue = new Map();

  Array.from(select.selectedOptions).forEach((option) => {
    if (option.value.length > 0) {
      snapshotsByValue.set(option.value, option.textContent ?? option.value);
    }
  });

  selectedValues.forEach((value) => {
    if (!snapshotsByValue.has(value)) {
      snapshotsByValue.set(value, value);
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
) => {
  lmsSetSelectOptions(
    select,
    courses,
    emptyLabel,
    selectedValues,
    lmsCourseLabel,
    (course) => course.courseId,
  );

  const availableValues = new Set(Array.from(select.options).map((option) => option.value));
  const firstCourseOption = select.options.item(1);

  selectedOptionSnapshots.forEach((label, value) => {
    if (availableValues.has(value)) {
      return;
    }

    const option = document.createElement("option");
    option.value = value;
    option.textContent = label;
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
) => {
  setCourseSelectOptions(
    select,
    [],
    "Courses unavailable",
    selectedValues,
    selectedOptionSnapshots,
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

const coursesPath = () => {
  const connectionId = getSelectedLmsConnectionId();

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
  const path = coursesPath();
  const url = lmsUrlWithSearchQuery(path, query);
  const selectedValues = lmsSelectedValuesForSelect(select);
  const selectedOptionSnapshots = selectedCourseOptionSnapshots(select, selectedValues);

  if (path.length === 0) {
    lmsCancelRequest(card);
    setCourseLookupStatus(card, select, "", false);
    setCourseSelectOptions(
      select,
      [],
      "Select an LMS connection first",
      selectedValues,
      selectedOptionSnapshots,
    );
    select.disabled = true;
    return lmsLookupComplete();
  }

  setCourseLookupStatus(card, select, "", false);
  select.disabled = true;
  setCourseSelectOptions(select, [], "Loading courses...", selectedValues, selectedOptionSnapshots);
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
    );
  }

  const { courses, hasMore } = parsed;
  setCourseSelectOptions(
    select,
    courses,
    courses.length === 0 ? "No matching courses" : "Select course",
    selectedValues,
    selectedOptionSnapshots,
  );
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
    workflowStatesUrlForAssignment: (assignmentId) =>
      workflowStatesPath(courseId, assignmentId),
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
