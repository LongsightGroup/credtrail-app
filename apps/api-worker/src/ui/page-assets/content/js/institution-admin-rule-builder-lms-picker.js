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

const lmsLookupErrorMessage = (error, fallback) => {
  return error instanceof Error ? error.message : fallback;
};

const setLmsLookupStatus = (message, isError) => {
  if (!(ruleBuilderLmsStatus instanceof HTMLElement)) {
    return;
  }

  const messageElement = ruleBuilderLmsStatus.querySelector(
    "[data-rule-builder-lms-status-message]",
  );

  ruleBuilderLmsStatus.hidden = message.length === 0;
  ruleBuilderLmsStatus.dataset.tone = isError ? "error" : "info";

  if (messageElement instanceof HTMLElement) {
    messageElement.textContent = message;
  }
};

const courseLookupAbortControllerByCard = new WeakMap();

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

const coursesPath = (query) => {
  const connectionId = getSelectedLmsConnectionId();

  if (connectionId.length === 0) {
    return "";
  }

  const queryString = query.trim();
  const suffix = queryString.length === 0 ? "" : "?q=" + encodeURIComponent(queryString);
  return lmsConnectionsApiPath + "/" + encodeURIComponent(connectionId) + "/courses" + suffix;
};

const gradebookItemsPath = (courseId, query) => {
  const connectionId = getSelectedLmsConnectionId();

  if (connectionId.length === 0 || courseId.length === 0) {
    return "";
  }

  const queryString = query.trim();
  const suffix = queryString.length === 0 ? "" : "?q=" + encodeURIComponent(queryString);
  return (
    lmsConnectionsApiPath +
    "/" +
    encodeURIComponent(connectionId) +
    "/courses/" +
    encodeURIComponent(courseId) +
    "/gradebook-items" +
    suffix
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
  courseLookupAbortControllerByCard.get(card)?.abort();
  const path = coursesPath(query);
  const selectedValues = lmsSelectedValuesForSelect(select);
  const selectedOptionSnapshots = selectedCourseOptionSnapshots(select, selectedValues);

  if (path.length === 0) {
    courseLookupAbortControllerByCard.delete(card);
    setCourseSelectOptions(
      select,
      [],
      "Select an LMS connection first",
      selectedValues,
      selectedOptionSnapshots,
    );
    select.disabled = true;
    return true;
  }

  const abortController = new AbortController();
  courseLookupAbortControllerByCard.set(card, abortController);
  setLmsLookupStatus("Loading courses...", false);
  select.disabled = true;
  setCourseSelectOptions(select, [], "Loading courses...", selectedValues, selectedOptionSnapshots);
  let payload;

  try {
    payload = await lmsFetchJson(path, "Unable to load LMS courses.", {
      signal: abortController.signal,
    });
  } catch (error) {
    if (abortController.signal.aborted) {
      return false;
    }

    courseLookupAbortControllerByCard.delete(card);
    setCourseSelectOptions(
      select,
      [],
      "Courses unavailable",
      selectedValues,
      selectedOptionSnapshots,
    );
    select.disabled = false;
    throw error;
  }

  if (courseLookupAbortControllerByCard.get(card) !== abortController) {
    return false;
  }

  courseLookupAbortControllerByCard.delete(card);
  const courses = payload && Array.isArray(payload.courses) ? payload.courses : [];
  const hasMore = payload && payload.hasMore === true;
  setCourseSelectOptions(
    select,
    courses,
    courses.length === 0 ? "No matching courses" : "Select course",
    selectedValues,
    selectedOptionSnapshots,
  );
  select.disabled = false;
  const normalizedQuery = query.trim();

  if (courses.length === 0) {
    setLmsLookupStatus(
      normalizedQuery.length === 0
        ? "No courses are available to the saved LMS account."
        : "No courses matched your search.",
      false,
    );
  } else if (hasMore) {
    setLmsLookupStatus(
      normalizedQuery.length === 0
        ? "Showing the first 100 courses. Search to narrow the list."
        : "Showing the first 100 matches. Refine your search to narrow the list.",
      false,
    );
  } else {
    setLmsLookupStatus("", false);
  }

  return true;
};

const hydrateWorkflowStateSelect = async (card) => {
  const courseId = readFieldFromCard(card, "courseId");
  const assignmentId = readFieldFromCard(card, "assignmentId");
  const stateSelect = card.querySelector("[data-lms-workflow-state-select]");

  await lmsHydrateWorkflowStateSelect({
    stateSelect,
    workflowStatesUrl: workflowStatesPath(courseId, assignmentId),
    fallbackMessage: "Unable to load workflow states.",
  });
};

const hydrateGradebookItemSelect = async (card, query) => {
  const courseId = readFieldFromCard(card, "courseId");
  const itemSelect = card.querySelector("[data-lms-gradebook-item-select]");
  const stateSelect = card.querySelector("[data-lms-workflow-state-select]");

  if (!(itemSelect instanceof HTMLSelectElement)) {
    return;
  }

  const path = gradebookItemsPath(courseId, query);

  setLmsLookupStatus("", false);
  await lmsHydrateGradebookItemWorkflowSelects({
    itemSelect,
    stateSelect,
    itemsUrl: path,
    query: "",
    itemFallbackMessage: "Unable to load gradebook items.",
    workflowFallbackMessage: "Unable to load workflow states.",
    workflowStatesUrlForAssignment: (assignmentId) =>
      workflowStatesPath(courseId, assignmentId),
  });
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
    onInput: () =>
      hydrateCourseSelect(
        card,
        courseSelect,
        courseSearch instanceof HTMLInputElement ? courseSearch.value : "",
      )
        .then((didHydrate) => {
          if (!didHydrate) {
            return;
          }

          syncDefinitionJsonFromBuilder();
          if (fieldName === "courseId") {
            void hydrateGradebookItemSelect(card, "");
          }
        })
        .catch((error) => {
          const message = lmsLookupErrorMessage(error, "Unable to load LMS courses.");
          setLmsLookupStatus(message, true);
          setStatus(ruleCreateStatus, message, true);
        }),
  });

  courseSelect.addEventListener("change", () => {
    courseSelect.dataset.selectedValue = courseSelect.value;
    courseSelect.dataset.selectedValues = Array.from(courseSelect.selectedOptions)
      .map((option) => option.value)
      .join(",");
    if (fieldName === "courseId") {
      void hydrateGradebookItemSelect(card, "");
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
    onInput: () =>
      hydrateGradebookItemSelect(
        card,
        itemSearch instanceof HTMLInputElement ? itemSearch.value : "",
      )
        .then(() => {
          syncDefinitionJsonFromBuilder();
        })
        .catch((error) => {
          const message = lmsLookupErrorMessage(error, "Unable to load gradebook items.");
          setLmsLookupStatus(message, true);
          setStatus(ruleCreateStatus, message, true);
        }),
  });

  itemSelect.addEventListener("change", () => {
    itemSelect.dataset.selectedValue = itemSelect.value;
    void hydrateWorkflowStateSelect(card).then(() => {
      syncDefinitionJsonFromBuilder();
    });
  });
};
