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

const setLookupSelectFailureState = (select, label) => {
  if (!(select instanceof HTMLSelectElement)) {
    return;
  }

  const placeholder = select.options.item(0);

  if (placeholder !== null) {
    placeholder.textContent = label;
  }

  select.disabled = false;
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
    setCourseLookupStatus(card, select, "", false);
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
  setCourseLookupStatus(card, select, "", false);
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
    setCourseLookupStatus(
      card,
      select,
      lmsLookupErrorMessage(error, "Unable to load LMS courses."),
      true,
    );
    return false;
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
  setCourseLookupStatus(
    card,
    select,
    courseLookupStatusMessage(courses.length, hasMore, query),
    false,
  );

  return true;
};

const hydrateWorkflowStateSelect = async (card) => {
  const courseId = readFieldFromCard(card, "courseId");
  const assignmentId = readFieldFromCard(card, "assignmentId");
  const stateSelect = card.querySelector("[data-lms-workflow-state-select]");

  setGradebookLookupStatus(card, "", false);

  try {
    return await lmsHydrateWorkflowStateSelect({
      stateSelect,
      workflowStatesUrl: workflowStatesPath(courseId, assignmentId),
      fallbackMessage: "Unable to load workflow states.",
    });
  } catch (error) {
    setLookupSelectFailureState(stateSelect, "Workflow states unavailable");
    setGradebookLookupStatus(
      card,
      lmsLookupErrorMessage(error, "Unable to load workflow states."),
      true,
    );
    return false;
  }
};

const hydrateGradebookItemSelect = async (card, query) => {
  const courseId = readFieldFromCard(card, "courseId");
  const itemSelect = card.querySelector("[data-lms-gradebook-item-select]");
  const stateSelect = card.querySelector("[data-lms-workflow-state-select]");

  if (!(itemSelect instanceof HTMLSelectElement)) {
    return false;
  }

  const path = gradebookItemsPath(courseId, query);

  setGradebookLookupStatus(card, "", false);

  try {
    return await lmsHydrateGradebookItemWorkflowSelects({
      itemSelect,
      stateSelect,
      itemsUrl: path,
      query: "",
      itemFallbackMessage: "Unable to load gradebook items.",
      workflowFallbackMessage: "Unable to load workflow states.",
      workflowStatesUrlForAssignment: (assignmentId) =>
        workflowStatesPath(courseId, assignmentId),
    });
  } catch (error) {
    setLookupSelectFailureState(itemSelect, "Gradebook items unavailable");
    setGradebookLookupStatus(
      card,
      lmsLookupErrorMessage(error, "Unable to load gradebook items."),
      true,
    );
    return false;
  }
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
      ).then((didHydrate) => {
        if (didHydrate) {
          syncDefinitionJsonFromBuilder();
        }
      }),
  });

  itemSelect.addEventListener("change", () => {
    itemSelect.dataset.selectedValue = itemSelect.value;
    void hydrateWorkflowStateSelect(card).then((didHydrate) => {
      if (didHydrate) {
        syncDefinitionJsonFromBuilder();
      }
    });
  });
};
