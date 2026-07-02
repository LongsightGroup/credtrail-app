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

const sakaiSites403Message =
  "Sakai blocked CredTrail from reading your site list (403). Save a Sakai username and password for an account that can view the target site and gradebook, then try again. If it still fails, ask a Sakai administrator to allow REST API access to Sites and Gradebook.";

const lmsLookupErrorMessage = (error, fallback) => {
  const message = error instanceof Error ? error.message : fallback;
  const providerKind = getSelectedLmsProviderKind();

  if (
    providerKind === "sakai" &&
    message.includes("(403)") &&
    message.includes("/api/users/me/sites")
  ) {
    return sakaiSites403Message;
  }

  return message;
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

const hydrateCourseSelect = async (select, query) => {
  const path = coursesPath(query);

  if (path.length === 0) {
    lmsSetSelectOptions(
      select,
      [],
      "Select an LMS connection first",
      [],
      lmsCourseLabel,
      (course) => course.courseId,
    );
    select.disabled = true;
    return;
  }

  setLmsLookupStatus("", false);
  select.disabled = true;
  lmsSetSelectOptions(
    select,
    [],
    "Loading courses...",
    lmsSelectedValuesForSelect(select),
    lmsCourseLabel,
    (course) => course.courseId,
  );
  const payload = await lmsFetchJson(path, "Request failed");
  const courses = payload && Array.isArray(payload.courses) ? payload.courses : [];
  lmsSetSelectOptions(
    select,
    courses,
    courses.length === 0 ? "No matching courses" : "Select course",
    lmsSelectedValuesForSelect(select),
    lmsCourseLabel,
    (course) => course.courseId,
  );
  select.disabled = false;
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

  if (!(itemSelect instanceof HTMLSelectElement)) {
    return;
  }

  const path = gradebookItemsPath(courseId, query);

  if (path.length === 0) {
    lmsSetSelectOptions(
      itemSelect,
      [],
      "Select course first",
      [],
      lmsGradebookItemLabel,
      (item) => item.assignmentId,
    );
    itemSelect.disabled = true;
    await hydrateWorkflowStateSelect(card);
    return;
  }

  setLmsLookupStatus("", false);
  await lmsHydrateGradebookItemSelect({
    itemSelect,
    itemsUrl: path,
    query: "",
    fallbackMessage: "Unable to load gradebook items.",
    workflowStatesUrlForAssignment: (assignmentId) => workflowStatesPath(courseId, assignmentId),
  });
  await hydrateWorkflowStateSelect(card);
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
        courseSelect,
        courseSearch instanceof HTMLInputElement ? courseSearch.value : "",
      )
        .then(() => {
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
