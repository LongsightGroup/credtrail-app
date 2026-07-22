const collectRuleBuilderLearnerCourseIds = (condition, courseIds) => {
  if (!condition || typeof condition !== "object") {
    return;
  }

  if (Array.isArray(condition.all)) {
    condition.all.forEach((child) => collectRuleBuilderLearnerCourseIds(child, courseIds));
  }

  if (Array.isArray(condition.any)) {
    condition.any.forEach((child) => collectRuleBuilderLearnerCourseIds(child, courseIds));
  }

  if (condition.not && typeof condition.not === "object") {
    collectRuleBuilderLearnerCourseIds(condition.not, courseIds);
  }

  if (typeof condition.courseId === "string" && condition.courseId.length > 0) {
    courseIds.add(condition.courseId);
  }

  if (Array.isArray(condition.courseIds)) {
    condition.courseIds.forEach((courseId) => {
      if (typeof courseId === "string" && courseId.length > 0) {
        courseIds.add(courseId);
      }
    });
  }
};

const ruleBuilderLearnerCourseIds = () => {
  const courseIds = new Set();
  readConditionsForPreview().forEach((condition) => {
    collectRuleBuilderLearnerCourseIds(condition, courseIds);
  });
  return Array.from(courseIds).sort();
};

const conditionRequiresRecipientIdentity = (condition) => {
  if (!condition || typeof condition !== "object") {
    return false;
  }

  if (condition.type === "prerequisite_badge") {
    return true;
  }

  if (Array.isArray(condition.all) && condition.all.some(conditionRequiresRecipientIdentity)) {
    return true;
  }

  if (Array.isArray(condition.any) && condition.any.some(conditionRequiresRecipientIdentity)) {
    return true;
  }

  return condition.not && typeof condition.not === "object"
    ? conditionRequiresRecipientIdentity(condition.not)
    : false;
};

const ruleBuilderTestRequiresRecipientIdentity = () => {
  return readConditionsForPreview().some(conditionRequiresRecipientIdentity);
};

const syncRuleBuilderTestRecipientFields = () => {
  if (ruleBuilderTestRecipientFields instanceof HTMLElement) {
    ruleBuilderTestRecipientFields.hidden = !ruleBuilderTestRequiresRecipientIdentity();
  }
};

const setRuleBuilderLearnerSearchStatus = (message, isError) => {
  if (!(ruleBuilderLearnerSearchStatus instanceof HTMLElement)) {
    return;
  }

  ruleBuilderLearnerSearchStatus.textContent = message;
  ruleBuilderLearnerSearchStatus.dataset.tone = isError ? "error" : "info";
};

const clearRuleBuilderLearnerSelection = (message) => {
  setRuleCreateFieldValue("testLearnerId", "");
  setRuleCreateFieldValue("testRecipientIdentity", "");

  if (ruleBuilderLearnerSelect instanceof HTMLSelectElement) {
    ruleBuilderLearnerSelect.replaceChildren(new Option(message, ""));
    ruleBuilderLearnerSelect.disabled = true;
    ruleBuilderLearnerSelect.dataset.courseIds = "";
  }
};

const ruleBuilderLearnersPath = (courseId, query) => {
  const connectionId = getSelectedLmsConnectionId();

  if (connectionId.length === 0) {
    return "";
  }

  return (
    lmsConnectionsApiPath +
    "/" +
    encodeURIComponent(connectionId) +
    "/courses/" +
    encodeURIComponent(courseId) +
    "/learners?q=" +
    encodeURIComponent(query)
  );
};

const mergeRuleBuilderLearners = (courseResults, courseCount) => {
  const learnersById = new Map();

  courseResults.forEach((courseResult) => {
    courseResult.forEach((learner) => {
      if (
        !learner ||
        typeof learner !== "object" ||
        typeof learner.learnerId !== "string" ||
        typeof learner.displayName !== "string"
      ) {
        return;
      }

      const existing = learnersById.get(learner.learnerId);

      if (existing) {
        existing.courseCount += 1;
        if (existing.email === null && typeof learner.email === "string") {
          existing.email = learner.email;
        }
        return;
      }

      learnersById.set(learner.learnerId, {
        learnerId: learner.learnerId,
        displayName: learner.displayName,
        email: typeof learner.email === "string" ? learner.email : null,
        courseCount: 1,
        requiredCourseCount: courseCount,
      });
    });
  });

  return Array.from(learnersById.values()).sort((left, right) => {
    if (left.courseCount !== right.courseCount) {
      return right.courseCount - left.courseCount;
    }

    return left.displayName.localeCompare(right.displayName);
  });
};

const ruleBuilderLearnerOptionLabel = (learner) => {
  const identity = learner.email === null ? learner.learnerId : learner.email;
  const coverage =
    learner.requiredCourseCount > 1
      ? " · " + String(learner.courseCount) + "/" + String(learner.requiredCourseCount) + " courses"
      : "";
  return learner.displayName + " · " + identity + coverage;
};

const searchRuleBuilderLearners = async () => {
  if (
    !(ruleBuilderLearnerQuery instanceof HTMLInputElement) ||
    !(ruleBuilderLearnerSelect instanceof HTMLSelectElement)
  ) {
    return;
  }

  syncRuleBuilderTestRecipientFields();
  const query = ruleBuilderLearnerQuery.value.trim();

  if (query.length < 2) {
    clearRuleBuilderLearnerSelection("Search for a learner first");
    setRuleBuilderLearnerSearchStatus("Enter at least two characters.", false);
    return;
  }

  const courseIds = ruleBuilderLearnerCourseIds();

  if (courseIds.length === 0) {
    clearRuleBuilderLearnerSelection("Add a course requirement first");
    setRuleBuilderLearnerSearchStatus(
      "Add at least one course-based requirement before searching LMS learners.",
      true,
    );
    return;
  }

  if (getSelectedLmsConnectionId().length === 0) {
    clearRuleBuilderLearnerSelection("Select an LMS connection first");
    setRuleBuilderLearnerSearchStatus("Select an LMS connection before searching learners.", true);
    return;
  }

  ruleBuilderLearnerSelect.replaceChildren(new Option("Searching LMS learners...", ""));
  ruleBuilderLearnerSelect.disabled = true;
  setRuleBuilderLearnerSearchStatus("Searching current LMS rosters...", false);

  try {
    const courseResults = await Promise.all(
      courseIds.map(async (courseId) => {
        const payload = await lmsFetchJson(
          ruleBuilderLearnersPath(courseId, query),
          "Unable to search LMS learners.",
        );
        return payload && Array.isArray(payload.learners) ? payload.learners : [];
      }),
    );
    const learners = mergeRuleBuilderLearners(courseResults, courseIds.length);
    const options = [
      new Option(learners.length === 0 ? "No matching learners" : "Select LMS learner", ""),
      ...learners.map((learner) => {
        const option = new Option(ruleBuilderLearnerOptionLabel(learner), learner.learnerId);
        option.dataset.email = learner.email ?? "";
        option.dataset.courseCount = String(learner.courseCount);
        return option;
      }),
    ];
    ruleBuilderLearnerSelect.replaceChildren(...options);
    ruleBuilderLearnerSelect.disabled = learners.length === 0;
    ruleBuilderLearnerSelect.dataset.courseIds = courseIds.join(",");
    setRuleBuilderLearnerSearchStatus(
      learners.length === 0
        ? "No learners matched this search in the rule's courses."
        : String(learners.length) + " LMS learner(s) found.",
      learners.length === 0,
    );
  } catch (error) {
    clearRuleBuilderLearnerSelection("Learner search failed");
    setRuleBuilderLearnerSearchStatus(
      lmsLookupErrorMessage(error, "Unable to search LMS learners."),
      true,
    );
  }
};

if (ruleBuilderLearnerQuery instanceof HTMLInputElement) {
  lmsBindDebouncedSearch({
    searchInput: ruleBuilderLearnerQuery,
    debounceMs: 250,
    onInput: searchRuleBuilderLearners,
  });
}

if (ruleBuilderLearnerSelect instanceof HTMLSelectElement) {
  ruleBuilderLearnerSelect.addEventListener("change", () => {
    const option = ruleBuilderLearnerSelect.selectedOptions.item(0);
    const learnerId = option === null ? "" : option.value;
    const email = option === null ? "" : (option.dataset.email ?? "");
    setRuleCreateFieldValue("testLearnerId", learnerId);
    setRuleCreateFieldValue("testRecipientIdentity", email);

    if (learnerId.length === 0) {
      setRuleBuilderLearnerSearchStatus("Select an LMS learner.", false);
      return;
    }

    setRuleBuilderLearnerSearchStatus(
      "Selected learner will be checked against current LMS data.",
      false,
    );
  });
}

syncRuleBuilderTestRecipientFields();
