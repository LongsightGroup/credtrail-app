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

const setRuleBuilderLearnerStatus = (message, isError) => {
  if (!(ruleBuilderLearnerStatus instanceof HTMLElement)) {
    return;
  }

  ruleBuilderLearnerStatus.textContent = message;
  ruleBuilderLearnerStatus.dataset.tone = isError ? "error" : "info";
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

const ruleBuilderLearnersPath = (courseId) => {
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
    "/learners"
  );
};

const mergeRuleBuilderLearners = (courseResults, courseCount) => {
  const learnersById = new Map();

  courseResults.forEach((courseResult) => {
    courseResult.learners.forEach((learner) => {
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

const applyRuleBuilderLearnerSelection = (option) => {
  const learnerId = option === null ? "" : option.value;
  const email = option === null ? "" : (option.dataset.email ?? "");
  setRuleCreateFieldValue("testLearnerId", learnerId);
  setRuleCreateFieldValue("testRecipientIdentity", email);
};

const setRuleBuilderLearnerFilterVisibility = (isVisible) => {
  if (ruleBuilderLearnerFilter instanceof HTMLElement) {
    ruleBuilderLearnerFilter.hidden = !isVisible;
  }
};

const RULE_BUILDER_LEARNER_OPTION_LIMIT = 100;
let ruleBuilderLearnerLoadSequence = 0;

const resetRuleBuilderLearnerPicker = (optionLabel, statusMessage, isError = false) => {
  ruleBuilderLearnerLoadSequence += 1;
  clearRuleBuilderLearnerSelection(optionLabel);
  setRuleBuilderLearnerFilterVisibility(false);
  setRuleBuilderLearnerStatus(statusMessage, isError);

  if (ruleBuilderLearnerFilterQuery instanceof HTMLInputElement) {
    ruleBuilderLearnerFilterQuery.value = "";
  }
};

const loadRuleBuilderLearners = async (query = "") => {
  if (!(ruleBuilderLearnerSelect instanceof HTMLSelectElement)) {
    return;
  }

  syncRuleBuilderTestRecipientFields();
  const courseIds = ruleBuilderLearnerCourseIds();

  if (courseIds.length === 0) {
    resetRuleBuilderLearnerPicker(
      "No course learners available",
      "This rule has no course requirement. Use generated example data to test its structure.",
    );
    return;
  }

  if (getSelectedLmsConnectionId().length === 0) {
    resetRuleBuilderLearnerPicker(
      "Select an LMS connection first",
      "Select an LMS connection before choosing a learner.",
      true,
    );
    return;
  }

  const loadSequence = ++ruleBuilderLearnerLoadSequence;

  if (query.length === 0 && ruleBuilderLearnerFilterQuery instanceof HTMLInputElement) {
    ruleBuilderLearnerFilterQuery.value = "";
  }

  clearRuleBuilderLearnerSelection("Loading learners...");
  setRuleBuilderLearnerStatus("Loading current LMS rosters...", false);

  try {
    const courseResults = await Promise.all(
      courseIds.map(async (courseId) => {
        const payload = await lmsFetchJson(
          lmsUrlWithSearchQuery(ruleBuilderLearnersPath(courseId), query),
          "Unable to load LMS learners.",
        );
        return {
          learners: payload && Array.isArray(payload.learners) ? payload.learners : [],
          hasMore: payload?.hasMore === true,
        };
      }),
    );

    if (loadSequence !== ruleBuilderLearnerLoadSequence) {
      return;
    }

    const learners = mergeRuleBuilderLearners(courseResults, courseIds.length);
    const requiresSearch =
      courseResults.some((courseResult) => courseResult.hasMore) ||
      learners.length > RULE_BUILDER_LEARNER_OPTION_LIMIT;
    const visibleLearners = learners.slice(0, RULE_BUILDER_LEARNER_OPTION_LIMIT);
    const placeholder =
      learners.length === 0
        ? query.length === 0
          ? "No learners found"
          : "No matching learners"
        : "Choose a learner";
    const options = [
      new Option(placeholder, ""),
      ...visibleLearners.map((learner) => {
        const option = new Option(ruleBuilderLearnerOptionLabel(learner), learner.learnerId);
        option.dataset.email = learner.email ?? "";
        option.dataset.courseCount = String(learner.courseCount);
        return option;
      }),
    ];
    ruleBuilderLearnerSelect.replaceChildren(...options);
    ruleBuilderLearnerSelect.disabled = learners.length === 0;
    ruleBuilderLearnerSelect.dataset.courseIds = courseIds.join(",");
    setRuleBuilderLearnerFilterVisibility(requiresSearch || query.length > 0);

    if (learners.length === 1 && !requiresSearch) {
      ruleBuilderLearnerSelect.value = learners[0].learnerId;
      applyRuleBuilderLearnerSelection(ruleBuilderLearnerSelect.selectedOptions.item(0));
      setRuleBuilderLearnerStatus("The only learner in this roster is selected.", false);
      return;
    }

    applyRuleBuilderLearnerSelection(null);

    if (learners.length === 0) {
      setRuleBuilderLearnerStatus(
        query.length === 0
          ? "No learners were found in the courses for this rule."
          : "No learners matched this search.",
        true,
      );
      return;
    }

    setRuleBuilderLearnerStatus(
      requiresSearch
        ? "This roster has more learners than the list can show. Search to narrow it."
        : "Choose one of " + String(learners.length) + " learners.",
      false,
    );
  } catch (error) {
    if (loadSequence !== ruleBuilderLearnerLoadSequence) {
      return;
    }

    clearRuleBuilderLearnerSelection("Unable to load learners");
    setRuleBuilderLearnerStatus(
      lmsLookupFailureMessage(error, "Unable to load LMS learners."),
      true,
    );
  }
};

if (ruleBuilderLearnerFilterQuery instanceof HTMLInputElement) {
  lmsBindDebouncedSearch({
    searchInput: ruleBuilderLearnerFilterQuery,
    debounceMs: 250,
    onInput: () => loadRuleBuilderLearners(ruleBuilderLearnerFilterQuery.value.trim()),
  });
}

if (ruleBuilderLearnerSelect instanceof HTMLSelectElement) {
  ruleBuilderLearnerSelect.addEventListener("change", () => {
    const option = ruleBuilderLearnerSelect.selectedOptions.item(0);
    applyRuleBuilderLearnerSelection(option);

    if (option === null || option.value.length === 0) {
      setRuleBuilderLearnerStatus("Choose an LMS learner.", false);
      return;
    }

    setRuleBuilderLearnerStatus(
      "Selected learner will be checked against current LMS data.",
      false,
    );
  });
}

syncRuleBuilderTestRecipientFields();
