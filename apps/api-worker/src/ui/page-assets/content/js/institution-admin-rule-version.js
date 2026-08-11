const RULE_VERSION_LABEL_ERROR_FALLBACK = "Course and assignment names could not be loaded";
const RULE_VERSION_LABEL_ERROR_MAX_LENGTH = 500;

const ruleVersionLabelErrorMessage = (payload) => {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return RULE_VERSION_LABEL_ERROR_FALLBACK;
  }

  const message = typeof payload.error === "string" ? payload.error.trim() : "";

  return message.length === 0
    ? RULE_VERSION_LABEL_ERROR_FALLBACK
    : message.slice(0, RULE_VERSION_LABEL_ERROR_MAX_LENGTH);
};

const ruleVersionFetchLabels = async (url) => {
  const response = await fetch(url, {
    cache: "no-store",
    credentials: "same-origin",
    headers: { Accept: "application/json" },
    priority: "low",
  });

  const payload = await response.json().catch(() => null);

  if (!response.ok) {
    throw new Error(ruleVersionLabelErrorMessage(payload));
  }

  return payload;
};

const ruleVersionAssignmentLabelsByCourse = (assignments) => {
  const labelsByCourse = new Map();

  for (const assignment of assignments) {
    if (
      !assignment ||
      typeof assignment.courseId !== "string" ||
      typeof assignment.assignmentId !== "string" ||
      typeof assignment.title !== "string"
    ) {
      continue;
    }

    const labelsByAssignment = labelsByCourse.get(assignment.courseId) ?? new Map();
    labelsByAssignment.set(assignment.assignmentId, assignment.title);
    labelsByCourse.set(assignment.courseId, labelsByAssignment);
  }

  return labelsByCourse;
};

const ruleVersionApplyReferenceLabels = (root, payload) => {
  const courses = payload && Array.isArray(payload.courses) ? payload.courses : [];
  const assignments = payload && Array.isArray(payload.assignments) ? payload.assignments : [];
  const courseLabels = new Map();

  for (const course of courses) {
    if (course && typeof course.courseId === "string" && typeof course.title === "string") {
      courseLabels.set(course.courseId, course.title);
    }
  }

  const assignmentLabelsByCourse = ruleVersionAssignmentLabelsByCourse(assignments);
  let resolvedCount = 0;
  let unresolvedCount = 0;

  root.querySelectorAll("[data-rule-lms-reference]").forEach((reference) => {
    const label = reference.querySelector("[data-rule-lms-label]");
    const courseId = reference.dataset.courseId ?? "";
    let resolvedLabel;

    if (reference.dataset.ruleLmsReference === "course") {
      resolvedLabel = courseLabels.get(courseId);
    } else if (reference.dataset.ruleLmsReference === "assignment") {
      const assignmentId = reference.dataset.assignmentId ?? "";
      resolvedLabel = assignmentLabelsByCourse.get(courseId)?.get(assignmentId);
    }

    if (label instanceof HTMLElement && typeof resolvedLabel === "string") {
      label.textContent = resolvedLabel;
      resolvedCount += 1;
      return;
    }

    unresolvedCount += 1;
  });

  return { resolvedCount, unresolvedCount };
};

const ruleVersionSetLabelStatus = (status, result) => {
  if (!(status instanceof HTMLElement)) {
    return;
  }

  if (result.unresolvedCount === 0) {
    status.textContent = "Course and assignment names loaded from the LMS.";
    status.dataset.tone = "success";
    return;
  }

  status.textContent =
    result.resolvedCount === 0
      ? "Course and assignment names could not be loaded. The saved LMS IDs remain visible."
      : "Some LMS names could not be loaded. Their saved IDs remain visible.";
  status.dataset.tone = "warning";
};

const ruleVersionSetLabelError = (status, message) => {
  if (!(status instanceof HTMLElement)) {
    return;
  }

  const punctuation = message.endsWith(".") ? "" : ".";
  status.textContent = `${message}${punctuation} The saved LMS IDs remain visible.`;
  status.dataset.tone = "warning";
};

const ruleVersionHydrateLmsLabels = async (root) => {
  const labelsUrl = root.dataset.lmsLabelsUrl ?? "";
  const status = root.querySelector("[data-rule-lms-label-status]");
  const references = root.querySelectorAll("[data-rule-lms-reference]");

  if (labelsUrl.length === 0 || references.length === 0) {
    if (status instanceof HTMLElement) {
      status.hidden = true;
    }
    return;
  }

  try {
    const payload = await ruleVersionFetchLabels(labelsUrl);
    ruleVersionSetLabelStatus(status, ruleVersionApplyReferenceLabels(root, payload));
  } catch (cause) {
    ruleVersionSetLabelError(
      status,
      cause instanceof Error ? cause.message : RULE_VERSION_LABEL_ERROR_FALLBACK,
    );
  }
};

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-rule-lms-labels]").forEach((root) => {
    void ruleVersionHydrateLmsLabels(root);
  });
});
