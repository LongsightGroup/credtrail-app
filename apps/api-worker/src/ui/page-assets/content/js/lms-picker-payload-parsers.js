const lmsParseCourseRecords = (candidate) => {
  if (!Array.isArray(candidate)) {
    return null;
  }

  const courses = [];

  for (const course of candidate) {
    if (
      !course ||
      typeof course !== "object" ||
      typeof course.courseId !== "string" ||
      course.courseId.length === 0 ||
      typeof course.title !== "string" ||
      (course.courseCode !== undefined &&
        course.courseCode !== null &&
        typeof course.courseCode !== "string")
    ) {
      return null;
    }

    courses.push({
      courseCode: typeof course.courseCode === "string" ? course.courseCode : null,
      courseId: course.courseId,
      title: course.title,
    });
  }

  return courses;
};

const lmsParseCourseSearchPayload = (payload) => {
  if (!payload || typeof payload !== "object" || typeof payload.hasMore !== "boolean") {
    return null;
  }

  const courses = lmsParseCourseRecords(payload.courses);
  return courses === null ? null : { courses, hasMore: payload.hasMore };
};

const lmsParseCourseResolutionPayload = (payload) => {
  if (!payload || typeof payload !== "object") {
    return null;
  }

  return lmsParseCourseRecords(payload.courses);
};

const lmsParseGradebookItems = (payload) => {
  if (!payload || typeof payload !== "object" || !Array.isArray(payload.items)) {
    return null;
  }

  const items = [];

  for (const item of payload.items) {
    if (
      !item ||
      typeof item !== "object" ||
      typeof item.assignmentId !== "string" ||
      item.assignmentId.length === 0 ||
      typeof item.title !== "string" ||
      (item.pointsPossible !== undefined &&
        item.pointsPossible !== null &&
        typeof item.pointsPossible !== "number")
    ) {
      return null;
    }

    items.push({
      assignmentId: item.assignmentId,
      pointsPossible: typeof item.pointsPossible === "number" ? item.pointsPossible : null,
      title: item.title,
    });
  }

  return items;
};

const lmsParseWorkflowStates = (payload) => {
  if (!payload || typeof payload !== "object" || !Array.isArray(payload.states)) {
    return null;
  }

  const states = [];

  for (const state of payload.states) {
    if (
      !state ||
      typeof state !== "object" ||
      typeof state.value !== "string" ||
      state.value.length === 0 ||
      typeof state.label !== "string" ||
      (state.preselected !== undefined && typeof state.preselected !== "boolean")
    ) {
      return null;
    }

    states.push({
      label: state.label,
      preselected: state.preselected === true,
      value: state.value,
    });
  }

  return states;
};
