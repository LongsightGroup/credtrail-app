const ruleBuilderCourseLabelsByConnectionId = new Map();

const ruleBuilderCourseLabel = (course) => {
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

const rememberRuleBuilderCourseLabels = (connectionId, courses) => {
  if (connectionId.length === 0) {
    return;
  }

  const labels = ruleBuilderCourseLabelsByConnectionId.get(connectionId) ?? new Map();

  courses.forEach((course) => {
    if (course && typeof course === "object" && typeof course.courseId === "string") {
      labels.set(course.courseId, ruleBuilderCourseLabel(course));
    }
  });

  ruleBuilderCourseLabelsByConnectionId.set(connectionId, labels);
};

const hasRuleBuilderCourseLabel = (connectionId, courseId) => {
  return ruleBuilderCourseLabelsByConnectionId.get(connectionId)?.has(courseId) === true;
};

const ruleBuilderCourseLabelForId = (connectionId, courseId) => {
  return ruleBuilderCourseLabelsByConnectionId.get(connectionId)?.get(courseId) ?? courseId;
};
