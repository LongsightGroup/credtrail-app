import { asJsonObject, asNonEmptyString, asString } from "../utils/value-parsers";
import type {
  GradebookAssignmentRecord,
  GradebookCompletionRecord,
  GradebookCourseRecord,
  GradebookEnrollmentRecord,
  GradebookGradeRecord,
  GradebookProvider,
  GradebookSubmissionRecord,
  SakaiGradebookProviderConfig,
} from "./gradebook-types";

interface CreateSakaiGradebookProviderInput {
  config: SakaiGradebookProviderConfig;
  fetchImpl?: typeof fetch;
}

export interface CreateSakaiSessionInput {
  apiBaseUrl: string;
  username: string;
  password: string;
  fetchImpl?: typeof fetch;
}

export interface SakaiSessionLoginResult {
  sessionId: string;
  cookieHeader: string;
}

interface SakaiGradebookMatrix {
  siteId: string;
  gradebookUid: string;
  columns: readonly SakaiGradebookMatrixColumn[];
  students: readonly SakaiGradebookMatrixStudent[];
}

interface SakaiGradebookMatrixColumn {
  id: string;
  name: string;
  points: number | null;
  weight: number | null;
  dueDate: string | null;
  released: boolean | null;
}

interface SakaiGradebookMatrixStudentCourseGrade {
  calculatedGrade: string | null;
  mappedGrade: string | null;
  displayGrade: string | null;
  pointsEarned: number | null;
  totalPointsPossible: number | null;
}

interface SakaiGradebookMatrixStudentGrade {
  grade: string | null;
  workflowState: string | null;
  recordedAt: string | null;
  excused: boolean | null;
}

interface SakaiGradebookMatrixStudent {
  learnerId: string;
  courseGrade: SakaiGradebookMatrixStudentCourseGrade | null;
  gradesByAssignmentId: Readonly<Record<string, SakaiGradebookMatrixStudentGrade>>;
}

const asIdentifier = (value: unknown): string | null => {
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed.length === 0 ? null : trimmed;
  }

  if (typeof value === "number" && Number.isFinite(value)) {
    return value.toString();
  }

  return null;
};

const asNumber = (value: unknown): number | null => {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }

  if (typeof value === "string") {
    const parsed = Number.parseFloat(value);
    return Number.isFinite(parsed) ? parsed : null;
  }

  return null;
};

const asBoolean = (value: unknown): boolean | null => {
  return typeof value === "boolean" ? value : null;
};

const asJsonArray = (value: unknown): readonly unknown[] | null => {
  return Array.isArray(value) ? value : null;
};

const asIsoTimestamp = (value: unknown): string | null => {
  const timestamp = asNonEmptyString(value);

  if (timestamp === null) {
    return null;
  }

  return Number.isFinite(Date.parse(timestamp)) ? timestamp : null;
};

const ensureHttpBaseUrl = (candidate: string): URL => {
  let parsed: URL;

  try {
    parsed = new URL(candidate);
  } catch {
    throw new Error("Gradebook provider apiBaseUrl must be a valid absolute URL");
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("Gradebook provider apiBaseUrl must use http or https");
  }

  if (!parsed.pathname.endsWith("/")) {
    parsed.pathname = `${parsed.pathname}/`;
  }

  return parsed;
};

const isSakaiSessionCookieName = (cookieName: string): boolean => {
  return cookieName === "SAKAIID" || cookieName === "JSESSIONID";
};

const stripSetCookieAttributes = (setCookieValue: string): string | null => {
  const cookiePair = setCookieValue.split(";")[0]?.trim();

  if (cookiePair === undefined || cookiePair.length === 0) {
    return null;
  }

  const equalsIndex = cookiePair.indexOf("=");

  if (equalsIndex <= 0 || equalsIndex === cookiePair.length - 1) {
    return null;
  }

  const cookieName = cookiePair.slice(0, equalsIndex);

  return isSakaiSessionCookieName(cookieName) ? cookiePair : null;
};

const parseSetCookieHeader = (headerValue: string | null): string | null => {
  if (headerValue === null || headerValue.trim().length === 0) {
    return null;
  }

  const cookieCandidates = headerValue.split(/,(?=\s*[^;,=\s]+=)/u);

  for (const cookieCandidate of cookieCandidates) {
    const cookieHeader = stripSetCookieAttributes(cookieCandidate);

    if (cookieHeader !== null) {
      return cookieHeader;
    }
  }

  return null;
};

const parseSessionIdFromCookieHeader = (cookieHeader: string): string | null => {
  const equalsIndex = cookieHeader.indexOf("=");

  if (equalsIndex <= 0 || equalsIndex === cookieHeader.length - 1) {
    return null;
  }

  const value = cookieHeader.slice(equalsIndex + 1).trim();

  return value.length === 0 ? null : (value.split(".")[0] ?? value);
};

const parseSessionIdFromJsonObject = (candidate: unknown): string | null => {
  const parsed = asJsonObject(candidate);

  if (parsed === null) {
    return null;
  }

  return (
    asNonEmptyString(parsed.id) ??
    asNonEmptyString(parsed.sessionId) ??
    asNonEmptyString(parsed.sessionid) ??
    asNonEmptyString(parsed.entityId)
  );
};

const parseSessionIdFromBody = (body: string): string | null => {
  const trimmed = body.trim();

  if (trimmed.length === 0) {
    return null;
  }

  try {
    const parsed: unknown = JSON.parse(trimmed);

    if (typeof parsed === "string") {
      return asNonEmptyString(parsed);
    }

    const jsonSessionId = parseSessionIdFromJsonObject(parsed);

    if (jsonSessionId !== null) {
      return jsonSessionId;
    }
  } catch {
    // Sakai commonly returns the session id as text/plain.
  }

  return trimmed.replace(/^"|"$/gu, "");
};

const parseSessionIdFromLocation = (headerValue: string | null, apiBaseUrl: URL): string | null => {
  if (headerValue === null || headerValue.trim().length === 0) {
    return null;
  }

  let parsed: URL;

  try {
    parsed = new URL(headerValue, apiBaseUrl);
  } catch {
    return null;
  }

  const lastPathSegment = parsed.pathname
    .split("/")
    .filter((part) => part.length > 0)
    .at(-1);

  if (lastPathSegment === undefined) {
    return null;
  }

  const withoutFormatSuffix = lastPathSegment.replace(/\.(json|xml|html|form)$/u, "");

  return withoutFormatSuffix.length === 0 ? null : decodeURIComponent(withoutFormatSuffix);
};

export const sakaiCookieHeaderFromAccessToken = (accessToken: string): string => {
  const trimmed = accessToken.trim();
  const setCookiePair = stripSetCookieAttributes(trimmed);

  if (setCookiePair !== null) {
    return setCookiePair;
  }

  if (/^[^=;,\s]+=.+/u.test(trimmed)) {
    return trimmed
      .split(";")
      .map((part) => part.trim())
      .filter((part) => part.length > 0 && /^[^=;,\s]+=.+/u.test(part))
      .join("; ");
  }

  return `SAKAIID=${trimmed}`;
};

export const createSakaiSession = async (
  input: CreateSakaiSessionInput,
): Promise<SakaiSessionLoginResult> => {
  const fetchImpl = input.fetchImpl ?? fetch;
  const apiBaseUrl = ensureHttpBaseUrl(input.apiBaseUrl);
  const loginUrl = new URL("/direct/session/new", apiBaseUrl);
  const body = new URLSearchParams({
    _username: input.username,
    _password: input.password,
  });
  const response = await fetchImpl(loginUrl.toString(), {
    method: "POST",
    headers: {
      accept: "text/plain, application/json",
      "content-type": "application/x-www-form-urlencoded",
    },
    body,
  });
  const responseBody = await response.text();

  if (!response.ok) {
    throw new Error(
      `Sakai session login failed (${String(response.status)}) for ${loginUrl.pathname}`,
    );
  }

  const cookieHeader = parseSetCookieHeader(response.headers.get("set-cookie"));
  const sessionId =
    parseSessionIdFromBody(responseBody) ??
    parseSessionIdFromLocation(response.headers.get("location"), apiBaseUrl) ??
    response.headers.get("entityid") ??
    response.headers.get("x-entity-id") ??
    (cookieHeader === null ? null : parseSessionIdFromCookieHeader(cookieHeader));

  if (sessionId === null || sessionId.length === 0) {
    throw new Error("Sakai session login succeeded but did not return a session id");
  }

  return {
    sessionId,
    cookieHeader: cookieHeader ?? `SAKAIID=${sessionId}`,
  };
};

const deriveCourseScorePercent = (
  courseGrade: SakaiGradebookMatrixStudentCourseGrade | null,
): number | null => {
  if (courseGrade === null) {
    return null;
  }

  const pointsEarned = courseGrade.pointsEarned;
  const totalPointsPossible = courseGrade.totalPointsPossible;

  if (
    pointsEarned !== null &&
    totalPointsPossible !== null &&
    Number.isFinite(pointsEarned) &&
    Number.isFinite(totalPointsPossible) &&
    totalPointsPossible > 0
  ) {
    return (pointsEarned / totalPointsPossible) * 100;
  }

  return asNumber(courseGrade.calculatedGrade);
};

const isCompletedGradebookItem = (grade: SakaiGradebookMatrixStudentGrade | undefined): boolean => {
  if (grade === undefined) {
    return false;
  }

  return grade.excused === true || (grade.grade !== null && grade.grade.trim().length > 0);
};

const deriveGradebookItemCompletionPercent = (
  columns: readonly SakaiGradebookMatrixColumn[],
  student: SakaiGradebookMatrixStudent,
): number | null => {
  if (columns.length === 0) {
    return null;
  }

  const completedItems = columns.filter((column) => {
    return isCompletedGradebookItem(student.gradesByAssignmentId[column.id]);
  }).length;

  return (completedItems / columns.length) * 100;
};

const parseMatrixColumn = (candidate: unknown): SakaiGradebookMatrixColumn | null => {
  const column = asJsonObject(candidate);

  if (column === null) {
    return null;
  }

  const id = asIdentifier(column.id);
  const name = asNonEmptyString(column.name);

  if (id === null || name === null) {
    return null;
  }

  return {
    id,
    name,
    points: asNumber(column.points),
    weight: asNumber(column.weight),
    dueDate: asIsoTimestamp(column.dueDate),
    released: asBoolean(column.released),
  };
};

const parseMatrixStudentCourseGrade = (
  candidate: unknown,
): SakaiGradebookMatrixStudentCourseGrade | null => {
  const parsed = asJsonObject(candidate);

  if (parsed === null) {
    return null;
  }

  return {
    calculatedGrade: asString(parsed.calculatedGrade),
    mappedGrade: asString(parsed.mappedGrade),
    displayGrade: asString(parsed.displayGrade),
    pointsEarned: asNumber(parsed.pointsEarned),
    totalPointsPossible: asNumber(parsed.totalPointsPossible),
  };
};

const parseMatrixStudentGrade = (candidate: unknown): SakaiGradebookMatrixStudentGrade | null => {
  const grade = asJsonObject(candidate);

  if (grade === null) {
    return null;
  }

  const parsedGrade = asString(grade.grade);
  const gradeReleased = asBoolean(grade.gradeReleased);
  const excused = asBoolean(grade.excused);
  const recordedAt = asIsoTimestamp(grade.dateRecorded);

  return {
    grade: parsedGrade,
    workflowState:
      excused === true
        ? "excused"
        : gradeReleased === false
          ? "hidden"
          : parsedGrade === null
            ? null
            : "graded",
    recordedAt,
    excused,
  };
};

const parseMatrixStudent = (candidate: unknown): SakaiGradebookMatrixStudent | null => {
  const student = asJsonObject(candidate);

  if (student === null) {
    return null;
  }

  const learnerId =
    asIdentifier(student.userId) ??
    asIdentifier(student.userEid) ??
    asIdentifier(student.userDisplayId);

  if (learnerId === null) {
    return null;
  }

  const rawGradesByAssignmentId = asJsonObject(student.grades) ?? {};
  const gradesByAssignmentId: Record<string, SakaiGradebookMatrixStudentGrade> = {};

  for (const [assignmentIdRaw, gradeCandidate] of Object.entries(rawGradesByAssignmentId)) {
    const assignmentId = asIdentifier(assignmentIdRaw);
    const grade = parseMatrixStudentGrade(gradeCandidate);

    if (assignmentId === null || grade === null) {
      continue;
    }

    gradesByAssignmentId[assignmentId] = grade;
  }

  return {
    learnerId,
    courseGrade: parseMatrixStudentCourseGrade(student.courseGrade),
    gradesByAssignmentId,
  };
};

const parseSakaiGradebookMatrix = (courseId: string, candidate: unknown): SakaiGradebookMatrix => {
  const root = asJsonObject(candidate);

  if (root === null) {
    throw new Error("Sakai gradebook API response must be a JSON object");
  }

  const siteId = asIdentifier(root.siteId) ?? courseId;
  const gradebookUid = asIdentifier(root.gradebookUid) ?? siteId;
  const columns = (asJsonArray(root.columns) ?? [])
    .map((column) => parseMatrixColumn(column))
    .filter((column): column is SakaiGradebookMatrixColumn => column !== null);
  const students = (asJsonArray(root.students) ?? [])
    .map((student) => parseMatrixStudent(student))
    .filter((student): student is SakaiGradebookMatrixStudent => student !== null);

  return {
    siteId,
    gradebookUid,
    columns,
    students,
  };
};

const parseSakaiCourseRecord = (candidate: unknown): GradebookCourseRecord | null => {
  const site = asJsonObject(candidate);

  if (site === null) {
    return null;
  }

  const courseId = asIdentifier(site.id) ?? asIdentifier(site.siteId);
  const title = asNonEmptyString(site.title) ?? asNonEmptyString(site.name);

  if (courseId === null || title === null) {
    return null;
  }

  return {
    courseId,
    title,
    courseCode: asString(site.shortDescription) ?? asString(site.courseCode),
    workflowState: asString(site.state),
    startsAt: asIsoTimestamp(site.createdDate),
    endsAt: asIsoTimestamp(site.termEid),
  };
};

export const createSakaiGradebookProvider = (
  input: CreateSakaiGradebookProviderInput,
): GradebookProvider => {
  const { config } = input;
  const fetchImpl = input.fetchImpl ?? fetch;
  const apiBaseUrl = ensureHttpBaseUrl(config.apiBaseUrl);
  const matrixRequestCache = new Map<string, Promise<SakaiGradebookMatrix>>();
  const cookieHeader = sakaiCookieHeaderFromAccessToken(config.accessToken);

  const requestJson = async (path: string, query?: URLSearchParams): Promise<unknown> => {
    const requestUrl = new URL(path, apiBaseUrl);

    if (query !== undefined && query.size > 0) {
      requestUrl.search = query.toString();
    }

    const response = await fetchImpl(requestUrl.toString(), {
      method: "GET",
      headers: {
        cookie: cookieHeader,
        accept: "application/json",
      },
    });

    if (!response.ok) {
      throw new Error(
        `Sakai gradebook API request failed (${String(response.status)}) for ${requestUrl.pathname}`,
      );
    }

    return response.json<unknown>().catch(() => null);
  };

  const fetchMatrix = (courseId: string): Promise<SakaiGradebookMatrix> => {
    const cached = matrixRequestCache.get(courseId);

    if (cached !== undefined) {
      return cached;
    }

    const request = requestJson(
      `/api/sites/${encodeURIComponent(courseId)}/grading/full-gradebook`,
    ).then((body) => parseSakaiGradebookMatrix(courseId, body));
    matrixRequestCache.set(courseId, request);
    return request;
  };

  return {
    kind: "sakai",
    listCourses: async (): Promise<readonly GradebookCourseRecord[]> => {
      const payload = await requestJson("/api/users/me/sites");
      const parsedPayload = asJsonObject(payload);
      const candidates = asJsonArray(parsedPayload?.sites ?? payload) ?? [];
      const courses = candidates
        .map((candidate) => parseSakaiCourseRecord(candidate))
        .filter((course): course is GradebookCourseRecord => course !== null);
      return courses;
    },
    listAssignments: async (input): Promise<readonly GradebookAssignmentRecord[]> => {
      const matrix = await fetchMatrix(input.courseId);
      return matrix.columns.map((column) => ({
        assignmentId: column.id,
        courseId: matrix.siteId,
        title: column.name,
        workflowState: column.released === false ? "unpublished" : "published",
        pointsPossible: column.points,
        dueAt: column.dueDate,
      }));
    },
    listEnrollments: async (input): Promise<readonly GradebookEnrollmentRecord[]> => {
      const matrix = await fetchMatrix(input.courseId);

      return matrix.students
        .filter((student) => input.learnerId === undefined || student.learnerId === input.learnerId)
        .map((student) => ({
          courseId: matrix.siteId,
          learnerId: student.learnerId,
          enrollmentState: "active",
          role: "StudentEnrollment",
          startedAt: null,
          lastActivityAt: null,
        }));
    },
    listSubmissions: async (input): Promise<readonly GradebookSubmissionRecord[]> => {
      const matrix = await fetchMatrix(input.courseId);
      const submissions: GradebookSubmissionRecord[] = [];

      for (const student of matrix.students) {
        if (input.learnerId !== undefined && student.learnerId !== input.learnerId) {
          continue;
        }

        for (const [assignmentId, grade] of Object.entries(student.gradesByAssignmentId)) {
          if (input.assignmentId !== undefined && assignmentId !== input.assignmentId) {
            continue;
          }

          submissions.push({
            courseId: matrix.siteId,
            assignmentId,
            learnerId: student.learnerId,
            workflowState: grade.workflowState,
            score: asNumber(grade.grade),
            submittedAt: grade.recordedAt,
            gradedAt: grade.recordedAt,
            late: null,
            missing: null,
          });
        }
      }

      return submissions;
    },
    listGrades: async (input): Promise<readonly GradebookGradeRecord[]> => {
      const matrix = await fetchMatrix(input.courseId);

      return matrix.students
        .filter((student) => input.learnerId === undefined || student.learnerId === input.learnerId)
        .map((student) => {
          const percentScore = deriveCourseScorePercent(student.courseGrade);
          return {
            courseId: matrix.siteId,
            learnerId: student.learnerId,
            currentScore: percentScore,
            finalScore: percentScore,
            currentGrade:
              student.courseGrade?.mappedGrade ?? student.courseGrade?.displayGrade ?? null,
            finalGrade:
              student.courseGrade?.mappedGrade ?? student.courseGrade?.displayGrade ?? null,
          };
        });
    },
    listCompletions: async (input): Promise<readonly GradebookCompletionRecord[]> => {
      const matrix = await fetchMatrix(input.courseId);

      return matrix.students
        .filter((student) => input.learnerId === undefined || student.learnerId === input.learnerId)
        .map((student) => {
          const completionPercent = deriveGradebookItemCompletionPercent(matrix.columns, student);
          const completed = completionPercent !== null && completionPercent >= 100;
          return {
            courseId: matrix.siteId,
            learnerId: student.learnerId,
            completed,
            completedAt: null,
            completionPercent,
            sourceState: completionPercent === null ? null : "gradebook_items",
          };
        });
    },
  };
};
