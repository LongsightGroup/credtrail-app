import { asJsonObject, asNonEmptyString, asString } from "../utils/value-parsers";
import { withCredTrailUserAgent } from "../http/outbound-user-agent";
import { mapConcurrentBounded } from "../utils/map-concurrent-bounded";
import { z } from "zod";
import {
  GradebookProviderError,
  gradebookProviderHttpError,
  type GradebookProviderOperation,
} from "./gradebook-provider-error";
import type {
  GradebookAssignmentRecord,
  GradebookCompletionRecord,
  GradebookCourseRecord,
  GradebookCourseSearchResult,
  GradebookEnrollmentRecord,
  GradebookGradeRecord,
  GradebookLearnerRecord,
  GradebookProvider,
  GradebookSubmissionRecord,
  SakaiGradebookProviderConfig,
} from "./gradebook-types";

interface CreateSakaiGradebookProviderInput {
  config: SakaiGradebookProviderConfig;
  fetchImpl?: typeof fetch;
  refreshSession?: () => Promise<SakaiSessionLoginResult>;
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

interface SakaiMembershipLearner {
  learnerId: string;
  displayName: string;
  email: string | null;
}

const SAKAI_COURSE_SEARCH_PAGE_SIZE = 101;
const SAKAI_COURSE_SEARCH_MAX_SCANNED_SITES = 10_000;
const SAKAI_COURSE_ACCESS_CONCURRENCY = 4;
const sakaiSiteCollectionSchema = z.object({
  site_collection: z.array(z.unknown()),
});

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
    headers: withCredTrailUserAgent({
      accept: "text/plain, application/json",
      "content-type": "application/x-www-form-urlencoded",
    }),
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
    asIdentifier(student.userEid) ??
    asIdentifier(student.userId) ??
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

const parseSakaiMembershipLearner = (candidate: unknown): SakaiMembershipLearner | null => {
  const membership = asJsonObject(candidate);

  if (membership === null) {
    return null;
  }

  const learnerId = asIdentifier(membership.userEid);
  const displayName = asNonEmptyString(membership.userDisplayName);

  if (learnerId === null || displayName === null) {
    return null;
  }

  const emailCandidate = asNonEmptyString(membership.userEmail);
  const email =
    emailCandidate !== null && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailCandidate)
      ? emailCandidate
      : null;

  return {
    learnerId,
    displayName,
    email,
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

  if (asNonEmptyString(site.type) !== "course") {
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
    workflowState: site.published === true ? "published" : asString(site.state),
    startsAt: null,
    endsAt: null,
  };
};

const isRetryableSessionStatus = (status: number): boolean => {
  return status === 401 || status === 403;
};

export const createSakaiGradebookProvider = (
  input: CreateSakaiGradebookProviderInput,
): GradebookProvider => {
  const { config } = input;
  const fetchImpl = input.fetchImpl ?? fetch;
  const apiBaseUrl = ensureHttpBaseUrl(config.apiBaseUrl);
  const matrixRequestCache = new Map<string, Promise<SakaiGradebookMatrix>>();
  const siteRequestCache = new Map<string, Promise<unknown>>();
  let cookieHeader = sakaiCookieHeaderFromAccessToken(config.accessToken);

  const fetchJson = (requestUrl: URL): Promise<Response> => {
    return fetchImpl(requestUrl.toString(), {
      method: "GET",
      headers: withCredTrailUserAgent({
        cookie: cookieHeader,
        accept: "application/json",
      }),
    });
  };

  const requestJson = async (
    path: string,
    operation: GradebookProviderOperation,
    query?: URLSearchParams,
  ): Promise<unknown> => {
    const requestUrl = new URL(path, apiBaseUrl);

    if (query !== undefined && query.size > 0) {
      requestUrl.search = query.toString();
    }

    let response = await fetchJson(requestUrl);

    if (
      !response.ok &&
      isRetryableSessionStatus(response.status) &&
      input.refreshSession !== undefined
    ) {
      try {
        const refreshedSession = await input.refreshSession();
        cookieHeader = refreshedSession.cookieHeader;
        response = await fetchJson(requestUrl);
      } catch (cause: unknown) {
        throw new GradebookProviderError({
          providerKind: "sakai",
          operation,
          reason: "request_failed",
          statusCode: null,
          message: `sakai ${operation} session refresh failed`,
          cause,
        });
      }
    }

    if (!response.ok) {
      throw gradebookProviderHttpError({
        providerKind: "sakai",
        operation,
        statusCode: response.status,
      });
    }

    try {
      return await response.json<unknown>();
    } catch (cause: unknown) {
      throw new GradebookProviderError({
        providerKind: "sakai",
        operation,
        reason: "invalid_response",
        statusCode: response.status,
        message: `sakai ${operation} response was not valid JSON`,
        cause,
      });
    }
  };

  const fetchMatrix = (courseId: string): Promise<SakaiGradebookMatrix> => {
    const cached = matrixRequestCache.get(courseId);

    if (cached !== undefined) {
      return cached;
    }

    const request = requestJson(
      `/api/sites/${encodeURIComponent(courseId)}/grading/full-gradebook`,
      "gradebook_read",
    ).then((body) => parseSakaiGradebookMatrix(courseId, body));
    matrixRequestCache.set(courseId, request);
    return request;
  };

  const siteById = (courseId: string): Promise<unknown> => {
    const cached = siteRequestCache.get(courseId);

    if (cached !== undefined) {
      return cached;
    }

    const request = requestJson(
      `/direct/site/${encodeURIComponent(courseId)}.json`,
      "course_search",
    ).catch((error: unknown) => {
      if (error instanceof GradebookProviderError && error.statusCode === 404) {
        return null;
      }

      throw error;
    });
    siteRequestCache.set(courseId, request);
    return request;
  };

  return {
    kind: "sakai",
    listCourses: async (listInput): Promise<GradebookCourseSearchResult> => {
      if (listInput.accessScope.kind !== "connection") {
        throw new Error("Sakai course access requires the saved connection account");
      }

      // Sakai applies select=any to the authenticated administrator session. Intersecting these
      // results with an LTI launch user's memberships would hide institution-wide admin access.
      const requestedCourseCount = listInput.limit + 1;
      const searchTerm = listInput.searchTerm?.trim();
      const coursesById = new Map<string, GradebookCourseRecord>();
      let scannedSiteCount = 0;

      while (
        coursesById.size < requestedCourseCount &&
        scannedSiteCount < SAKAI_COURSE_SEARCH_MAX_SCANNED_SITES
      ) {
        const query = new URLSearchParams();
        query.set("select", "any");
        query.set("_limit", String(SAKAI_COURSE_SEARCH_PAGE_SIZE));

        if (scannedSiteCount > 0) {
          query.set("_start", String(scannedSiteCount));
        }

        if (searchTerm !== undefined && searchTerm.length > 0) {
          query.set("search", searchTerm);
        }

        const payload = await requestJson("/direct/site.json", "course_search", query);
        const parsedPayload = sakaiSiteCollectionSchema.safeParse(payload);

        if (!parsedPayload.success) {
          throw new GradebookProviderError({
            providerKind: "sakai",
            operation: "course_search",
            reason: "invalid_response",
            statusCode: 200,
            message: "sakai course_search response did not include site_collection",
            cause: parsedPayload.error,
          });
        }

        const candidates = parsedPayload.data.site_collection;

        if (candidates.length === 0) {
          break;
        }

        scannedSiteCount += candidates.length;

        for (const candidate of candidates) {
          const course = parseSakaiCourseRecord(candidate);

          if (course !== null) {
            coursesById.set(course.courseId, course);
          }
        }
      }

      if (
        coursesById.size < requestedCourseCount &&
        scannedSiteCount >= SAKAI_COURSE_SEARCH_MAX_SCANNED_SITES
      ) {
        throw new GradebookProviderError({
          providerKind: "sakai",
          operation: "course_search",
          reason: "request_failed",
          statusCode: null,
          message: "sakai course_search exceeded the bounded site scan",
        });
      }

      const matchingCourses = [...coursesById.values()].sort(
        (left, right) =>
          left.title.localeCompare(right.title) || left.courseId.localeCompare(right.courseId),
      );

      return {
        courses: matchingCourses.slice(0, listInput.limit),
        hasMore: matchingCourses.length > listInput.limit,
      };
    },
    verifyCourseAccess: async (accessInput) => {
      if (accessInput.accessScope.kind !== "connection") {
        throw new Error("Sakai course access requires the saved connection account");
      }

      const uniqueCourseIds = [...new Set(accessInput.courseIds)];
      const accessChecks = await mapConcurrentBounded(
        uniqueCourseIds,
        { concurrency: SAKAI_COURSE_ACCESS_CONCURRENCY },
        async (courseId) => {
          const site = await siteById(courseId);
          const course = parseSakaiCourseRecord(site);
          return { courseId, course };
        },
      );
      const authorizedCoursesById = new Map(
        accessChecks.flatMap((check) =>
          check.course === null ? [] : [[check.courseId, check.course] as const],
        ),
      );

      return {
        authorizedCourses: uniqueCourseIds.flatMap((courseId) => {
          const course = authorizedCoursesById.get(courseId);
          return course === undefined ? [] : [course];
        }),
        unauthorizedCourseIds: accessInput.courseIds.filter(
          (courseId) => !authorizedCoursesById.has(courseId),
        ),
      };
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
    listLearners: async (input): Promise<readonly GradebookLearnerRecord[]> => {
      const [matrix, membershipPayload] = await Promise.all([
        fetchMatrix(input.courseId),
        requestJson(
          `/direct/membership/site/${encodeURIComponent(input.courseId)}.json`,
          "learner_search",
        ),
      ]);
      const membershipObject = asJsonObject(membershipPayload);
      const membershipCandidates = asJsonArray(membershipObject?.membership_collection) ?? [];
      const learnersById = new Map(
        membershipCandidates
          .map((candidate) => parseSakaiMembershipLearner(candidate))
          .filter((learner): learner is SakaiMembershipLearner => learner !== null)
          .map((learner) => [learner.learnerId, learner]),
      );
      const searchTerm = input.searchTerm?.trim().toLocaleLowerCase() ?? "";

      return matrix.students
        .map((student) => learnersById.get(student.learnerId))
        .filter((learner): learner is SakaiMembershipLearner => learner !== undefined)
        .map((learner) => ({
          courseId: matrix.siteId,
          learnerId: learner.learnerId,
          displayName: learner.displayName,
          email: learner.email,
        }))
        .filter((learner) => {
          if (searchTerm.length === 0) {
            return true;
          }

          return [learner.displayName, learner.email ?? "", learner.learnerId].some((value) =>
            value.toLocaleLowerCase().includes(searchTerm),
          );
        });
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
