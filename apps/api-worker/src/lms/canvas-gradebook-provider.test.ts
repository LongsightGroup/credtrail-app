import { describe, expect, it } from "vitest";
import { CREDTRAIL_OUTBOUND_USER_AGENT } from "../http/outbound-user-agent";
import { createCanvasGradebookProvider } from "./canvas-gradebook-provider";

interface MockRoute {
  pathWithQuery: string;
  responseBody: unknown;
  headers?: Record<string, string>;
  status?: number;
}

interface RecordingMockFetch {
  fetchImpl: typeof fetch;
  requests: string[];
}

const createRecordingMockFetch = (routes: readonly MockRoute[]): RecordingMockFetch => {
  const routeMap = new Map<string, MockRoute>(
    routes.map((route) => {
      return [route.pathWithQuery, route];
    }),
  );
  const requests: string[] = [];

  const fetchImpl = ((input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const request = input instanceof Request ? input : new Request(input, init);
    const requestUrl = new URL(request.url);
    const routeKey = `${requestUrl.pathname}${requestUrl.search}`;
    requests.push(routeKey);
    const route = routeMap.get(routeKey);

    if (route === undefined) {
      return Promise.resolve(
        new Response(
          JSON.stringify({
            error: `No mock route configured for ${routeKey}`,
          }),
          {
            status: 404,
            headers: {
              "content-type": "application/json",
            },
          },
        ),
      );
    }

    if (request.headers.get("authorization") !== "Bearer canvas-token") {
      return Promise.resolve(
        new Response(
          JSON.stringify({
            error: "Unauthorized",
          }),
          {
            status: 401,
            headers: {
              "content-type": "application/json",
            },
          },
        ),
      );
    }

    if (request.headers.get("user-agent") !== CREDTRAIL_OUTBOUND_USER_AGENT) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "User-Agent required" }), {
          status: 403,
          headers: {
            "content-type": "application/json",
          },
        }),
      );
    }

    return Promise.resolve(
      new Response(JSON.stringify(route.responseBody), {
        status: route.status ?? 200,
        headers: {
          "content-type": "application/json",
          ...route.headers,
        },
      }),
    );
  }) as typeof fetch;

  return {
    fetchImpl,
    requests,
  };
};

const createMockFetch = (routes: readonly MockRoute[]): typeof fetch => {
  return createRecordingMockFetch(routes).fetchImpl;
};

describe("createCanvasGradebookProvider", () => {
  it("maps canvas API responses to normalized records", async () => {
    const provider = createCanvasGradebookProvider({
      config: {
        kind: "canvas",
        apiBaseUrl: "https://canvas.example.edu",
        accessToken: "canvas-token",
      },
      fetchImpl: createMockFetch([
        {
          pathWithQuery: "/api/v1/courses?per_page=100&enrollment_state=active",
          responseBody: [
            {
              id: 42,
              name: "CS 101",
              course_code: "CS101",
              workflow_state: "available",
              start_at: "2026-01-01T00:00:00.000Z",
              end_at: "2026-05-01T00:00:00.000Z",
            },
            {
              id: null,
              name: "Invalid course",
            },
          ],
        },
        {
          pathWithQuery: "/api/v1/courses/course-42/assignments?per_page=100",
          responseBody: [
            {
              id: 7,
              name: "Capstone Project",
              workflow_state: "published",
              points_possible: 100,
              due_at: "2026-03-12T00:00:00.000Z",
            },
            {
              id: null,
              name: "Invalid assignment",
            },
          ],
        },
        {
          pathWithQuery:
            "/api/v1/courses/course-42/enrollments?per_page=100&type%5B%5D=StudentEnrollment",
          responseBody: [
            {
              user_id: 11,
              enrollment_state: "active",
              type: "StudentEnrollment",
              created_at: "2026-01-10T00:00:00.000Z",
              last_activity_at: "2026-02-01T00:00:00.000Z",
              grades: {
                current_score: 88.5,
                final_score: 90,
                current_grade: "B+",
                final_grade: "A-",
              },
            },
            {
              user_id: 12,
              enrollment_state: "concluded",
              type: "StudentEnrollment",
              updated_at: "2026-02-10T00:00:00.000Z",
              last_activity_at: "2026-02-09T00:00:00.000Z",
              grades: {
                current_score: "95",
                final_score: "96.5",
                current_grade: "A",
                final_grade: "A",
              },
            },
          ],
        },
        {
          pathWithQuery:
            "/api/v1/courses/course-42/students/submissions?per_page=100&assignment_ids%5B%5D=assignment-7&student_ids%5B%5D=learner-11",
          responseBody: [
            {
              user_id: 11,
              assignment_id: 7,
              workflow_state: "graded",
              score: 96.5,
              submitted_at: "2026-02-04T00:00:00.000Z",
              graded_at: "2026-02-05T00:00:00.000Z",
              late: false,
              missing: false,
            },
            {
              user_id: null,
              assignment_id: 8,
            },
          ],
        },
        {
          pathWithQuery: "/api/v1/courses/course-42/students/submissions?per_page=100",
          responseBody: [
            {
              user_id: 11,
              assignment_id: 7,
              workflow_state: "graded",
              score: 96.5,
              submitted_at: "2026-02-04T00:00:00.000Z",
              graded_at: "2026-02-05T00:00:00.000Z",
              late: false,
              missing: false,
            },
          ],
        },
        {
          pathWithQuery:
            "/api/v1/courses/course-42/enrollments?per_page=100&type%5B%5D=StudentEnrollment&student_ids%5B%5D=learner-11",
          responseBody: [
            {
              user_id: 11,
              enrollment_state: "active",
              type: "StudentEnrollment",
              created_at: "2026-01-10T00:00:00.000Z",
              last_activity_at: "2026-02-01T00:00:00.000Z",
              grades: {
                current_score: 88.5,
                final_score: 90,
                current_grade: "B+",
                final_grade: "A-",
              },
            },
          ],
        },
      ]),
    });

    const courseSearch = await provider.listCourses({ limit: 100 });
    const assignments = await provider.listAssignments({
      courseId: "course-42",
    });
    const enrollments = await provider.listEnrollments({
      courseId: "course-42",
    });
    const submissions = await provider.listSubmissions({
      courseId: "course-42",
      assignmentId: "assignment-7",
      learnerId: "learner-11",
    });
    const grades = await provider.listGrades({
      courseId: "course-42",
      learnerId: "learner-11",
    });
    const completions = await provider.listCompletions({
      courseId: "course-42",
    });

    expect(courseSearch).toEqual({
      courses: [
        {
          courseId: "42",
          title: "CS 101",
          courseCode: "CS101",
          workflowState: "available",
          startsAt: "2026-01-01T00:00:00.000Z",
          endsAt: "2026-05-01T00:00:00.000Z",
        },
      ],
      hasMore: false,
    });

    expect(assignments).toEqual([
      {
        assignmentId: "7",
        courseId: "course-42",
        title: "Capstone Project",
        workflowState: "published",
        pointsPossible: 100,
        dueAt: "2026-03-12T00:00:00.000Z",
      },
    ]);

    expect(enrollments).toEqual([
      {
        courseId: "course-42",
        learnerId: "11",
        enrollmentState: "active",
        role: "StudentEnrollment",
        startedAt: "2026-01-10T00:00:00.000Z",
        lastActivityAt: "2026-02-01T00:00:00.000Z",
      },
      {
        courseId: "course-42",
        learnerId: "12",
        enrollmentState: "concluded",
        role: "StudentEnrollment",
        startedAt: null,
        lastActivityAt: "2026-02-09T00:00:00.000Z",
      },
    ]);

    expect(submissions).toEqual([
      {
        courseId: "course-42",
        assignmentId: "7",
        learnerId: "11",
        workflowState: "graded",
        score: 96.5,
        submittedAt: "2026-02-04T00:00:00.000Z",
        gradedAt: "2026-02-05T00:00:00.000Z",
        late: false,
        missing: false,
      },
    ]);

    expect(grades).toEqual([
      {
        courseId: "course-42",
        learnerId: "11",
        currentScore: 88.5,
        finalScore: 90,
        currentGrade: "B+",
        finalGrade: "A-",
      },
    ]);

    expect(completions).toEqual([
      {
        courseId: "course-42",
        learnerId: "11",
        completed: true,
        completedAt: null,
        completionPercent: 100,
        sourceState: "gradebook_items",
      },
      {
        courseId: "course-42",
        learnerId: "12",
        completed: false,
        completedAt: null,
        completionPercent: 0,
        sourceState: "gradebook_items",
      },
    ]);
  });

  it("searches the complete authorized course set across pages", async () => {
    const mockFetch = createRecordingMockFetch([
      {
        pathWithQuery: "/api/v1/courses?per_page=100&enrollment_state=active",
        headers: {
          link: '<https://canvas.example.edu/api/v1/courses?page=2&per_page=100>; rel="next"',
        },
        responseBody: [
          {
            id: 42,
            name: "History",
            course_code: "CS101",
            workflow_state: "available",
          },
        ],
      },
      {
        pathWithQuery: "/api/v1/courses?page=2&per_page=100",
        responseBody: [
          {
            id: 77,
            name: "Capstone Seminar",
            course_code: "CAP-401",
            workflow_state: "available",
          },
        ],
      },
    ]);
    const provider = createCanvasGradebookProvider({
      config: {
        kind: "canvas",
        apiBaseUrl: "https://canvas.example.edu",
        accessToken: "canvas-token",
      },
      fetchImpl: mockFetch.fetchImpl,
    });

    const result = await provider.listCourses({
      searchTerm: "capstone",
      limit: 100,
    });

    expect(result).toEqual({
      courses: [
        expect.objectContaining({
          courseId: "77",
          title: "Capstone Seminar",
        }),
      ],
      hasMore: false,
    });
    expect(mockFetch.requests).toEqual([
      "/api/v1/courses?per_page=100&enrollment_state=active",
      "/api/v1/courses?page=2&per_page=100",
    ]);
  });

  it("filters the authorized Canvas course set by title, code, or ID", async () => {
    const mockFetch = createRecordingMockFetch([
      {
        pathWithQuery: "/api/v1/courses?per_page=100&enrollment_state=active",
        responseBody: [
          {
            id: 42,
            name: "Capstone Seminar",
            course_code: "CAP-401",
            workflow_state: "available",
          },
          {
            id: 77,
            name: "Biology",
            course_code: "BIO-101",
            workflow_state: "available",
          },
        ],
      },
    ]);
    const provider = createCanvasGradebookProvider({
      config: {
        kind: "canvas",
        apiBaseUrl: "https://canvas.example.edu",
        accessToken: "canvas-token",
      },
      fetchImpl: mockFetch.fetchImpl,
    });

    await expect(
      provider.listCourses({ searchTerm: " cap-401 ", limit: 100 }),
    ).resolves.toEqual({
      courses: [
        expect.objectContaining({
          courseId: "42",
          title: "Capstone Seminar",
        }),
      ],
      hasMore: false,
    });
    await expect(provider.listCourses({ searchTerm: "77", limit: 100 })).resolves.toEqual({
      courses: [
        expect.objectContaining({
          courseId: "77",
          title: "Biology",
        }),
      ],
      hasMore: false,
    });
  });

  it("follows canvas pagination links when listing gradebook items", async () => {
    const mockFetch = createRecordingMockFetch([
      {
        pathWithQuery: "/api/v1/courses/course-42/assignments?per_page=100",
        headers: {
          link: '<https://canvas.example.edu/api/v1/courses/course-42/assignments?page=2&per_page=100>; rel="next"',
        },
        responseBody: [
          {
            id: 7,
            name: "Capstone Project",
            workflow_state: "published",
          },
        ],
      },
      {
        pathWithQuery: "/api/v1/courses/course-42/assignments?page=2&per_page=100",
        responseBody: [
          {
            id: 8,
            name: "Final Exam",
            workflow_state: "published",
          },
        ],
      },
    ]);
    const provider = createCanvasGradebookProvider({
      config: {
        kind: "canvas",
        apiBaseUrl: "https://canvas.example.edu",
        accessToken: "canvas-token",
      },
      fetchImpl: mockFetch.fetchImpl,
    });

    const assignments = await provider.listAssignments({ courseId: "course-42" });

    expect(assignments.map((assignment) => assignment.assignmentId)).toEqual(["7", "8"]);
    expect(mockFetch.requests).toEqual([
      "/api/v1/courses/course-42/assignments?per_page=100",
      "/api/v1/courses/course-42/assignments?page=2&per_page=100",
    ]);
  });

  it("throws when canvas API returns non-200 responses", async () => {
    const provider = createCanvasGradebookProvider({
      config: {
        kind: "canvas",
        apiBaseUrl: "https://canvas.example.edu",
        accessToken: "canvas-token",
      },
      fetchImpl: createMockFetch([
        {
          pathWithQuery: "/api/v1/courses?per_page=100&enrollment_state=active",
          responseBody: {
            error: "server error",
          },
          status: 500,
        },
      ]),
    });

    await expect(provider.listCourses({ limit: 100 })).rejects.toMatchObject({
      _tag: "GradebookProviderError",
      operation: "course_search",
      providerKind: "canvas",
      statusCode: 500,
    });
  });

  it("throws when canvas API returns non-array JSON payloads", async () => {
    const provider = createCanvasGradebookProvider({
      config: {
        kind: "canvas",
        apiBaseUrl: "https://canvas.example.edu",
        accessToken: "canvas-token",
      },
      fetchImpl: createMockFetch([
        {
          pathWithQuery: "/api/v1/courses?per_page=100&enrollment_state=active",
          responseBody: {
            id: 42,
            name: "unexpected object",
          },
        },
      ]),
    });

    await expect(provider.listCourses({ limit: 100 })).rejects.toMatchObject({
      _tag: "GradebookProviderError",
      operation: "course_search",
      providerKind: "canvas",
      reason: "invalid_response",
    });
  });

  it("reuses all-submissions completion fetches for assignment submission lookups", async () => {
    const mockFetch = createRecordingMockFetch([
      {
        pathWithQuery:
          "/api/v1/courses/course-42/enrollments?per_page=100&type%5B%5D=StudentEnrollment&student_ids%5B%5D=11",
        responseBody: [
          {
            user_id: 11,
            enrollment_state: "active",
            type: "StudentEnrollment",
          },
        ],
      },
      {
        pathWithQuery: "/api/v1/courses/course-42/assignments?per_page=100",
        responseBody: [
          {
            id: 7,
            name: "Capstone Project",
            workflow_state: "published",
            points_possible: 100,
          },
        ],
      },
      {
        pathWithQuery:
          "/api/v1/courses/course-42/students/submissions?per_page=100&student_ids%5B%5D=11",
        responseBody: [
          {
            user_id: 11,
            assignment_id: 7,
            workflow_state: "graded",
            score: 96.5,
            graded_at: "2026-02-05T00:00:00.000Z",
            missing: false,
          },
        ],
      },
    ]);
    const provider = createCanvasGradebookProvider({
      config: {
        kind: "canvas",
        apiBaseUrl: "https://canvas.example.edu",
        accessToken: "canvas-token",
      },
      fetchImpl: mockFetch.fetchImpl,
    });

    await provider.listCompletions({
      courseId: "course-42",
      learnerId: "11",
    });
    const submissions = await provider.listSubmissions({
      courseId: "course-42",
      assignmentId: "7",
      learnerId: "11",
    });

    expect(submissions).toEqual([
      {
        courseId: "course-42",
        assignmentId: "7",
        learnerId: "11",
        workflowState: "graded",
        score: 96.5,
        submittedAt: null,
        gradedAt: "2026-02-05T00:00:00.000Z",
        late: null,
        missing: false,
      },
    ]);
    expect(
      mockFetch.requests.filter((request) => {
        return (
          request ===
          "/api/v1/courses/course-42/students/submissions?per_page=100&student_ids%5B%5D=11"
        );
      }),
    ).toHaveLength(1);
    expect(
      mockFetch.requests.some((request) => {
        return request.includes("assignment_ids%5B%5D=7");
      }),
    ).toBe(false);
  });

  it("searches course learners with display names and recipient emails", async () => {
    const mockFetch = createRecordingMockFetch([
      {
        pathWithQuery:
          "/api/v1/courses/course-42/users?per_page=100&enrollment_type%5B%5D=student&enrollment_state%5B%5D=active",
        responseBody: [
          {
            id: 11,
            name: "Ada Lovelace",
            email: "ada@example.edu",
          },
          {
            id: 12,
            name: "Grace Hopper",
            email: "grace@example.edu",
          },
        ],
      },
    ]);
    const provider = createCanvasGradebookProvider({
      config: {
        kind: "canvas",
        apiBaseUrl: "https://canvas.example.edu",
        accessToken: "canvas-token",
      },
      fetchImpl: mockFetch.fetchImpl,
    });

    await expect(
      provider.listLearners({ courseId: "course-42", searchTerm: "ada" }),
    ).resolves.toEqual([
      {
        courseId: "course-42",
        learnerId: "11",
        displayName: "Ada Lovelace",
        email: "ada@example.edu",
      },
    ]);
  });
});
