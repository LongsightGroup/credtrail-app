import { describe, expect, it } from "vitest";
import { createSakaiGradebookProvider } from "./sakai-gradebook-provider";

interface MockRoute {
  pathWithQuery: string;
  responseBody: unknown;
  status?: number;
}

const createMockFetch = (
  routes: readonly MockRoute[],
): {
  fetchImpl: typeof fetch;
  requests: string[];
} => {
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

    if (
      request.headers.get("authorization") !== "Bearer sakai-token" ||
      request.headers.get("cookie") !== "SAKAIID=sakai-token"
    ) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Unauthorized" }), {
          status: 401,
          headers: {
            "content-type": "application/json",
          },
        }),
      );
    }

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

    return Promise.resolve(
      new Response(JSON.stringify(route.responseBody), {
        status: route.status ?? 200,
        headers: {
          "content-type": "application/json",
        },
      }),
    );
  }) as typeof fetch;

  return {
    fetchImpl,
    requests,
  };
};

describe("createSakaiGradebookProvider", () => {
  it("maps Sakai API responses to normalized records", async () => {
    const { fetchImpl } = createMockFetch([
      {
        pathWithQuery: "/api/users/me/sites",
        responseBody: {
          sites: [
            {
              id: "site-1",
              title: "CS 101",
              shortDescription: "CS101",
              state: "published",
              createdDate: "2026-01-01T00:00:00.000Z",
              termEid: "2026-05-01T00:00:00.000Z",
            },
          ],
        },
      },
      {
        pathWithQuery: "/api/sites/site-1/grading/full-gradebook",
        responseBody: {
          siteId: "site-1",
          gradebookUid: "gb-1",
          columns: [
            {
              id: "assignment-1",
              name: "Capstone Project",
              points: 100,
              dueDate: "2026-02-10T00:00:00.000Z",
              released: true,
            },
          ],
          students: [
            {
              userEid: "learner-1",
              courseGrade: {
                calculatedGrade: "92",
                mappedGrade: "A-",
                displayGrade: "A-",
                pointsEarned: 92,
                totalPointsPossible: 100,
              },
              grades: {
                "assignment-1": {
                  grade: "95",
                  gradeReleased: true,
                  dateRecorded: "2026-02-11T00:00:00.000Z",
                  excused: false,
                },
              },
            },
          ],
        },
      },
    ]);

    const provider = createSakaiGradebookProvider({
      config: {
        kind: "sakai",
        apiBaseUrl: "https://sakai.example.edu",
        accessToken: "sakai-token",
      },
      fetchImpl,
    });

    const courses = await provider.listCourses();
    const assignments = await provider.listAssignments({ courseId: "site-1" });
    const enrollments = await provider.listEnrollments({ courseId: "site-1" });
    const submissions = await provider.listSubmissions({ courseId: "site-1" });
    const grades = await provider.listGrades({ courseId: "site-1" });
    const completions = await provider.listCompletions({ courseId: "site-1" });

    expect(courses).toEqual([
      {
        courseId: "site-1",
        title: "CS 101",
        courseCode: "CS101",
        workflowState: "published",
        startsAt: "2026-01-01T00:00:00.000Z",
        endsAt: "2026-05-01T00:00:00.000Z",
      },
    ]);

    expect(assignments).toEqual([
      {
        assignmentId: "assignment-1",
        courseId: "site-1",
        title: "Capstone Project",
        workflowState: "published",
        pointsPossible: 100,
        dueAt: "2026-02-10T00:00:00.000Z",
      },
    ]);

    expect(enrollments).toEqual([
      {
        courseId: "site-1",
        learnerId: "learner-1",
        enrollmentState: "active",
        role: "StudentEnrollment",
        startedAt: null,
        lastActivityAt: null,
      },
    ]);

    expect(submissions).toEqual([
      {
        courseId: "site-1",
        assignmentId: "assignment-1",
        learnerId: "learner-1",
        workflowState: "graded",
        score: 95,
        submittedAt: "2026-02-11T00:00:00.000Z",
        gradedAt: "2026-02-11T00:00:00.000Z",
        late: null,
        missing: null,
      },
    ]);

    expect(grades).toEqual([
      {
        courseId: "site-1",
        learnerId: "learner-1",
        currentScore: 92,
        finalScore: 92,
        currentGrade: "A-",
        finalGrade: "A-",
      },
    ]);

    expect(completions).toEqual([
      {
        courseId: "site-1",
        learnerId: "learner-1",
        completed: true,
        completedAt: null,
        completionPercent: 92,
        sourceState: "graded",
      },
    ]);
  });

  it("caches full gradebook matrix responses per course", async () => {
    const { fetchImpl, requests } = createMockFetch([
      {
        pathWithQuery: "/api/sites/site-1/grading/full-gradebook",
        responseBody: {
          siteId: "site-1",
          columns: [],
          students: [],
        },
      },
    ]);

    const provider = createSakaiGradebookProvider({
      config: {
        kind: "sakai",
        apiBaseUrl: "https://sakai.example.edu",
        accessToken: "sakai-token",
      },
      fetchImpl,
    });

    await provider.listAssignments({ courseId: "site-1" });
    await provider.listGrades({ courseId: "site-1" });
    await provider.listCompletions({ courseId: "site-1" });

    expect(
      requests.filter(
        (pathWithQuery) => pathWithQuery === "/api/sites/site-1/grading/full-gradebook",
      ),
    ).toHaveLength(1);
  });

  it("throws a clear error when Sakai returns a non-200 response", async () => {
    const { fetchImpl } = createMockFetch([
      {
        pathWithQuery: "/api/sites/site-1/grading/full-gradebook",
        responseBody: {
          error: "Server error",
        },
        status: 500,
      },
    ]);

    const provider = createSakaiGradebookProvider({
      config: {
        kind: "sakai",
        apiBaseUrl: "https://sakai.example.edu",
        accessToken: "sakai-token",
      },
      fetchImpl,
    });

    await expect(
      provider.listAssignments({
        courseId: "site-1",
      }),
    ).rejects.toThrowError(
      "Sakai gradebook API request failed (500) for /api/sites/site-1/grading/full-gradebook",
    );
  });
});
