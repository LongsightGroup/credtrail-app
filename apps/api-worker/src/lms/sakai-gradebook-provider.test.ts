import { describe, expect, it } from "vitest";
import { CREDTRAIL_OUTBOUND_USER_AGENT } from "../http/outbound-user-agent";
import {
  createSakaiGradebookProvider,
  createSakaiSession,
  sakaiCookieHeaderFromAccessToken,
} from "./sakai-gradebook-provider";

interface MockRoute {
  pathWithQuery: string;
  responseBody: unknown;
  status?: number;
}

const createMockFetch = (
  routes: readonly MockRoute[],
  expectedCookie = "SAKAIID=sakai-token",
): {
  fetchImpl: typeof fetch;
  requests: {
    pathWithQuery: string;
    authorization: string | null;
    cookie: string | null;
    userAgent: string | null;
  }[];
} => {
  const routeMap = new Map<string, MockRoute>(
    routes.map((route) => {
      return [route.pathWithQuery, route];
    }),
  );
  const requests: Array<{
    pathWithQuery: string;
    authorization: string | null;
    cookie: string | null;
    userAgent: string | null;
  }> = [];

  const fetchImpl = ((input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const request = input instanceof Request ? input : new Request(input, init);
    const requestUrl = new URL(request.url);
    const routeKey = `${requestUrl.pathname}${requestUrl.search}`;
    requests.push({
      pathWithQuery: routeKey,
      authorization: request.headers.get("authorization"),
      cookie: request.headers.get("cookie"),
      userAgent: request.headers.get("user-agent"),
    });
    const route = routeMap.get(routeKey);

    if (
      request.headers.get("authorization") !== null ||
      request.headers.get("cookie") !== expectedCookie ||
      request.headers.get("user-agent") !== CREDTRAIL_OUTBOUND_USER_AGENT
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
  it("creates a Sakai session from username and password", async () => {
    const requests: Array<{
      pathWithQuery: string;
      method: string;
      body: string;
      contentType: string | null;
      userAgent: string | null;
    }> = [];
    const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const request = input instanceof Request ? input : new Request(input, init);
      const requestUrl = new URL(request.url);
      requests.push({
        pathWithQuery: `${requestUrl.pathname}${requestUrl.search}`,
        method: request.method,
        body: await request.text(),
        contentType: request.headers.get("content-type"),
        userAgent: request.headers.get("user-agent"),
      });

      return new Response("sakai-session-id", {
        status: 201,
        headers: {
          "set-cookie": "SAKAIID=sakai-session-id; Path=/; HttpOnly",
          "content-type": "text/plain",
        },
      });
    }) as typeof fetch;

    await expect(
      createSakaiSession({
        apiBaseUrl: "https://sakai.example.edu",
        username: "sakai-admin",
        password: "sakai-password",
        fetchImpl,
      }),
    ).resolves.toEqual({
      sessionId: "sakai-session-id",
      cookieHeader: "SAKAIID=sakai-session-id",
    });

    expect(requests).toHaveLength(1);
    expect(requests[0]).toMatchObject({
      pathWithQuery: "/direct/session/new",
      method: "POST",
      body: "_username=sakai-admin&_password=sakai-password",
    });
    expect(requests[0]?.contentType).toContain("application/x-www-form-urlencoded");
    expect(requests[0]?.userAgent).toBe(CREDTRAIL_OUTBOUND_USER_AGENT);
  });

  it("normalizes raw and full Sakai session cookie values", () => {
    expect(sakaiCookieHeaderFromAccessToken("sakai-token")).toBe("SAKAIID=sakai-token");
    expect(sakaiCookieHeaderFromAccessToken("JSESSIONID=sakai-session.Sakai; Path=/")).toBe(
      "JSESSIONID=sakai-session.Sakai",
    );
  });

  it("maps Sakai API responses to normalized records", async () => {
    const { fetchImpl, requests } = createMockFetch([
      {
        pathWithQuery: "/direct/site.json?select=any&_limit=101",
        responseBody: {
          site_collection: [
            {
              id: "site-1",
              title: "CS 101",
              type: "course",
              shortDescription: "CS101",
              published: true,
            },
          ],
        },
      },
      {
        pathWithQuery: "/direct/site.json?select=any&_limit=101&_start=1",
        responseBody: {
          site_collection: [],
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
            {
              id: "assignment-2",
              name: "Reflection",
              points: 10,
              dueDate: "2026-02-17T00:00:00.000Z",
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

    const courseSearch = await provider.listCourses({ limit: 100 });
    const assignments = await provider.listAssignments({ courseId: "site-1" });
    const enrollments = await provider.listEnrollments({ courseId: "site-1" });
    const submissions = await provider.listSubmissions({ courseId: "site-1" });
    const grades = await provider.listGrades({ courseId: "site-1" });
    const completions = await provider.listCompletions({ courseId: "site-1" });

    expect(requests.every((request) => request.authorization === null)).toBe(true);
    expect(requests.every((request) => request.cookie === "SAKAIID=sakai-token")).toBe(true);

    expect(courseSearch).toEqual({
      courses: [
        {
          courseId: "site-1",
          title: "CS 101",
          courseCode: "CS101",
          workflowState: "published",
          startsAt: null,
          endsAt: null,
        },
      ],
      hasMore: false,
    });

    expect(assignments).toEqual([
      {
        assignmentId: "assignment-1",
        courseId: "site-1",
        title: "Capstone Project",
        workflowState: "published",
        pointsPossible: 100,
        dueAt: "2026-02-10T00:00:00.000Z",
      },
      {
        assignmentId: "assignment-2",
        courseId: "site-1",
        title: "Reflection",
        workflowState: "published",
        pointsPossible: 10,
        dueAt: "2026-02-17T00:00:00.000Z",
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
        completed: false,
        completedAt: null,
        completionPercent: 50,
        sourceState: "gradebook_items",
      },
    ]);
  });

  it("searches authorized Sakai sites and returns only courses in title order", async () => {
    const { fetchImpl, requests } = createMockFetch([
      {
        pathWithQuery: "/direct/site.json?select=any&_limit=101&search=capstone+2026",
        responseBody: {
          site_collection: [
            {
              id: "project-1",
              title: "Capstone Faculty Project",
              type: "project",
            },
            {
              id: "!admin",
              title: "Administration Workspace",
              type: "admin",
            },
            {
              id: "capstone-2026-b",
              title: "Capstone Seminar",
              description: "Spring cohort",
              type: "course",
            },
            {
              id: "capstone-2026-a",
              title: "Applied Capstone",
              description: "Summer cohort",
              type: "course",
            },
          ],
        },
      },
      {
        pathWithQuery:
          "/direct/site.json?select=any&_limit=101&_start=4&search=capstone+2026",
        responseBody: {
          site_collection: [],
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

    await expect(
      provider.listCourses({ searchTerm: "  capstone 2026  ", limit: 100 }),
    ).resolves.toEqual({
      courses: [
        expect.objectContaining({
          courseId: "capstone-2026-a",
          title: "Applied Capstone",
        }),
        expect.objectContaining({
          courseId: "capstone-2026-b",
          title: "Capstone Seminar",
        }),
      ],
      hasMore: false,
    });
    expect(requests.map((request) => request.pathWithQuery)).toEqual([
      "/direct/site.json?select=any&_limit=101&search=capstone+2026",
      "/direct/site.json?select=any&_limit=101&_start=4&search=capstone+2026",
    ]);
  });

  it("continues past full pages of non-course sites before applying the course limit", async () => {
    const { fetchImpl, requests } = createMockFetch([
      {
        pathWithQuery: "/direct/site.json?select=any&_limit=101",
        responseBody: {
          site_collection: Array.from({ length: 101 }, (_, index) => ({
            id: `project-${String(index)}`,
            title: `Project ${String(index)}`,
            type: "project",
          })),
        },
      },
      {
        pathWithQuery: "/direct/site.json?select=any&_limit=101&_start=101",
        responseBody: {
          site_collection: [
            {
              id: "course-z",
              title: "Zoology",
              type: "course",
            },
            {
              id: "course-a",
              title: "Anthropology",
              type: "course",
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

    await expect(provider.listCourses({ limit: 1 })).resolves.toEqual({
      courses: [
        expect.objectContaining({
          courseId: "course-a",
          title: "Anthropology",
        }),
      ],
      hasMore: true,
    });
    expect(requests.map((request) => request.pathWithQuery)).toEqual([
      "/direct/site.json?select=any&_limit=101",
      "/direct/site.json?select=any&_limit=101&_start=101",
    ]);
  });

  it("rejects malformed Sakai site-search envelopes", async () => {
    const { fetchImpl } = createMockFetch([
      {
        pathWithQuery: "/direct/site.json?select=any&_limit=101",
        responseBody: {
          sites: [],
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

    await expect(provider.listCourses({ limit: 100 })).rejects.toMatchObject({
      _tag: "GradebookProviderError",
      operation: "course_search",
      providerKind: "sakai",
      reason: "invalid_response",
    });
  });

  it("surfaces permission failures from authorized Sakai site search", async () => {
    const { fetchImpl } = createMockFetch([
      {
        pathWithQuery: "/direct/site.json?select=any&_limit=101",
        responseBody: {
          message: "Forbidden",
        },
        status: 403,
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

    await expect(provider.listCourses({ limit: 100 })).rejects.toMatchObject({
      _tag: "GradebookProviderError",
      operation: "course_search",
      providerKind: "sakai",
      statusCode: 403,
    });
  });

  it("uses stored Sakai cookie headers without wrapping them", async () => {
    const { fetchImpl, requests } = createMockFetch(
      [
        {
          pathWithQuery: "/direct/site.json?select=any&_limit=101",
          responseBody: {
            site_collection: [
              {
                id: "site-1",
                title: "CS 101",
                type: "course",
              },
            ],
          },
        },
        {
          pathWithQuery: "/direct/site.json?select=any&_limit=101&_start=1",
          responseBody: {
            site_collection: [],
          },
        },
      ],
      "JSESSIONID=sakai-session.Sakai",
    );

    const provider = createSakaiGradebookProvider({
      config: {
        kind: "sakai",
        apiBaseUrl: "https://sakai.example.edu",
        accessToken: "JSESSIONID=sakai-session.Sakai",
      },
      fetchImpl,
    });

    await expect(provider.listCourses({ limit: 100 })).resolves.toEqual({
      courses: [
        {
          courseId: "site-1",
          title: "CS 101",
          courseCode: null,
          workflowState: null,
          startsAt: null,
          endsAt: null,
        },
      ],
      hasMore: false,
    });
    expect(requests[0]?.cookie).toBe("JSESSIONID=sakai-session.Sakai");
  });

  it("refreshes the Sakai session once when the cached cookie is rejected", async () => {
    const requests: { pathWithQuery: string; cookie: string | null }[] = [];
    let refreshCalls = 0;
    const fetchImpl = ((input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const request = input instanceof Request ? input : new Request(input, init);
      const requestUrl = new URL(request.url);
      const pathWithQuery = `${requestUrl.pathname}${requestUrl.search}`;
      const cookie = request.headers.get("cookie");
      requests.push({ pathWithQuery, cookie });

      if (
        pathWithQuery !== "/direct/site.json?select=any&_limit=101" &&
        pathWithQuery !== "/direct/site.json?select=any&_limit=101&_start=1"
      ) {
        return Promise.resolve(
          new Response(JSON.stringify({ error: "No mock route configured" }), {
            status: 404,
            headers: {
              "content-type": "application/json",
            },
          }),
        );
      }

      if (cookie !== "SAKAIID=fresh-token") {
        return Promise.resolve(
          new Response(JSON.stringify({ message: "Missing or invalid Sakai session" }), {
            status: 403,
            headers: {
              "content-type": "application/json",
            },
          }),
        );
      }

      return Promise.resolve(
        new Response(
          JSON.stringify({
            site_collection:
              pathWithQuery === "/direct/site.json?select=any&_limit=101"
                ? [
                    {
                      id: "site-1",
                      title: "CS 101",
                      type: "course",
                    },
                  ]
                : [],
          }),
          {
            status: 200,
            headers: {
              "content-type": "application/json",
            },
          },
        ),
      );
    }) as typeof fetch;

    const provider = createSakaiGradebookProvider({
      config: {
        kind: "sakai",
        apiBaseUrl: "https://sakai.example.edu",
        accessToken: "stale-token",
      },
      fetchImpl,
      refreshSession: (): Promise<{ sessionId: string; cookieHeader: string }> => {
        refreshCalls += 1;
        return Promise.resolve({
          sessionId: "fresh-token",
          cookieHeader: "SAKAIID=fresh-token",
        });
      },
    });

    await expect(provider.listCourses({ limit: 100 })).resolves.toEqual({
      courses: [
        {
          courseId: "site-1",
          title: "CS 101",
          courseCode: null,
          workflowState: null,
          startsAt: null,
          endsAt: null,
        },
      ],
      hasMore: false,
    });
    expect(refreshCalls).toBe(1);
    expect(requests).toEqual([
      {
        pathWithQuery: "/direct/site.json?select=any&_limit=101",
        cookie: "SAKAIID=stale-token",
      },
      {
        pathWithQuery: "/direct/site.json?select=any&_limit=101",
        cookie: "SAKAIID=fresh-token",
      },
      {
        pathWithQuery: "/direct/site.json?select=any&_limit=101&_start=1",
        cookie: "SAKAIID=fresh-token",
      },
    ]);
  });

  it("marks Sakai course completion only when every gradebook item is completed", async () => {
    const { fetchImpl } = createMockFetch([
      {
        pathWithQuery: "/api/sites/site-1/grading/full-gradebook",
        responseBody: {
          siteId: "site-1",
          columns: [
            {
              id: "assignment-1",
              name: "Capstone Project",
            },
            {
              id: "assignment-2",
              name: "Reflection",
            },
          ],
          students: [
            {
              userEid: "learner-1",
              courseGrade: {
                calculatedGrade: "92",
              },
              grades: {
                "assignment-1": {
                  grade: "95",
                  gradeReleased: true,
                  excused: false,
                },
                "assignment-2": {
                  grade: null,
                  gradeReleased: true,
                  excused: true,
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

    await expect(provider.listCompletions({ courseId: "site-1" })).resolves.toEqual([
      {
        courseId: "site-1",
        learnerId: "learner-1",
        completed: true,
        completedAt: null,
        completionPercent: 100,
        sourceState: "gradebook_items",
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
        (request) => request.pathWithQuery === "/api/sites/site-1/grading/full-gradebook",
      ),
    ).toHaveLength(1);
  });

  it("searches gradebook learners using Sakai membership details", async () => {
    const { fetchImpl } = createMockFetch([
      {
        pathWithQuery: "/api/sites/site-1/grading/full-gradebook",
        responseBody: {
          siteId: "site-1",
          columns: [],
          students: [
            {
              userId: "internal-1",
              userEid: "ada",
              grades: {},
            },
          ],
        },
      },
      {
        pathWithQuery: "/direct/membership/site/site-1.json",
        responseBody: {
          membership_collection: [
            {
              userEid: "ada",
              userDisplayName: "Ada Lovelace",
              userEmail: "ada@example.edu",
            },
            {
              userEid: "instructor",
              userDisplayName: "Course Instructor",
              userEmail: "instructor@example.edu",
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

    await expect(provider.listLearners({ courseId: "site-1", searchTerm: "ada" })).resolves.toEqual(
      [
        {
          courseId: "site-1",
          learnerId: "ada",
          displayName: "Ada Lovelace",
          email: "ada@example.edu",
        },
      ],
    );
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
    ).rejects.toMatchObject({
      _tag: "GradebookProviderError",
      operation: "gradebook_read",
      providerKind: "sakai",
      statusCode: 500,
    });
  });
});
