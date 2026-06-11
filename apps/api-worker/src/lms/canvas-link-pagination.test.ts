import { describe, expect, it } from "vitest";

import {
  CANVAS_GRADEBOOK_FULL_MAX_PAGES,
  fetchCanvasJsonArrayPages,
  parseLinkRelUrl,
} from "./canvas-link-pagination";

describe("parseLinkRelUrl", () => {
  it("returns the next URL from a canvas-style link header", () => {
    const linkHeader =
      '<https://canvas.example.edu/api/v1/courses?page=2&per_page=100>; rel="next", <https://canvas.example.edu/api/v1/courses?page=1&per_page=100>; rel="current"';

    expect(parseLinkRelUrl(linkHeader, "next")).toBe(
      "https://canvas.example.edu/api/v1/courses?page=2&per_page=100",
    );
  });

  it("matches rel values case-insensitively and without quotes", () => {
    const linkHeader = "<https://canvas.example.edu/api/v1/courses?page=2>; rel=next";

    expect(parseLinkRelUrl(linkHeader, "next")).toBe(
      "https://canvas.example.edu/api/v1/courses?page=2",
    );
  });

  it("returns null when the requested relation is absent", () => {
    expect(parseLinkRelUrl('<https://canvas.example.edu/>; rel="current"', "next")).toBeNull();
    expect(parseLinkRelUrl(null, "next")).toBeNull();
  });
});

describe("fetchCanvasJsonArrayPages", () => {
  const apiBaseUrl = new URL("https://canvas.example.edu/");

  it("follows next links until the final page", async () => {
    const requests: string[] = [];
    const fetchImpl = ((input: RequestInfo | URL): Promise<Response> => {
      const requestUrl = new URL(input instanceof Request ? input.url : input.toString());
      requests.push(`${requestUrl.pathname}${requestUrl.search}`);

      if (requestUrl.searchParams.get("page") === "2") {
        return Promise.resolve(
          new Response(JSON.stringify([{ id: 2 }]), {
            status: 200,
            headers: { "content-type": "application/json" },
          }),
        );
      }

      return Promise.resolve(
        new Response(JSON.stringify([{ id: 1 }]), {
          status: 200,
          headers: {
            "content-type": "application/json",
            link: '<https://canvas.example.edu/api/v1/items?page=2&per_page=100>; rel="next"',
          },
        }),
      );
    }) as typeof fetch;

    const payload = await fetchCanvasJsonArrayPages({
      apiBaseUrl,
      fetchImpl,
      accessToken: "canvas-token",
      path: "/api/v1/items",
      query: new URLSearchParams({ per_page: "100" }),
      maxPages: CANVAS_GRADEBOOK_FULL_MAX_PAGES,
      onMaxPages: "throw",
    });

    expect(payload).toEqual([{ id: 1 }, { id: 2 }]);
    expect(requests).toEqual(["/api/v1/items?per_page=100", "/api/v1/items?page=2&per_page=100"]);
  });

  it("throws when pagination exceeds maxPages", async () => {
    const fetchImpl = ((): Promise<Response> => {
      return Promise.resolve(
        new Response(JSON.stringify([{ id: 1 }]), {
          status: 200,
          headers: {
            "content-type": "application/json",
            link: '<https://canvas.example.edu/api/v1/items?page=2>; rel="next"',
          },
        }),
      );
    }) as typeof fetch;

    await expect(
      fetchCanvasJsonArrayPages({
        apiBaseUrl,
        fetchImpl,
        accessToken: "canvas-token",
        path: "/api/v1/items",
        maxPages: 1,
        onMaxPages: "throw",
      }),
    ).rejects.toThrowError("pagination exceeded 1 pages");
  });

  it("throws when a next link is declared but cannot be parsed", async () => {
    const fetchImpl = ((): Promise<Response> => {
      return Promise.resolve(
        new Response(JSON.stringify([{ id: 1 }]), {
          status: 200,
          headers: {
            "content-type": "application/json",
            link: 'not-a-valid-link; rel="next"',
          },
        }),
      );
    }) as typeof fetch;

    await expect(
      fetchCanvasJsonArrayPages({
        apiBaseUrl,
        fetchImpl,
        accessToken: "canvas-token",
        path: "/api/v1/items",
        maxPages: CANVAS_GRADEBOOK_FULL_MAX_PAGES,
        onMaxPages: "throw",
      }),
    ).rejects.toThrowError("unparseable pagination link");
  });

  it("truncates after maxPages when onMaxPages is truncate", async () => {
    const requests: string[] = [];
    const fetchImpl = ((input: RequestInfo | URL): Promise<Response> => {
      const requestUrl = new URL(input instanceof Request ? input.url : input.toString());
      requests.push(`${requestUrl.pathname}${requestUrl.search}`);

      return Promise.resolve(
        new Response(JSON.stringify([{ id: 1 }]), {
          status: 200,
          headers: {
            "content-type": "application/json",
            link: '<https://canvas.example.edu/api/v1/items?page=2>; rel="next"',
          },
        }),
      );
    }) as typeof fetch;

    const payload = await fetchCanvasJsonArrayPages({
      apiBaseUrl,
      fetchImpl,
      accessToken: "canvas-token",
      path: "/api/v1/items",
      maxPages: 1,
      onMaxPages: "truncate",
    });

    expect(payload).toEqual([{ id: 1 }]);
    expect(requests).toEqual(["/api/v1/items"]);
  });
});
