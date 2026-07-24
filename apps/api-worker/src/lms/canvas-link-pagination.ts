import { withCredTrailUserAgent } from "../http/outbound-user-agent";
import {
  GradebookProviderError,
  gradebookProviderHttpError,
  type GradebookProviderOperation,
} from "./gradebook-provider-error";

/**
 * LMS picker limits are intentionally tighter than full gradebook sync limits:
 * route-level LMS_PICKER_MAX_* caps keep admin select payloads usable, Canvas picker
 * calls read one page, and full gradebook evaluation can walk many pages for fidelity.
 */
export const CANVAS_PICKER_MAX_PAGES = 1;
export const CANVAS_GRADEBOOK_FULL_MAX_PAGES = 100;

const linkHeaderDeclaresRel = (linkHeader: string, rel: string): boolean => {
  const pattern = new RegExp(`rel\\s*=\\s*"?${rel}"?`, "i");
  return pattern.test(linkHeader);
};

export const parseLinkRelUrl = (linkHeader: string | null, rel: string): string | null => {
  if (linkHeader === null) {
    return null;
  }

  const normalizedRel = rel.toLowerCase();

  for (const entry of linkHeader.split(",")) {
    const trimmedEntry = entry.trim();
    const urlMatch = trimmedEntry.match(/^<([^>]+)>/);

    if (urlMatch === null) {
      continue;
    }

    const relMatch = trimmedEntry.match(/;\s*rel\s*=\s*"?([^";,\s]+)"?/i);

    if (relMatch === null || relMatch[1]?.toLowerCase() !== normalizedRel) {
      continue;
    }

    const url = urlMatch[1]?.trim();

    if (url === undefined || url.length === 0) {
      return null;
    }

    return url;
  }

  return null;
};

export type CanvasPaginationMaxPagesPolicy = "truncate" | "throw";

export interface FetchCanvasJsonArrayPagesInput {
  apiBaseUrl: URL;
  fetchImpl: typeof fetch;
  accessToken: string;
  path: string;
  query?: URLSearchParams;
  maxPages: number;
  onMaxPages: CanvasPaginationMaxPagesPolicy;
  operation: GradebookProviderOperation;
}

const asJsonArray = (value: unknown): readonly unknown[] | null => {
  return Array.isArray(value) ? value : null;
};

export const fetchCanvasJsonArrayPages = async (
  input: FetchCanvasJsonArrayPagesInput,
): Promise<readonly unknown[]> => {
  const firstRequestUrl = new URL(input.path, input.apiBaseUrl);

  if (input.query !== undefined && input.query.size > 0) {
    firstRequestUrl.search = input.query.toString();
  }

  const payloads: unknown[] = [];
  let requestUrl: URL | null = firstRequestUrl;
  let pageCount = 0;

  while (requestUrl !== null) {
    pageCount += 1;

    const response = await input.fetchImpl(requestUrl.toString(), {
      method: "GET",
      headers: withCredTrailUserAgent({
        authorization: `Bearer ${input.accessToken}`,
        accept: "application/json",
      }),
    });

    if (!response.ok) {
      throw gradebookProviderHttpError({
        providerKind: "canvas",
        operation: input.operation,
        statusCode: response.status,
      });
    }

    const body = await response.json<unknown>().catch(() => null);
    const payload = asJsonArray(body);

    if (payload === null) {
      throw new GradebookProviderError({
        providerKind: "canvas",
        operation: input.operation,
        reason: "invalid_response",
        statusCode: response.status,
        message: `canvas ${input.operation} response was not a JSON array`,
      });
    }

    const linkHeader = response.headers.get("link");
    const nextUrl = parseLinkRelUrl(linkHeader, "next");

    if (nextUrl === null && linkHeader !== null && linkHeaderDeclaresRel(linkHeader, "next")) {
      throw new GradebookProviderError({
        providerKind: "canvas",
        operation: input.operation,
        reason: "invalid_response",
        statusCode: response.status,
        message: `canvas ${input.operation} response included an invalid pagination link`,
      });
    }

    payloads.push(...payload);

    if (pageCount >= input.maxPages) {
      if (nextUrl !== null && input.onMaxPages === "throw") {
        throw new GradebookProviderError({
          providerKind: "canvas",
          operation: input.operation,
          reason: "request_failed",
          statusCode: null,
          message: `canvas ${input.operation} exceeded the bounded page limit`,
        });
      }

      requestUrl = null;
      continue;
    }

    requestUrl = nextUrl === null ? null : new URL(nextUrl, input.apiBaseUrl);
  }

  return payloads;
};
