import type {
  ObservabilityContext,
  ObservabilityFields,
  ObservabilityLevel,
} from "@credtrail/core-domain";
import { describe, expect, it } from "vitest";
import { createAppLogger } from "./observability";

interface RecordedLog {
  level: ObservabilityLevel;
  context: ObservabilityContext;
  message: string;
  fields: ObservabilityFields;
}

describe("createAppLogger", () => {
  it("writes structured log records with base fields", () => {
    const records: RecordedLog[] = [];
    const logger = createAppLogger({
      context: {
        service: "api-worker",
        environment: "test",
      },
      fields: {
        requestId: "request-1",
        method: "GET",
      },
      writer: (level, context, message, fields) => {
        records.push({
          level,
          context,
          message,
          fields,
        });
      },
    });

    logger.info("http_request", {
      status: 200,
    });

    expect(records).toEqual([
      {
        level: "info",
        context: {
          service: "api-worker",
          environment: "test",
        },
        message: "http_request",
        fields: {
          requestId: "request-1",
          method: "GET",
          status: 200,
        },
      },
    ]);
  });

  it("lets child loggers add scoped fields", () => {
    const records: RecordedLog[] = [];
    const logger = createAppLogger({
      context: {
        service: "api-worker",
        environment: "test",
      },
      fields: {
        requestId: "request-1",
        component: "http",
      },
      writer: (level, context, message, fields) => {
        records.push({
          level,
          context,
          message,
          fields,
        });
      },
    });

    logger.child({ component: "lti", tenantId: "tenant_123" }).warn("lti_warning", {
      reason: "upstream_error",
    });

    expect(records).toEqual([
      {
        level: "warn",
        context: {
          service: "api-worker",
          environment: "test",
        },
        message: "lti_warning",
        fields: {
          requestId: "request-1",
          component: "lti",
          tenantId: "tenant_123",
          reason: "upstream_error",
        },
      },
    ]);
  });
});
