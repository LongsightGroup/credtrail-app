import type { ObservabilityFields } from "@credtrail/core-domain";
import type { AppContext } from "../app";
import { ltiLogger } from "./log";

interface CreateLtiHonoLoggerInput {
  c: AppContext;
  messageOverrides?: Readonly<Record<string, string>>;
}

const redactProtocolSecrets = (value: string): string => {
  return value
    .replace(/id_token=[^,\s)]+/gi, "id_token=[redacted]")
    .replace(/state=[^,\s)]+/gi, "state=[redacted]")
    .slice(0, 500);
};

const isLogRecord = (value: unknown): value is Record<string, unknown> => {
  return typeof value === "object" && value !== null && !Array.isArray(value);
};

const errorDetail = (error: unknown): string | undefined => {
  if (error instanceof Error) {
    return redactProtocolSecrets(error.message);
  }

  if (typeof error === "string") {
    return redactProtocolSecrets(error);
  }

  return undefined;
};

const honoLogFields = (input: unknown): ObservabilityFields => {
  if (!isLogRecord(input)) {
    return {};
  }

  const fields: ObservabilityFields = {};
  const path = input.path;

  if (typeof path === "string") {
    fields.path = path;
  }

  const error = input.error;
  const detail = errorDetail(error);

  if (detail !== undefined) {
    fields.detail = detail;
  }

  if (error instanceof Error) {
    fields.errorName = error.name;
  }

  return fields;
};

/**
 * Adapts the lti-tool Hono package logger shape to CredTrail's request logger.
 */
export const createLtiHonoLogger = (input: CreateLtiHonoLoggerInput) => {
  const logger = ltiLogger(input.c);

  const honoLogger = {
    error(fields: unknown, message?: unknown): void {
      if (logger === undefined) {
        return;
      }

      const rawMessage = typeof message === "string" ? message : "lti_hono_error";
      const appMessage = input.messageOverrides?.[rawMessage] ?? rawMessage;
      logger.error(appMessage, honoLogFields(fields));
    },
  };

  // SAFETY: @longsightgroup/lti-tool/hono only calls logger.error(fields, message)
  // in the handlers CredTrail wires here. The adapter intentionally exposes that
  // narrow pino-compatible surface while preserving CredTrail's logger contract.
  return honoLogger as Parameters<
    typeof import("@longsightgroup/lti-tool/hono").jwksRouteHandler
  >[0]["logger"];
};
