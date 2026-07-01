import type { ObservabilityFields } from "@credtrail/core-domain";
import type { AppContext } from "../app";
import { ltiLogger } from "./log";
import { redactLtiProtocolSecrets } from "./redaction";

interface CreateLtiHonoLoggerInput {
  c: AppContext;
  messageOverrides?: Readonly<Record<string, string>>;
}

/**
 * Logger surface expected by @longsightgroup/lti-tool/hono route handlers.
 */
interface LtiHonoPackageLogger {
  error(fields: unknown, message?: unknown): void;
}

const isLogRecord = (value: unknown): value is Record<string, unknown> => {
  return typeof value === "object" && value !== null && !Array.isArray(value);
};

const errorDetail = (error: unknown): string | undefined => {
  if (error instanceof Error) {
    return redactLtiProtocolSecrets(error.message);
  }

  if (typeof error === "string") {
    return redactLtiProtocolSecrets(error);
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
export const createLtiHonoLogger = (input: CreateLtiHonoLoggerInput): LtiHonoPackageLogger => {
  const logger = ltiLogger(input.c);

  return {
    error(fields, message): void {
      if (logger === undefined) {
        return;
      }

      const rawMessage = typeof message === "string" ? message : "lti_hono_error";
      const appMessage = input.messageOverrides?.[rawMessage] ?? rawMessage;
      logger.error(appMessage, honoLogFields(fields));
    },
  };
};
