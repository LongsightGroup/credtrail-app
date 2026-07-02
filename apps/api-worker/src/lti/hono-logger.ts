import type { ObservabilityFields } from "@credtrail/core-domain";
import type { LtiLogger } from "@longsightgroup/lti-tool";
import type { AppLogger } from "../app/observability";
import type { AppContext } from "../app";
import { ltiLogger } from "./log";
import { ltiErrorDetail } from "./redaction";

interface CreateLtiHonoLoggerInput {
  c: AppContext;
  messageOverrides?: Readonly<Record<string, string>>;
}

const isLogRecord = (value: unknown): value is Record<string, unknown> => {
  return typeof value === "object" && value !== null && !Array.isArray(value);
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
  const detail = ltiErrorDetail(error);

  if (detail !== undefined) {
    fields.detail = detail;
  }

  if (error instanceof Error) {
    fields.errorName = error.name;
  }

  return fields;
};

const resolveLogMessage = (input: {
  rawFieldsOrMessage: string | Readonly<Record<string, unknown>>;
  rawMessage: string | undefined;
  fallback: string;
  overrides: Readonly<Record<string, string>> | undefined;
}): string => {
  const rawMessage =
    input.rawMessage ??
    (typeof input.rawFieldsOrMessage === "string" ? input.rawFieldsOrMessage : input.fallback);

  return input.overrides?.[rawMessage] ?? rawMessage;
};

const createPackageLogMethod = (input: {
  logger: AppLogger | undefined;
  level: "debug" | "info" | "warn" | "error";
  fallback: string;
  overrides: Readonly<Record<string, string>> | undefined;
}): LtiLogger["error"] => {
  function log(message: string): void;
  function log(fields: Readonly<Record<string, unknown>>): void;
  function log(fields: Readonly<Record<string, unknown>>, message: string): void;
  function log(
    fieldsOrMessage: string | Readonly<Record<string, unknown>>,
    message?: string,
  ): void {
    if (input.logger === undefined) {
      return;
    }

    const appMessage = resolveLogMessage({
      rawFieldsOrMessage: fieldsOrMessage,
      rawMessage: message,
      fallback: input.fallback,
      overrides: input.overrides,
    });
    const fields = typeof fieldsOrMessage === "string" ? {} : honoLogFields(fieldsOrMessage);

    if (input.level === "error") {
      input.logger.error(appMessage, fields);
      return;
    }

    if (input.level === "warn") {
      input.logger.warn(appMessage, fields);
      return;
    }

    input.logger.info(appMessage, fields);
  }

  return log;
};

/**
 * Adapts the lti-tool Hono package logger shape to CredTrail's request logger.
 */
export const createLtiHonoLogger = (input: CreateLtiHonoLoggerInput): LtiLogger => {
  const logger = ltiLogger(input.c);

  return {
    debug: createPackageLogMethod({
      logger,
      level: "debug",
      fallback: "lti_hono_debug",
      overrides: input.messageOverrides,
    }),
    info: createPackageLogMethod({
      logger,
      level: "info",
      fallback: "lti_hono_info",
      overrides: input.messageOverrides,
    }),
    warn: createPackageLogMethod({
      logger,
      level: "warn",
      fallback: "lti_hono_warn",
      overrides: input.messageOverrides,
    }),
    error: createPackageLogMethod({
      logger,
      level: "error",
      fallback: "lti_hono_error",
      overrides: input.messageOverrides,
    }),
  };
};
