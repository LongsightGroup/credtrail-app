import {
  logError,
  logInfo,
  logWarn,
  type ObservabilityContext,
  type ObservabilityFields,
  type ObservabilityLevel,
} from "@credtrail/core-domain";
import type { Context } from "hono";
import type { AppBindings, AppEnv } from "./types";

type AppContext = Context<AppEnv>;

export const API_SERVICE_NAME = "api-worker";

export const observabilityContext = (bindings: AppBindings): ObservabilityContext => {
  return {
    service: API_SERVICE_NAME,
    environment: bindings.APP_ENV,
  };
};

export interface AppLogger {
  child(fields: ObservabilityFields): AppLogger;
  info(message: string, fields?: ObservabilityFields): void;
  warn(message: string, fields?: ObservabilityFields): void;
  error(message: string, fields?: ObservabilityFields): void;
}

export interface ObservabilityContextVariables {
  requestId: string;
  appLogger?: AppLogger;
}

export const optionalAppLogger = (c: AppContext): AppLogger | undefined => {
  return c.get("appLogger");
};

type AppLogWriter = (
  level: ObservabilityLevel,
  context: ObservabilityContext,
  message: string,
  fields: ObservabilityFields,
) => void;

const defaultAppLogWriter: AppLogWriter = (level, context, message, fields): void => {
  if (level === "error") {
    logError(context, message, fields);
    return;
  }

  if (level === "warn") {
    logWarn(context, message, fields);
    return;
  }

  logInfo(context, message, fields);
};

interface CreateAppLoggerInput {
  context: ObservabilityContext;
  fields?: ObservabilityFields;
  writer?: AppLogWriter;
}

export const createAppLogger = (input: CreateAppLoggerInput): AppLogger => {
  const baseFields = input.fields ?? {};
  const writer = input.writer ?? defaultAppLogWriter;

  const write = (
    level: ObservabilityLevel,
    message: string,
    fields: ObservabilityFields = {},
  ): void => {
    writer(level, input.context, message, {
      ...baseFields,
      ...fields,
    });
  };

  return {
    child(fields) {
      return createAppLogger({
        context: input.context,
        fields: {
          ...baseFields,
          ...fields,
        },
        writer,
      });
    },
    info(message, fields) {
      write("info", message, fields);
    },
    warn(message, fields) {
      write("warn", message, fields);
    },
    error(message, fields) {
      write("error", message, fields);
    },
  };
};
