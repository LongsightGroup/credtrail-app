export type ObservabilityValue = string | number | boolean | null;

export type ObservabilityFields = Record<string, ObservabilityValue | undefined>;

export type ObservabilityLevel = "info" | "warn" | "error";

export interface ObservabilityContext {
  service: string;
  environment: string;
}

const logRecord = (
  level: ObservabilityLevel,
  context: ObservabilityContext,
  message: string,
  fields: ObservabilityFields = {},
): void => {
  const payload = {
    timestamp: new Date().toISOString(),
    level,
    service: context.service,
    environment: context.environment,
    message,
    ...fields,
  };

  const serialized = JSON.stringify(payload);

  if (level === "error") {
    console.error(serialized);
    return;
  }

  console.log(serialized);
};

export const logInfo = (
  context: ObservabilityContext,
  message: string,
  fields: ObservabilityFields = {},
): void => {
  logRecord("info", context, message, fields);
};

export const logWarn = (
  context: ObservabilityContext,
  message: string,
  fields: ObservabilityFields = {},
): void => {
  logRecord("warn", context, message, fields);
};

export const logError = (
  context: ObservabilityContext,
  message: string,
  fields: ObservabilityFields = {},
): void => {
  logRecord("error", context, message, fields);
};
