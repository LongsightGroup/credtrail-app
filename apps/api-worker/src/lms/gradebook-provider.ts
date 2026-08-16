import { asJsonObject, asNonEmptyString } from "../utils/value-parsers";
import { createCanvasGradebookProvider } from "./canvas-gradebook-provider";
import {
  createSakaiGradebookProvider,
  type SakaiSessionLoginResult,
} from "./sakai-gradebook-provider";
import {
  GRADEBOOK_PROVIDER_KINDS,
  type CourseAuthoringGradebookProvider,
  type GradebookProviderConfig,
  type GradebookProviderKind,
  type GradebookRequestOptions,
} from "./gradebook-types";

const isGradebookProviderKind = (value: string): value is GradebookProviderKind => {
  return (GRADEBOOK_PROVIDER_KINDS as readonly string[]).includes(value);
};

const parseRequiredField = (candidate: unknown, fieldName: string): string => {
  const value = asNonEmptyString(candidate);

  if (value === null) {
    throw new Error(`Gradebook provider config requires non-empty string field "${fieldName}"`);
  }

  return value;
};

export const parseGradebookProviderConfig = (input: unknown): GradebookProviderConfig => {
  const parsedConfig = asJsonObject(input);

  if (parsedConfig === null) {
    throw new Error("Gradebook provider config must be a JSON object");
  }

  const kindRaw = asNonEmptyString(parsedConfig.kind);

  if (kindRaw === null || !isGradebookProviderKind(kindRaw)) {
    throw new Error(
      `Gradebook provider kind must be one of: ${GRADEBOOK_PROVIDER_KINDS.join(", ")}`,
    );
  }

  return {
    kind: kindRaw,
    apiBaseUrl: parseRequiredField(parsedConfig.apiBaseUrl, "apiBaseUrl"),
    accessToken: parseRequiredField(parsedConfig.accessToken, "accessToken"),
  };
};

export const parseGradebookProviderConfigJson = (
  rawConfigJson: string,
): GradebookProviderConfig => {
  let parsed: unknown;

  try {
    parsed = JSON.parse(rawConfigJson);
  } catch {
    throw new Error("Gradebook provider config JSON is invalid");
  }

  return parseGradebookProviderConfig(parsed);
};

export interface CreateGradebookProviderInput {
  config: GradebookProviderConfig;
  fetchImpl?: typeof fetch;
  sakaiRefreshSession?: (options?: GradebookRequestOptions) => Promise<SakaiSessionLoginResult>;
}

export const createGradebookProvider = (
  input: CreateGradebookProviderInput,
): CourseAuthoringGradebookProvider => {
  switch (input.config.kind) {
    case "canvas":
      return createCanvasGradebookProvider({
        config: input.config,
        ...(input.fetchImpl === undefined ? {} : { fetchImpl: input.fetchImpl }),
      });
    case "sakai":
      return createSakaiGradebookProvider({
        config: input.config,
        ...(input.fetchImpl === undefined ? {} : { fetchImpl: input.fetchImpl }),
        ...(input.sakaiRefreshSession === undefined
          ? {}
          : { refreshSession: input.sakaiRefreshSession }),
      });
    default:
      throw new Error(`Gradebook provider "${input.config.kind}" is not implemented yet`);
  }
};
