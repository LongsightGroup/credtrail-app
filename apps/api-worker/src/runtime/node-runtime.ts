import type { AppBindings } from "../app";
import { createSesEmailBinding } from "../notifications/ses-email";
import { createS3ImmutableCredentialStore } from "../storage/s3-immutable-credential-store";

type EnvSource = Record<string, string | undefined>;

const OPTIONAL_BINDING_KEYS = [
  "DATABASE_URL",
  "SENTRY_DSN",
  "TENANT_SIGNING_REGISTRY_JSON",
  "TENANT_SIGNING_KEY_HISTORY_JSON",
  "TENANT_REMOTE_SIGNER_REGISTRY_JSON",
  "ISSUANCE_EMAIL_NOTIFICATIONS_ENABLED",
  "TRANSACTIONAL_EMAIL_FROM_ADDRESS",
  "TRANSACTIONAL_EMAIL_FROM_NAME",
  "TURNSTILE_SITE_KEY",
  "TURNSTILE_SECRET_KEY",
  "BETTER_AUTH_SECRET",
  "BETTER_AUTH_TRUSTED_ORIGINS",
  "GOOGLE_OAUTH_CLIENT_ID",
  "GOOGLE_OAUTH_CLIENT_SECRET",
  "GITHUB_TOKEN",
  "JOB_PROCESSOR_TOKEN",
  "BOOTSTRAP_ADMIN_TOKEN",
  "LTI_ISSUER_REGISTRY_JSON",
  "LTI_STATE_SIGNING_SECRET",
  "CANVAS_OAUTH_STATE_SIGNING_SECRET",
  "OB3_DISCOVERY_TITLE",
  "OB3_TERMS_OF_SERVICE_URL",
  "OB3_PRIVACY_POLICY_URL",
  "OB3_IMAGE_URL",
  "OB3_OAUTH_REGISTRATION_URL",
  "OB3_OAUTH_AUTHORIZATION_URL",
  "OB3_OAUTH_TOKEN_URL",
  "OB3_OAUTH_REFRESH_URL",
  "BADGE_IMAGE_GENERATION_MODEL",
] as const;

type OptionalBindingKey = (typeof OPTIONAL_BINDING_KEYS)[number];

const optionalEnv = (envSource: EnvSource, name: string): string | undefined => {
  const value = envSource[name]?.trim();

  if (value === undefined || value.length === 0) {
    return undefined;
  }

  return value;
};

const requireEnv = (envSource: EnvSource, name: string): string => {
  const value = optionalEnv(envSource, name);

  if (value === undefined) {
    throw new Error(`${name} is required`);
  }

  return value;
};

const parseBooleanEnv = (envSource: EnvSource, name: string): boolean | undefined => {
  const value = optionalEnv(envSource, name);

  if (value === undefined) {
    return undefined;
  }

  if (value === "true" || value === "1") {
    return true;
  }

  if (value === "false" || value === "0") {
    return false;
  }

  throw new Error(`${name} must be one of: true, false, 1, 0`);
};

const createNodeEmailBinding = (envSource: EnvSource): SendEmail | undefined => {
  const provider = optionalEnv(envSource, "EMAIL_PROVIDER")?.toLowerCase();

  if (provider === undefined || provider === "none") {
    return undefined;
  }

  if (provider !== "ses") {
    throw new Error(`Unsupported EMAIL_PROVIDER "${provider}". Node runtime supports "ses".`);
  }

  requireEnv(envSource, "TRANSACTIONAL_EMAIL_FROM_ADDRESS");

  return createSesEmailBinding({
    region: optionalEnv(envSource, "AWS_SES_REGION") ?? requireEnv(envSource, "S3_REGION"),
    configurationSetName: optionalEnv(envSource, "AWS_SES_CONFIGURATION_SET"),
  });
};

const optionalBindingsFromEnv = (envSource: EnvSource): Partial<AppBindings> => {
  const bindings: Partial<AppBindings> = {};

  for (const key of OPTIONAL_BINDING_KEYS) {
    const value = optionalEnv(envSource, key);

    if (value === undefined) {
      continue;
    }

    (bindings as Record<OptionalBindingKey, string>)[key] = value;
  }

  return bindings;
};

export const parseNodeRuntimePort = (envSource: EnvSource = process.env): number => {
  const rawPort = optionalEnv(envSource, "PORT") ?? "8787";
  const parsedPort = Number.parseInt(rawPort, 10);

  if (!Number.isFinite(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
    throw new Error(`PORT must be an integer between 1 and 65535 (received "${rawPort}")`);
  }

  return parsedPort;
};

export const parsePositiveIntegerEnv = (
  envSource: EnvSource,
  name: string,
  fallback: number,
): number => {
  const rawValue = optionalEnv(envSource, name);

  if (rawValue === undefined) {
    return fallback;
  }

  const parsed = Number.parseInt(rawValue, 10);

  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer (received "${rawValue}")`);
  }

  return parsed;
};

export const createNodeRuntimeBindings = (envSource: EnvSource = process.env): AppBindings => {
  const storageBackend = (optionalEnv(envSource, "STORAGE_BACKEND") ?? "s3").toLowerCase();

  if (storageBackend !== "s3") {
    throw new Error(
      `Unsupported STORAGE_BACKEND "${storageBackend}". Node runtime currently supports "s3".`,
    );
  }

  const s3Endpoint = optionalEnv(envSource, "S3_ENDPOINT");
  const s3ForcePathStyle = parseBooleanEnv(envSource, "S3_FORCE_PATH_STYLE");
  const awsSessionToken = optionalEnv(envSource, "AWS_SESSION_TOKEN");

  const badgeObjectsBinding = createS3ImmutableCredentialStore({
    bucket: requireEnv(envSource, "S3_BUCKET"),
    region: requireEnv(envSource, "S3_REGION"),
    accessKeyId: requireEnv(envSource, "AWS_ACCESS_KEY_ID"),
    secretAccessKey: requireEnv(envSource, "AWS_SECRET_ACCESS_KEY"),
    ...(s3Endpoint === undefined ? {} : { endpoint: s3Endpoint }),
    ...(s3ForcePathStyle === undefined ? {} : { forcePathStyle: s3ForcePathStyle }),
    ...(awsSessionToken === undefined ? {} : { sessionToken: awsSessionToken }),
  });
  const emailBinding = createNodeEmailBinding(envSource);

  return {
    APP_ENV: optionalEnv(envSource, "APP_ENV") ?? "development",
    PLATFORM_DOMAIN: optionalEnv(envSource, "PLATFORM_DOMAIN") ?? "localhost",
    BADGE_OBJECTS: badgeObjectsBinding,
    ...(emailBinding === undefined ? {} : { EMAIL: emailBinding }),
    ...optionalBindingsFromEnv(envSource),
  };
};

export const createNodeExecutionContext = (): ExecutionContext => {
  return {
    waitUntil: (_promise: Promise<unknown>) => undefined,
    passThroughOnException: () => undefined,
    props: undefined,
  };
};
