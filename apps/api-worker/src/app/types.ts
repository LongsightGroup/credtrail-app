import type { ImmutableCredentialStore } from "@credtrail/core-domain";
import type { Context } from "hono";
import type { AuthContextVariables } from "../auth/auth-context";
import type { BadgeTemplateImageGenerationAiBinding } from "../badges/badge-template-image-generation";
import type { PublicResourceNetwork } from "../http/public-resource-network";
import type { ObservabilityContextVariables } from "./observability";

export interface AppBindings {
  APP_ENV: string;
  DATABASE_URL?: string;
  HYPERDRIVE?: Hyperdrive;
  BADGE_OBJECTS: ImmutableCredentialStore;
  EMAIL?: SendEmail;
  PLATFORM_DOMAIN: string;
  PUBLIC_APP_ORIGIN: string;
  TENANT_SIGNING_REGISTRY_JSON?: string;
  TENANT_SIGNING_KEY_HISTORY_JSON?: string;
  TENANT_REMOTE_SIGNER_REGISTRY_JSON?: string;
  ISSUANCE_EMAIL_NOTIFICATIONS_ENABLED?: string;
  TRANSACTIONAL_EMAIL_FROM_ADDRESS?: string;
  TRANSACTIONAL_EMAIL_FROM_NAME?: string;
  TURNSTILE_SITE_KEY?: string;
  TURNSTILE_SECRET_KEY?: string;
  BETTER_AUTH_SECRET?: string;
  BETTER_AUTH_TRUSTED_ORIGINS?: string;
  GOOGLE_OAUTH_CLIENT_ID?: string;
  GOOGLE_OAUTH_CLIENT_SECRET?: string;
  GITHUB_TOKEN?: string;
  BOOTSTRAP_ADMIN_TOKEN?: string;
  JOB_PROCESSOR_TOKEN?: string;
  LTI_ISSUER_REGISTRY_JSON?: string;
  LTI_STATE_SIGNING_SECRET?: string;
  AI?: BadgeTemplateImageGenerationAiBinding;
  OB3_DISCOVERY_TITLE?: string;
  OB3_TERMS_OF_SERVICE_URL?: string;
  OB3_PRIVACY_POLICY_URL?: string;
  OB3_IMAGE_URL?: string;
  OB3_OAUTH_REGISTRATION_URL?: string;
  OB3_OAUTH_AUTHORIZATION_URL?: string;
  OB3_OAUTH_TOKEN_URL?: string;
  OB3_OAUTH_REFRESH_URL?: string;
  BADGE_IMAGE_GENERATION_MODEL?: string;
  PUBLIC_RESOURCE_NETWORK?: PublicResourceNetwork;
}

export interface AppEnv {
  Bindings: AppBindings;
  Variables: AuthContextVariables & ObservabilityContextVariables;
}

export type AppContext = Context<AppEnv>;
